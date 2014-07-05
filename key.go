// Copyright 2014 Gregory Holt. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package brimcrypt

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh/terminal"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

// NoKeyAndNoPromptError indicates no key could be determined and interactively
// prompting the user for a key phrase was not enabled.
var NoKeyAndNoPromptError = fmt.Errorf("no key and no prompt")

// KeyError indicates an invalid encryption key has been given.
var KeyError = fmt.Errorf("invalid key")

// Key will return a 32 byte key from a key phrase, cache, or prompting the
// user. If any of the func args are "", that procedure will be skipped. In the
// OS environment, x_KEY x_KEY_FILE and x_KEY_INACTIVITY are used for the key
// phrase itself (not recommended), where to cache, and for how long.
func Key(phrase string, envPrefix string, prompt string, confirm string) ([]byte, error) {
	if phrase != "" {
		return keyPhrase(phrase), nil
	}
	if envPrefix != "" {
		if phrase = os.Getenv(envPrefix + "_KEY"); phrase != "" {
			return keyPhrase(phrase), nil
		}
		fname := os.Getenv(envPrefix + "_KEY_FILE")
		if fname != "" {
			if inact, err := strconv.Atoi(os.Getenv(envPrefix + "_KEY_INACTIVITY")); err == nil && inact > 0 {
				if finfo, err := os.Stat(fname); err == nil && finfo.Size() == 32 && finfo.Mode() == 0600 && time.Now().After(finfo.ModTime()) && time.Now().Sub(finfo.ModTime()).Seconds() < float64(inact) {
					if key, err := ioutil.ReadFile(fname); err == nil && len(key) == 32 {
						return key, nil
					}
				}
			}
			os.Remove(fname)
		}
	}
	if prompt == "" {
		return nil, NoKeyAndNoPromptError
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("no controlling terminal to ask for key phrase: %s", err)
	}
	var bphrase []byte
	if _, err = fmt.Fprintf(tty, prompt); err != nil {
		return nil, err
	}
	if bphrase, err = terminal.ReadPassword(int(tty.Fd())); err != nil {
		return nil, err
	}
	if _, err = fmt.Fprintf(tty, "\n"); err != nil {
		return nil, err
	}
	if confirm != "" {
		if _, err = fmt.Fprintf(tty, confirm); err != nil {
			return nil, err
		}
		var bphrase2 []byte
		if bphrase2, err = terminal.ReadPassword(int(tty.Fd())); err != nil {
			return nil, err
		}
		if _, err = fmt.Fprintf(tty, "\n"); err != nil {
			return nil, err
		}
		if !bytes.Equal(bphrase, bphrase2) {
			return nil, fmt.Errorf("input did not match")
		}
	}
	if bphrase == nil || len(bphrase) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	return keyPhrase(string(bphrase)), nil
}

// CacheKey will cache based on the OS environment; x_KEY_FILE and
// x_KEY_INACTIVITY are used to determine where to cache and for how long. An
// error will be returned if caching does not occur for any reason, including
// deliberately disabled caching. If no error is returned, the caller should
// launch a key watcher for clearing the cache when appropriate.
func CacheKey(key []byte, envPrefix string) error {
	if envPrefix == "" {
		return fmt.Errorf("key caching disabled because no os environment prefix given")
	}
	fname := os.Getenv(envPrefix + "_KEY_FILE")
	if fname == "" {
		return fmt.Errorf("key caching disabled because %s is not set", envPrefix+"_KEY_FILE")
	}
	inact, err := strconv.Atoi(os.Getenv(envPrefix + "_KEY_INACTIVITY"))
	if err != nil {
		return err
	}
	if inact < 1 {
		return fmt.Errorf("key caching disabled because %s = %d", envPrefix+"_KEY_INACTIVITY", inact)
	}
	tf, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	defer os.Remove(tf.Name())
	if _, err = tf.Write(key); err != nil {
		return err
	}
	if err = tf.Close(); err != nil {
		return err
	}
	return os.Rename(tf.Name(), fname)
}

// UncacheKey will immediately clear the cache location based on the x_KEY_FILE
// OS environment variable.
func UncacheKey(envPrefix string) {
	if envPrefix == "" {
		return
	}
	if fname := os.Getenv(envPrefix + "_KEY_FILE"); fname != "" {
		os.Remove(fname)
	}
}

// KeyWatch will loop forever watching for an expired key file to remove. The
// OS environment variables x_KEY_FILE and x_KEY_INACTIVITY indicate where the
// key is cached and for how long. The logTimeFormat, if not "", indicates
// verbose output of the activity.
func KeyWatch(envPrefix string, logTimeFormat string) error {
	if envPrefix == "" {
		return fmt.Errorf("no envPrefix")
	}
	fname := os.Getenv(envPrefix + "_KEY_FILE")
	if fname == "" {
		return fmt.Errorf("no %s_KEY_FILE set", envPrefix)
	}
	sinact := os.Getenv(envPrefix + "_KEY_INACTIVITY")
	if sinact == "" {
		return fmt.Errorf("no %s_KEY_INACTIVITY set", envPrefix)
	}
	inact, err := strconv.Atoi(sinact)
	if err != nil {
		return fmt.Errorf("could not parse %s_KEY_INACTIVITY value of %#v", envPrefix, sinact)
	}
	if inact < 1 {
		return fmt.Errorf("value of %s_KEY_INACTIVITY is less than 1, indicating the feature should be turned off", envPrefix)
	}
	for {
		sleep := time.Duration(inact) * time.Second
		remove := false
		finfo, err := os.Stat(fname)
		if err != nil {
			if !os.IsNotExist(err) {
				if logTimeFormat != "" {
					fmt.Printf("%s Got error trying to check on %#v: %#v\n", time.Now().Format(logTimeFormat), fname, err)
				}
				remove = true
			}
		} else if finfo.Size() != 32 {
			if logTimeFormat != "" {
				fmt.Printf("%s File size of %#v was %d not 32.\n", time.Now().Format(logTimeFormat), fname, finfo.Size())
			}
			remove = true
		} else if finfo.Mode() != 0600 {
			if logTimeFormat != "" {
				fmt.Printf("%s File permissions on %#v were %04o not 0600.\n", time.Now().Format(logTimeFormat), fname, finfo.Mode())
			}
			remove = true
		} else if time.Now().Sub(finfo.ModTime()) < 60 {
			if logTimeFormat != "" {
				fmt.Printf("%s File time of %#v was more than 60s in the future.\n", time.Now().Format(logTimeFormat), fname)
			}
			remove = true
		} else if time.Now().Sub(finfo.ModTime()).Seconds() >= float64(inact) {
			if logTimeFormat != "" {
				fmt.Printf("%s File time of %#v was inactive for %ds and the timeout is %ds.\n", time.Now().Format(logTimeFormat), fname, int(time.Now().Sub(finfo.ModTime()).Seconds()), inact)
			}
			remove = true
		} else {
			sleep = (time.Duration(inact) * time.Second) - time.Now().Sub(finfo.ModTime())
			if sleep/time.Second > 60 {
				sleep = 60 * time.Second
			}
		}
		if remove {
			err = os.Remove(fname)
			if logTimeFormat != "" {
				if err != nil {
					fmt.Printf("%s Got error trying to remove %#v: %#v\n", time.Now().Format(logTimeFormat), fname, err)
				} else {
					fmt.Printf("%s Removed %#v.\n", time.Now().Format(logTimeFormat), fname)
				}
			}
		}
		if logTimeFormat != "" {
			fmt.Printf("%s Check complete; will check again in %s.\n", time.Now().Format(logTimeFormat), sleep)
		}
		time.Sleep(sleep)
	}
}

func keyPhrase(phrase string) []byte {
	h := sha256.New()
	h.Write([]byte(phrase))
	return h.Sum(nil)
}
