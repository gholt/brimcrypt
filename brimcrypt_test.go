// Copyright 2014 Gregory Holt. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package brimcrypt

import (
	"testing"
)

func TestCrypt0(t *testing.T) {
	plain := []byte("Test Message 123")
	key, err := Key("Test Phrase", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encrypt0(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decrypt0(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(plain) {
		t.Errorf("decryption failed")
	}

	key, err = Key("Test Phrase Two", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	dec, err = decrypt0(enc, key)
	if err == nil {
		t.Errorf("expected err when using wrong key")
	}
	if err != KeyError {
		t.Errorf("expected KeyError when using wrong key; got %s", err)
	}

	plain = []byte("Test Message Not Aligned")
	enc, err = encrypt0(plain, key)
	if err == nil {
		t.Errorf("expected err with misaligned plainBlock")
	}

	enc = []byte("Test Message Not Aligned")
	dec, err = decrypt0(enc, key)
	if err == nil {
		t.Errorf("expected err with misaligned block")
	}
}
