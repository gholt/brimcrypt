package brimcrypt

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

func EmptyTestDir(t *testing.T) string {
	tmp, err := ioutil.TempDir("", "go-test")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(tmp)
	return tmp
}

func removeTestTree(pth string) {
	if dir, err := os.Open(pth); os.IsNotExist(err) {
		return
	} else if err != nil {
		fmt.Println(err)
		return
	} else {
		defer dir.Close()
		if fi, err := dir.Stat(); err != nil {
			fmt.Println(err)
			return
		} else if !fi.IsDir() {
			fmt.Printf("%#v is not a directory\n", pth)
			return
		}
		if names, err := dir.Readdirnames(-1); err != nil {
			fmt.Println(err)
			return
		} else {
			for _, name := range names {
				if err = os.Remove(path.Join(pth, name)); err != nil {
					if strings.HasSuffix(err.Error(), ": directory not empty") {
						removeTestTree(path.Join(pth, name))
					} else {
						fmt.Println(err)
					}
				}
			}
		}
	}
	if err := os.Remove(pth); err != nil {
		fmt.Println(err)
	}
}
