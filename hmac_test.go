package brimcrypt

import (
	"fmt"
	"testing"
)

func TestHMAC(t *testing.T) {
	h := newHMAC([]byte("testing"), []byte("testing"))
	if len(h) != 32 {
		t.Errorf("HMAC wasn't 32 bytes, was %d", len(h))
	}
	exp := "a33c8c7140685e7d9622b353fdc0f41744905de7ea6c9f5fc2f3607d205ca5a8"
	if fmt.Sprintf("%x", h) != exp {
		t.Errorf("HMAC %x did not match %s", h, exp)
	}
	if !validateHMAC([]byte("testing"), h, []byte("testing")) {
		t.Errorf("could not validate HMAC")
	}
	if validateHMAC([]byte("test"), h, []byte("testing")) {
		t.Errorf("incorrect HMAC validation")
	}
	if validateHMAC([]byte("testing"), h, []byte("test")) {
		t.Errorf("incorrect HMAC validation")
	}
	h[16] = 0
	if validateHMAC([]byte("testing"), h, []byte("testing")) {
		t.Errorf("incorrect HMAC validation")
	}
}
