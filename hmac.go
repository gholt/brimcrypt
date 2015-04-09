package brimcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
)

const hmacSize = 32

func newHMAC(block []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(block)
	return h.Sum(nil)
}

func validateHMAC(block []byte, givenHMAC []byte, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(block)
	return hmac.Equal(givenHMAC, h.Sum(nil))
}
