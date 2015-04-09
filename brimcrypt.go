// Copyright Gregory Holt. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package brimcrypt contains crypto-related code including an encrypted disk
// file implementation of io.Reader, Writer, Seeker, and Closer. The encryption
// used is AES-256 with each block signed using SHA-256.
//
// This is the latest development area for the package.
//
// For the latest stable version of the package, switch to the
// v1 branch at https://github.com/gholt/brimcrypt/tree/v1
// or use gopkg.in/gholt/brimcrypt.v1 as the import path.
//
// Also, you'd want to use http://godoc.org/gopkg.in/gholt/brimcrypt.v1
// for the v1 documentation.
package brimcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func decrypt0(block []byte, key []byte) ([]byte, error) {
	if len(block)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block must be multiple of AES block size %d", aes.BlockSize)
	}
	if !validateHMAC(block[hmacSize:], block[:hmacSize], key) {
		return nil, KeyError
	}
	iv := block[hmacSize : hmacSize+aes.BlockSize]
	block = block[hmacSize+aes.BlockSize:]
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(ciph, iv)
	mode.CryptBlocks(block, block)
	return block, nil
}

func encrypt0(plainBlock []byte, key []byte) ([]byte, error) {
	if len(plainBlock)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plainBlock must be multiple of AES block size %d", aes.BlockSize)
	}
	block := make([]byte, hmacSize+aes.BlockSize+len(plainBlock))
	iv := block[hmacSize : hmacSize+aes.BlockSize]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(ciph, iv)
	mode.CryptBlocks(block[hmacSize+aes.BlockSize:], plainBlock)
	copy(block[:hmacSize], newHMAC(block[hmacSize:], key))
	return block, err
}
