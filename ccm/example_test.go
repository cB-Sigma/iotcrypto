// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ccm_test

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/ccm"
)

// Seal and open a message with AES-128-CCM, a 13-byte nonce and an 8-byte
// tag (the parameters of RFC 3610's packet vectors).
func ExampleNew() {
	key := bytes.Repeat([]byte{0x40}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := ccm.New(block, 13, 8)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize()) // never reuse a nonce with one key
	header := []byte("header")
	sealed := aead.Seal(nil, nonce, []byte("meter reading 42"), header)
	fmt.Println(len(sealed))
	plain, err := aead.Open(nil, nonce, sealed, header)
	fmt.Printf("%s %v\n", plain, err)
	sealed[0] ^= 1
	_, err = aead.Open(nil, nonce, sealed, header)
	fmt.Println(err)
	// Output:
	// 24
	// meter reading 42 <nil>
	// ccm: message authentication failed
}
