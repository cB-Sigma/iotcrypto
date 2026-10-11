// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package kmac_test

import (
	"encoding/hex"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/kmac"
)

// KMAC256 with a 32-byte output and a customisation string.
func ExampleSum256() {
	key := []byte("a key of any length")
	tag := kmac.Sum256(key, []byte("message"), 32, []byte("my application"))
	fmt.Println(len(tag))
	// The streaming form gives the same tag.
	m := kmac.New256(key, 32, []byte("my application"))
	m.Write([]byte("mess"))
	m.Write([]byte("age"))
	fmt.Println(hex.EncodeToString(m.Sum(nil)) == hex.EncodeToString(tag))
	// Output:
	// 32
	// true
}

// KMACXOF256 as a key-derivation source: read two keys of different
// lengths from one output stream.
func ExampleNewXOF256() {
	x := kmac.NewXOF256([]byte("a key of any length"), []byte("key schedule"))
	x.Write([]byte("context"))
	encKey := make([]byte, 16)
	macKey := make([]byte, 32)
	x.Read(encKey)
	x.Read(macKey)
	fmt.Println(len(encKey), len(macKey))
	// Output:
	// 16 32
}
