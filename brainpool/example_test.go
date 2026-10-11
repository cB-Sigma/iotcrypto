// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package brainpool_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/brainpool"
)

// Sign and verify with a brainpoolP256r1 key, and agree on an ECDH secret.
func ExampleGenerateKey() {
	c := brainpool.P256r1()
	key, err := brainpool.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256([]byte("message"))
	sig, err := key.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(brainpool.Verify(key.Public().(*ecdsa.PublicKey), digest[:], sig))

	privA, pubA, _ := brainpool.GenerateECDHKey(c, rand.Reader)
	privB, pubB, _ := brainpool.GenerateECDHKey(c, rand.Reader)
	zA, _ := brainpool.ECDH(c, privA, pubB)
	zB, _ := brainpool.ECDH(c, privB, pubA)
	fmt.Println(bytes.Equal(zA, zB))
	// Output:
	// true
	// true
}
