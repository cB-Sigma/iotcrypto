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

// Key agreement with the API shaped like crypto/ecdh.
func ExampleECDHCurve() {
	curve := brainpool.ECDHP384r1()
	alice, _ := curve.GenerateKey(rand.Reader)
	bob, _ := curve.GenerateKey(rand.Reader)

	// Bob receives Alice's public key as bytes (compressed here).
	alicePub, err := curve.NewPublicKey(alice.PublicKey().CompressedBytes())
	if err != nil {
		panic(err)
	}
	s1, _ := bob.ECDH(alicePub)
	s2, _ := alice.ECDH(bob.PublicKey())
	fmt.Println(len(s1), bytes.Equal(s1, s2))
	// Output: 48 true
}

// Signatures in the fixed-length r || s form used by JWS and COSE.
func ExampleSignP1363() {
	key, _ := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	digest := sha256.Sum256([]byte("message"))
	sig, _ := brainpool.SignP1363(rand.Reader, key, digest[:])
	fmt.Println(len(sig), brainpool.VerifyP1363(key.PublicKey(), digest[:], sig))
	// Output: 64 true
}
