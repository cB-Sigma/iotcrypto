// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package koblitz_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/koblitz"
)

// Diffie-Hellman on sect283k1: both sides reach the same x-coordinate.
func ExampleCurve_ScalarMult() {
	c := koblitz.Sect283k1()
	a, _ := c.RandomScalar(rand.Reader)
	b, _ := c.RandomScalar(rand.Reader)
	pubA, pubB := c.ScalarBaseMult(a), c.ScalarBaseMult(b)
	sa, _ := c.ScalarMult(pubB, a)
	sb, _ := c.ScalarMult(pubA, b)
	fmt.Println(c.Name(), sa.Equal(sb))
	// Compressed public keys are what Zigbee Smart Energy carries.
	enc, _ := c.Compress(pubA)
	back, _ := c.DecodePoint(enc)
	fmt.Println(len(enc), back.Equal(pubA))
	// Output:
	// sect283k1 true
	// 37 true
}
