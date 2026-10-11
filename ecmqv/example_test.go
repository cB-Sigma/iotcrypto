// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ecmqv_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/ecmqv"
	"github.com/cB-Sigma/iotcrypto/koblitz"
)

// ECMQV between U and V, each with a static key pair (1) and an ephemeral
// key pair (2): both compute the same shared secret Z.
func ExampleSharedSecret() {
	c := koblitz.Sect283k1()
	pair := func() (*koblitz.Scalar, *koblitz.Point) {
		d, _ := c.RandomScalar(rand.Reader)
		return d, c.ScalarBaseMult(d)
	}
	d1U, q1U := pair()
	d2U, q2U := pair()
	d1V, q1V := pair()
	d2V, q2V := pair()
	zU, err := ecmqv.SharedSecret(c, d1U, d2U, q2U, q1V, q2V)
	if err != nil {
		panic(err)
	}
	zV, _ := ecmqv.SharedSecret(c, d1V, d2V, q2V, q1U, q2U)
	fmt.Println(len(zU), bytes.Equal(zU, zV))
	// Output:
	// 36 true
}
