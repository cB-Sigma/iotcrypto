// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ecqv_test

import (
	"crypto/rand"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/ecqv"
)

// A private CA issues a suite 2 implicit certificate; the device builds its
// private key from it and anyone can rebuild the matching public key.
func ExampleIssue() {
	c := ecqv.Suite2.Curve()
	dCA, _ := c.RandomScalar(rand.Reader)
	qCA := c.ScalarBaseMult(dCA)

	kU, rU, _ := ecqv.Request(ecqv.Suite2, rand.Reader) // on the device
	fields := ecqv.Suite2Fields{Subject: 0x0022080000000001, KeyUsage: ecqv.UsageKeyAgreement, ValidFor: ecqv.ValidForever}
	raw, r, err := ecqv.Issue(ecqv.Suite2, dCA, rU, func(pu []byte) []byte { return ecqv.EncodeSuite2(pu, fields) }, rand.Reader)
	if err != nil {
		panic(err)
	}
	cert, err := ecqv.Parse(ecqv.Suite2, raw)
	if err != nil {
		panic(err)
	}
	dU, _ := ecqv.PrivateKey(cert, qCA, r, kU)
	qU, _ := ecqv.PublicKey(cert, qCA)
	fmt.Println(len(raw), c.ScalarBaseMult(dU).Equal(qU))
	// Output:
	// 74 true
}
