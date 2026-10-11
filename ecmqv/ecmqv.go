// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package ecmqv implements the elliptic curve MQV primitive of SEC 1 v2.0
// 3.4 on the Koblitz curves of package koblitz, as Zigbee Smart Energy
// certificate-based key establishment uses it (SE 1.4a C.4.2.4.3).
package ecmqv

import (
	"errors"
	"math/big"

	"github.com/cB-Sigma/iotcrypto/koblitz"
)

// ErrInvalid is the primitive's "invalid" output: a peer key that is not a
// usable point, or a shared point at infinity.
var ErrInvalid = errors.New("ecmqv: invalid")

// avf is the associate value of a point (SEC 1 3.4 steps 2 and 4): the
// integer of its x coordinate's octets, reduced modulo 2^ceil(f/2) with
// f = ceil(log2 n), plus 2^ceil(f/2). n is not a power of two, so
// ceil(log2 n) is the bit length of n.
func avf(c *koblitz.Curve, q *koblitz.Point) (*big.Int, error) {
	xb, err := c.XBytes(q)
	if err != nil {
		return nil, err
	}
	half := uint((c.OrderBits() + 1) / 2)
	x := new(big.Int).SetBytes(xb)
	bound := new(big.Int).Lsh(big.NewInt(1), half)
	x.Mod(x, bound)
	return x.Add(x, bound), nil
}

// SharedSecret returns the shared secret field element z as FieldSize
// octets (SEC 1 2.3.5), computed by U from its static key pair (d1U, Q1U),
// its ephemeral key pair (d2U, q2U), and V's static and ephemeral public
// keys q1V and q2V:
//
//	s = d2U + avf(Q2U) * d1U mod n
//	P = h * s * (Q2V + avf(Q2V) * Q1V), z = x(P)
//
// q1V must be a valid public key (ecqv.PublicKey returns one); q2V need
// only be on the curve (partial validation): the cofactor multiplication
// removes any small-order component, and a result at infinity is refused.
// The operations on d1U, d2U and s run in constant time.
func SharedSecret(c *koblitz.Curve, d1U, d2U *koblitz.Scalar, q2U, q1V, q2V *koblitz.Point) ([]byte, error) {
	if !c.IsOnCurve(q2U) || !c.IsOnCurve(q1V) || !c.IsOnCurve(q2V) {
		return nil, ErrInvalid
	}
	au, err := avf(c, q2U)
	if err != nil {
		return nil, ErrInvalid
	}
	auB := make([]byte, c.ScalarSize())
	au.FillBytes(auB)
	auS, err := c.ScalarFromBytes(auB)
	if err != nil {
		return nil, ErrInvalid
	}
	s := c.AddScalars(d2U, c.MulScalars(auS, d1U))

	av, err := avf(c, q2V)
	if err != nil {
		return nil, ErrInvalid
	}
	t := c.Add(q2V, c.MulPublic(q1V, av))
	t = c.MulCofactor(t)
	if t.IsInfinity() {
		return nil, ErrInvalid
	}
	p, err := c.ScalarMult(t, s)
	if err != nil || p.IsInfinity() {
		return nil, ErrInvalid
	}
	return c.XBytes(p)
}
