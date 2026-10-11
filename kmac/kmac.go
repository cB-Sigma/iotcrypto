// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package kmac is KMAC128 and KMAC256 of NIST SP 800-185 (clause 4) on
// the cSHAKE of crypto/sha3: KMAC(K, X, L, S) = cSHAKE(bytepad(
// encode_string(K), rate) || X || right_encode(L), L, "KMAC", S). Go's
// standard library has cSHAKE but no KMAC; IEC 62351-4 E2E security
// uses KMAC256 (kMACWithSHAKE256) as an integrity check value algorithm.
// The XOF variant (clause 4.3.1, right_encode(0)) is not provided: IEC
// 62351-4 fixes the output length.
package kmac

import (
	"crypto/sha3"
	"hash"
)

// rates of cSHAKE128 and cSHAKE256 in bytes.
const (
	rate128 = 168
	rate256 = 136
)

// leftEncode is left_encode(x) of SP 800-185 2.3.1.
func leftEncode(x uint64) []byte {
	n := 1
	for v := x >> 8; v > 0; v >>= 8 {
		n++
	}
	b := make([]byte, n+1)
	b[0] = byte(n)
	for i := n; i >= 1; i-- {
		b[i] = byte(x)
		x >>= 8
	}
	return b
}

// rightEncode is right_encode(x) of SP 800-185 2.3.1.
func rightEncode(x uint64) []byte {
	l := leftEncode(x)
	return append(l[1:], l[0])
}

// bytepad is bytepad(encode_string(k), w) of SP 800-185 2.3.3.
func bytepadKey(k []byte, w int) []byte {
	b := leftEncode(uint64(w))
	b = append(b, leftEncode(uint64(len(k))*8)...)
	b = append(b, k...)
	for len(b)%w != 0 {
		b = append(b, 0)
	}
	return b
}

// KMAC is a keyed hash of fixed output length.
type KMAC struct {
	sh    *sha3.SHAKE
	init  []byte // bytepad(encode_string(K))
	n     int    // output bytes
	rate  int
	is256 bool
	s     []byte
}

// New128 returns KMAC128 with key k, output size bytes and
// customization string s.
func New128(k []byte, size int, s []byte) *KMAC { return newKMAC(k, size, s, false) }

// New256 returns KMAC256 with key k, output size bytes and
// customization string s.
func New256(k []byte, size int, s []byte) *KMAC { return newKMAC(k, size, s, true) }

func newKMAC(k []byte, size int, s []byte, is256 bool) *KMAC {
	m := &KMAC{n: size, rate: rate128, is256: is256, s: append([]byte(nil), s...)}
	if is256 {
		m.rate = rate256
	}
	m.init = bytepadKey(k, m.rate)
	m.Reset()
	return m
}

var _ hash.Hash = (*KMAC)(nil)

// Reset starts a new computation with the same key.
func (m *KMAC) Reset() {
	if m.is256 {
		m.sh = sha3.NewCSHAKE256([]byte("KMAC"), m.s)
	} else {
		m.sh = sha3.NewCSHAKE128([]byte("KMAC"), m.s)
	}
	m.sh.Write(m.init)
}

// Write absorbs data; it never fails.
func (m *KMAC) Write(p []byte) (int, error) { return m.sh.Write(p) }

// Sum appends the MAC of the data so far to b; the state is kept.
func (m *KMAC) Sum(b []byte) []byte {
	c := *m.sh // a copy: SHAKE is a value type holding its state
	c.Write(rightEncode(uint64(m.n) * 8))
	out := make([]byte, m.n)
	c.Read(out)
	return append(b, out...)
}

// Size is the output length in bytes.
func (m *KMAC) Size() int { return m.n }

// BlockSize is the rate of the underlying cSHAKE.
func (m *KMAC) BlockSize() int { return m.rate }

// Sum256 is KMAC256(k, x, 8*size, s).
func Sum256(k, x []byte, size int, s []byte) []byte {
	m := New256(k, size, s)
	m.Write(x)
	return m.Sum(nil)
}

// Sum128 is KMAC128(k, x, 8*size, s).
func Sum128(k, x []byte, size int, s []byte) []byte {
	m := New128(k, size, s)
	m.Write(x)
	return m.Sum(nil)
}
