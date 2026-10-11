// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package koblitz

import "math/bits"

// Binary field arithmetic in GF(2^m) with a polynomial basis, for the two
// field sizes of SEC 2 3.2.1 and 3.5.1 (m = 163 and m = 283).
//
// An element is a polynomial of degree below m held in fixed 64-bit limbs,
// least significant limb first, bit i of the whole being the coefficient
// of x^i. Every routine runs the same instruction sequence for any value
// of its operands: loop bounds, shift amounts and the reduction taps
// depend only on the field, never on the data, and there is no table
// indexed by data.

const maxWords = 5 // 283 bits

type fe [maxWords]uint64

type field struct {
	m     int   // degree of the reduction polynomial
	words int   // limbs in use, ceil(m/64)
	bytes int   // octets of an encoded element, ceil(m/8) (SEC 1 2.3.5)
	taps  []int // exponents of f(x) below m, 0 included
}

// clmul returns the 128-bit carry-less product of x and y.
//
// Each half is computed with ordinary integer multiplications on operands
// whose bits are split into four interleaved classes (every fourth bit),
// so that the sums at each product position stay below 16 and cannot carry
// into the next position of the same class; masking keeps one class per
// partial product. Integer multiplication is constant time on the targets
// we build for (arm64, amd64). The high half is the low half of the
// product of the bit-reversed operands, reversed back.
func clmul(x, y uint64) (hi, lo uint64) {
	lo = bmul64(x, y)
	hi = bits.Reverse64(bmul64(bits.Reverse64(x), bits.Reverse64(y))) >> 1
	return hi, lo
}

// bmul64 is the low 64 bits of the carry-less product of x and y.
func bmul64(x, y uint64) uint64 {
	const (
		m0 = 0x1111111111111111
		m1 = 0x2222222222222222
		m2 = 0x4444444444444444
		m3 = 0x8888888888888888
	)
	x0, x1, x2, x3 := x&m0, x&m1, x&m2, x&m3
	y0, y1, y2, y3 := y&m0, y&m1, y&m2, y&m3
	z0 := (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
	z1 := (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
	z2 := (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
	z3 := (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
	return z0&m0 | z1&m1 | z2&m2 | z3&m3
}

// xorAt adds (XOR) w shifted left by s bits into t.
func xorAt(t []uint64, w uint64, s int) {
	q, r := s/64, uint(s%64)
	t[q] ^= w << r
	if r != 0 {
		t[q+1] ^= w >> (64 - r)
	}
}

// reduce sets z to t mod f(x), for t of degree below 2m-1.
func (f *field) reduce(z *fe, t *[2 * maxWords]uint64) {
	top, off := f.m/64, uint(f.m%64)
	// x^j = x^(j-m) * (f(x) - x^m) for j >= m. Fold whole limbs from the top
	// down; a fold lands at least m - 76 bits lower, so always in a limb
	// still to be visited.
	for i := 2*f.words - 1; i > top; i-- {
		w := t[i]
		t[i] = 0
		for _, k := range f.taps {
			xorAt(t[:], w, 64*i-f.m+k)
		}
	}
	w := t[top] >> off
	t[top] &= 1<<off - 1
	for _, k := range f.taps {
		xorAt(t[:], w, k)
	}
	*z = fe{}
	copy(z[:f.words], t[:f.words])
}

func (f *field) add(z, a, b *fe) {
	for i := range z {
		z[i] = a[i] ^ b[i]
	}
}

func (f *field) mul(z, a, b *fe) {
	var t [2 * maxWords]uint64
	for i := 0; i < f.words; i++ {
		for j := 0; j < f.words; j++ {
			hi, lo := clmul(a[i], b[j])
			t[i+j] ^= lo
			t[i+j+1] ^= hi
		}
	}
	f.reduce(z, &t)
}

// spread interleaves the bits of x with zeros (the square of a polynomial
// in characteristic 2).
func spread(x uint32) uint64 {
	v := uint64(x)
	v = (v | v<<16) & 0x0000FFFF0000FFFF
	v = (v | v<<8) & 0x00FF00FF00FF00FF
	v = (v | v<<4) & 0x0F0F0F0F0F0F0F0F
	v = (v | v<<2) & 0x3333333333333333
	v = (v | v<<1) & 0x5555555555555555
	return v
}

func (f *field) sqr(z, a *fe) {
	var t [2 * maxWords]uint64
	for i := 0; i < f.words; i++ {
		t[2*i] = spread(uint32(a[i]))
		t[2*i+1] = spread(uint32(a[i] >> 32))
	}
	f.reduce(z, &t)
}

// sqrn sets z = a^(2^n).
func (f *field) sqrn(z, a *fe, n int) {
	*z = *a
	for range n {
		f.sqr(z, z)
	}
}

// inv sets z = a^-1 (and 0 for a = 0) as a^(2^m - 2), with the Itoh-Tsujii
// addition chain on m-1: b_k = a^(2^k - 1), b_2k = b_k^(2^k) * b_k,
// b_(k+1) = b_k^2 * a. The chain depends only on m.
func (f *field) inv(z, a *fe) {
	e := f.m - 1
	b := *a
	k := 1
	for i := bits.Len(uint(e)) - 2; i >= 0; i-- {
		var t fe
		f.sqrn(&t, &b, k)
		f.mul(&b, &t, &b)
		k *= 2
		if e>>uint(i)&1 == 1 {
			f.sqr(&b, &b)
			f.mul(&b, &b, a)
			k++
		}
	}
	f.sqr(z, &b)
}

// trace returns Tr(a) = a + a^2 + ... + a^(2^(m-1)), which is 0 or 1.
func (f *field) trace(a *fe) uint64 {
	t := *a
	s := *a
	for i := 1; i < f.m; i++ {
		f.sqr(&t, &t)
		f.add(&s, &s, &t)
	}
	return s[0] & 1
}

// halfTrace returns the sum of a^(4^i) for i = 0..(m-1)/2; for odd m and
// Tr(a) = 0 it is a root z of z^2 + z = a.
func (f *field) halfTrace(a *fe) fe {
	t := *a
	s := *a
	for i := 1; i <= (f.m-1)/2; i++ {
		f.sqr(&t, &t)
		f.sqr(&t, &t)
		f.add(&s, &s, &t)
	}
	return s
}

// isZero returns 1 if a is zero and 0 otherwise, in constant time.
func isZero(a *fe) uint64 {
	var v uint64
	for _, w := range a {
		v |= w
	}
	return ((v | -v) >> 63) ^ 1
}

// equal returns 1 if a == b, in constant time.
func equal(a, b *fe) uint64 {
	var d fe
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return isZero(&d)
}

// cswap exchanges a and b if c is 1 and leaves them if c is 0, in constant
// time.
func cswap(a, b *fe, c uint64) {
	m := -c
	for i := range a {
		t := m & (a[i] ^ b[i])
		a[i] ^= t
		b[i] ^= t
	}
}

// csel sets z = b if c is 1 and leaves z = a otherwise, in constant time.
func csel(z, a, b *fe, c uint64) {
	m := -c
	for i := range z {
		z[i] = a[i] ^ (m & (a[i] ^ b[i]))
	}
}

// setBytes decodes a big-endian element of f.bytes octets (SEC 1 2.3.6),
// refusing values of degree m or more.
func (f *field) setBytes(z *fe, b []byte) bool {
	if len(b) != f.bytes {
		return false
	}
	*z = fe{}
	for i, c := range b {
		bit := 8 * (len(b) - 1 - i)
		z[bit/64] |= uint64(c) << uint(bit%64)
	}
	top, off := f.m/64, uint(f.m%64)
	if z[top]>>off != 0 {
		return false
	}
	for i := top + 1; i < maxWords; i++ {
		if z[i] != 0 {
			return false
		}
	}
	return true
}

// bytes encodes a as f.bytes big-endian octets (SEC 1 2.3.5).
func (f *field) bytesOf(a *fe) []byte {
	b := make([]byte, f.bytes)
	for i := range b {
		bit := 8 * (len(b) - 1 - i)
		b[i] = byte(a[bit/64] >> uint(bit%64))
	}
	return b
}
