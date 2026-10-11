// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package koblitz implements the binary-field Koblitz curves sect163k1 and
// sect283k1 (SEC 2 v2.0 3.2.1 and 3.5.1), the curves of Zigbee Smart
// Energy certificate-based key establishment (crypto suites 1 and 2), with
// the point encodings of SEC 1 v2.0 2.3.3 and 2.3.4 and the arithmetic
// modulo the group order that ECQV and ECMQV need.
//
// # Arithmetic
//
// Field elements are polynomials in fixed 64-bit limbs (field.go);
// multiplication is a schoolbook product of limbs whose 64x64 carry-less
// products use integer multiplications on bit classes with holes, followed
// by reduction by the SEC 2 trinomial/pentanomial with fixed shifts.
// Inversion is Fermat's a^(2^m - 2) by the Itoh-Tsujii chain.
//
// Scalar multiplication by a secret is the Montgomery ladder on x-only
// Lopez-Dahab projective coordinates (Lopez and Dahab, CHES 1999), with
// y recovered at the end. The ladder always runs over the bit length of
// the group order n, starting from (O, P), and swaps its two registers
// with masks, so the sequence of field operations is the same for every
// scalar below n. Arithmetic modulo n uses the bigmod package.
//
// # What is constant time, and what is not
//
//   - Constant time in the secret scalar: ScalarMult, ScalarBaseMult,
//     AddScalars, MulScalars, and the field arithmetic under them.
//     Conversions between bytes and scalars leak only lengths.
//   - Whether a result is the point at infinity is returned to the caller
//     (it happens only for a scalar that is 0 modulo the point's order).
//   - Point decoding and validation, Add, Double and the other operations
//     on public points use data-dependent branches; they take only public
//     inputs (certificates, received public keys, public scalars).
//   - RandomScalar rejects out-of-range candidates, which leaks the number
//     of rejections but nothing about the accepted value.
package koblitz

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/cB-Sigma/iotcrypto/bigmod"
)

// Curve is one of the two Koblitz curves y^2 + xy = x^3 + a*x^2 + 1.
type Curve struct {
	name  string
	f     field
	a     uint64 // 0 or 1
	g     Point
	n     *bigmod.Modulus
	nb    []byte // order, ScalarSize octets
	nBits int
	h     int
}

// Point is an affine point, or the point at infinity.
type Point struct {
	x, y fe
	inf  bool
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newCurve(name string, m int, taps []int, a uint64, g, n string, h int) *Curve {
	c := &Curve{name: name, a: a, h: h}
	c.f = field{m: m, words: (m + 63) / 64, bytes: (m + 7) / 8, taps: taps}
	nb := mustHex(n)
	mod, err := bigmod.NewModulus(nb)
	if err != nil {
		panic(err)
	}
	c.n = mod
	c.nBits = new(big.Int).SetBytes(nb).BitLen()
	c.nb = make([]byte, (c.nBits+7)/8)
	copy(c.nb[len(c.nb)-len(nb):], nb)
	p, err := c.DecodePoint(mustHex(g))
	if err != nil {
		panic(name + ": base point: " + err.Error())
	}
	c.g = *p
	return c
}

// SEC 2 v2.0 3.2.1: f(x) = x^163 + x^7 + x^6 + x^3 + 1, a = b = 1, h = 2.
var sect163k1 = newCurve("sect163k1", 163, []int{7, 6, 3, 0}, 1,
	"0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9",
	"04000000000000000000020108A2E0CC0D99F8A5EF", 2)

// SEC 2 v2.0 3.5.1: f(x) = x^283 + x^12 + x^7 + x^5 + 1, a = 0, b = 1, h = 4.
var sect283k1 = newCurve("sect283k1", 283, []int{12, 7, 5, 0}, 0,
	"040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836"+
		"01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61", 4)

// Sect163k1 returns the curve of Zigbee Smart Energy crypto suite 1.
func Sect163k1() *Curve { return sect163k1 }

// Sect283k1 returns the curve of Zigbee Smart Energy crypto suite 2.
func Sect283k1() *Curve { return sect283k1 }

// Name is the SEC 2 name of the curve.
func (c *Curve) Name() string { return c.name }

// FieldSize is the octet length of an encoded field element (21 or 36).
func (c *Curve) FieldSize() int { return c.f.bytes }

// PointSize is the octet length of a compressed point (22 or 37).
func (c *Curve) PointSize() int { return c.f.bytes + 1 }

// ScalarSize is the octet length of a private key (SEC 1 2.3.7): 21 or 36.
func (c *Curve) ScalarSize() int { return len(c.nb) }

// OrderBits is the bit length of the group order n.
func (c *Curve) OrderBits() int { return c.nBits }

// Order returns n as ScalarSize big-endian octets.
func (c *Curve) Order() []byte { return append([]byte(nil), c.nb...) }

// Cofactor is h.
func (c *Curve) Cofactor() int { return c.h }

// Generator returns a copy of the base point G.
func (c *Curve) Generator() *Point { g := c.g; return &g }

// Infinity returns the point at infinity.
func Infinity() *Point { return &Point{inf: true} }

// IsInfinity reports whether p is the point at infinity.
func (p *Point) IsInfinity() bool { return p.inf }

// Equal reports whether p and q are the same point.
func (p *Point) Equal(q *Point) bool {
	if p.inf || q.inf {
		return p.inf == q.inf
	}
	return equal(&p.x, &q.x)&equal(&p.y, &q.y) == 1
}

// ---------------------------------------------------------------------------
// Encoding

var (
	errEncoding = errors.New("koblitz: invalid point encoding")
	errNotOnCur = errors.New("koblitz: point not on curve")
	errInfinity = errors.New("koblitz: point at infinity")
)

// DecodePoint converts a compressed (02/03) or uncompressed (04) octet
// string to a point on the curve (SEC 1 2.3.4). The point at infinity
// (a single 00 octet) is refused, since no key may be the identity.
// Subgroup membership is not checked; see InSubgroup.
func (c *Curve) DecodePoint(b []byte) (*Point, error) {
	fb := c.f.bytes
	switch {
	case len(b) == 1+fb && (b[0] == 2 || b[0] == 3):
		var p Point
		if !c.f.setBytes(&p.x, b[1:]) {
			return nil, errEncoding
		}
		if isZero(&p.x) == 1 {
			// y^2 = b = 1: y = 1.
			p.y = fe{1}
			return &p, nil
		}
		// beta = x + a + b/x^2; z^2 + z = beta; y = x*z.
		var beta, t fe
		c.f.sqr(&t, &p.x)
		c.f.inv(&t, &t)
		c.f.add(&beta, &p.x, &t)
		beta[0] ^= c.a
		if c.f.trace(&beta) != 0 {
			return nil, errNotOnCur
		}
		z := c.f.halfTrace(&beta)
		if z[0]&1 != uint64(b[0]&1) {
			z[0] ^= 1
		}
		c.f.mul(&p.y, &p.x, &z)
		if !c.onCurve(&p) {
			return nil, errNotOnCur
		}
		return &p, nil
	case len(b) == 1+2*fb && b[0] == 4:
		var p Point
		if !c.f.setBytes(&p.x, b[1:1+fb]) || !c.f.setBytes(&p.y, b[1+fb:]) {
			return nil, errEncoding
		}
		if !c.onCurve(&p) {
			return nil, errNotOnCur
		}
		return &p, nil
	case len(b) == 1 && b[0] == 0:
		return nil, errInfinity
	}
	return nil, errEncoding
}

// Compress returns the compressed octet string of p (SEC 1 2.3.3).
func (c *Curve) Compress(p *Point) ([]byte, error) {
	if p.inf {
		return nil, errInfinity
	}
	out := make([]byte, 1+c.f.bytes)
	out[0] = 2
	if isZero(&p.x) == 0 {
		var z fe
		c.f.inv(&z, &p.x)
		c.f.mul(&z, &z, &p.y)
		out[0] |= byte(z[0] & 1)
	}
	copy(out[1:], c.f.bytesOf(&p.x))
	return out, nil
}

// Uncompressed returns the 04 || x || y octet string of p.
func (c *Curve) Uncompressed(p *Point) ([]byte, error) {
	if p.inf {
		return nil, errInfinity
	}
	out := []byte{4}
	out = append(out, c.f.bytesOf(&p.x)...)
	return append(out, c.f.bytesOf(&p.y)...), nil
}

// XBytes returns the x coordinate of p as FieldSize octets (SEC 1 2.3.5).
func (c *Curve) XBytes(p *Point) ([]byte, error) {
	if p.inf {
		return nil, errInfinity
	}
	return c.f.bytesOf(&p.x), nil
}

func (c *Curve) onCurve(p *Point) bool {
	// y^2 + xy = x^3 + a x^2 + 1
	var l, r, t, x2 fe
	c.f.sqr(&l, &p.y)
	c.f.mul(&t, &p.x, &p.y)
	c.f.add(&l, &l, &t)
	c.f.sqr(&x2, &p.x)
	c.f.mul(&r, &x2, &p.x)
	if c.a == 1 {
		c.f.add(&r, &r, &x2)
	}
	r[0] ^= 1
	return equal(&l, &r) == 1
}

// IsOnCurve reports whether p satisfies the curve equation (the point at
// infinity does not).
func (c *Curve) IsOnCurve(p *Point) bool { return !p.inf && c.onCurve(p) }

// ---------------------------------------------------------------------------
// Group law on public points (affine, variable time)

// Neg returns -p = (x, x + y).
func (c *Curve) Neg(p *Point) *Point {
	if p.inf {
		return Infinity()
	}
	q := *p
	c.f.add(&q.y, &p.x, &p.y)
	return &q
}

// Add returns p + q. It branches on its inputs: use it on public points
// only.
func (c *Curve) Add(p, q *Point) *Point {
	switch {
	case p.inf:
		r := *q
		return &r
	case q.inf:
		r := *p
		return &r
	}
	if equal(&p.x, &q.x) == 1 {
		if equal(&p.y, &q.y) == 1 {
			return c.Double(p)
		}
		return Infinity() // q = -p
	}
	// l = (y1 + y2)/(x1 + x2); x3 = l^2 + l + x1 + x2 + a; y3 = l(x1 + x3) + x3 + y1
	var l, dx, dy, x3, y3, t fe
	c.f.add(&dx, &p.x, &q.x)
	c.f.add(&dy, &p.y, &q.y)
	c.f.inv(&t, &dx)
	c.f.mul(&l, &dy, &t)
	c.f.sqr(&x3, &l)
	c.f.add(&x3, &x3, &l)
	c.f.add(&x3, &x3, &dx)
	x3[0] ^= c.a
	c.f.add(&t, &p.x, &x3)
	c.f.mul(&y3, &l, &t)
	c.f.add(&y3, &y3, &x3)
	c.f.add(&y3, &y3, &p.y)
	return &Point{x: x3, y: y3}
}

// Double returns 2p. It branches on its input: use it on public points only.
func (c *Curve) Double(p *Point) *Point {
	if p.inf || isZero(&p.x) == 1 {
		return Infinity()
	}
	// l = x + y/x; x3 = l^2 + l + a; y3 = x^2 + (l + 1) x3
	var l, x3, y3, t fe
	c.f.inv(&t, &p.x)
	c.f.mul(&l, &p.y, &t)
	c.f.add(&l, &l, &p.x)
	c.f.sqr(&x3, &l)
	c.f.add(&x3, &x3, &l)
	x3[0] ^= c.a
	t = l
	t[0] ^= 1
	c.f.mul(&y3, &t, &x3)
	c.f.sqr(&t, &p.x)
	c.f.add(&y3, &y3, &t)
	return &Point{x: x3, y: y3}
}

// MulCofactor returns h*p.
func (c *Curve) MulCofactor(p *Point) *Point {
	r := p
	for h := c.h; h > 1; h >>= 1 {
		r = c.Double(r)
	}
	return r
}

// ---------------------------------------------------------------------------
// Montgomery ladder

// ladder runs the x-only Montgomery ladder for the scalar k (big-endian,
// at most nbits significant bits) on the affine x coordinate px (non-zero).
// It returns (X1:Z1) = x(kP) and (X2:Z2) = x((k+1)P). The operations
// performed depend only on nbits.
func (c *Curve) ladder(px *fe, k []byte, nbits int) (x1, z1, x2, z2 fe) {
	f := &c.f
	x1 = fe{1} // O = (1:0)
	x2, z2 = *px, fe{1}
	for i := nbits - 1; i >= 0; i-- {
		bit := uint64(k[len(k)-1-i/8]>>uint(i%8)) & 1
		cswap(&x1, &x2, bit)
		cswap(&z1, &z2, bit)
		// (x2:z2) <- (x1:z1) + (x2:z2), difference P:
		// T1 = X1 Z2, T2 = X2 Z1, Z = (T1 + T2)^2, X = x Z + T1 T2.
		var t1, t2, t fe
		f.mul(&t1, &x1, &z2)
		f.mul(&t2, &x2, &z1)
		f.add(&t, &t1, &t2)
		f.sqr(&z2, &t)
		f.mul(&t, &t1, &t2)
		f.mul(&x2, px, &z2)
		f.add(&x2, &x2, &t)
		// (x1:z1) <- 2 (x1:z1): X = X^4 + b Z^4, Z = X^2 Z^2 (b = 1).
		f.sqr(&t1, &x1)
		f.sqr(&t2, &z1)
		f.mul(&z1, &t1, &t2)
		f.sqr(&t1, &t1)
		f.sqr(&t2, &t2)
		f.add(&x1, &t1, &t2)
		cswap(&x1, &x2, bit)
		cswap(&z1, &z2, bit)
	}
	return
}

// scalarMult computes kP for P not at infinity with x(P) != 0, k given as
// big-endian octets with at most nbits significant bits.
func (c *Curve) scalarMult(p *Point, k []byte, nbits int) *Point {
	f := &c.f
	x1, z1, x2, z2 := c.ladder(&p.x, k, nbits)
	// y recovery (Lopez-Dahab): with D = x Z1 Z2,
	// xk = X1 x Z2 / D,
	// yk = (x + xk) [(X1 + x Z1)(X2 + x Z2) + (x^2 + y) Z1 Z2] / D + y.
	var d, di, xk, yk, t, u, v fe
	f.mul(&t, &z1, &z2) // Z1 Z2
	f.mul(&d, &t, &p.x)
	f.inv(&di, &d)
	f.mul(&xk, &x1, &z2)
	f.mul(&xk, &xk, &p.x)
	f.mul(&xk, &xk, &di)
	f.mul(&u, &p.x, &z1)
	f.add(&u, &u, &x1)
	f.mul(&v, &p.x, &z2)
	f.add(&v, &v, &x2)
	f.mul(&u, &u, &v)
	f.sqr(&v, &p.x)
	f.add(&v, &v, &p.y)
	f.mul(&v, &v, &t)
	f.add(&u, &u, &v)
	f.add(&v, &p.x, &xk)
	f.mul(&yk, &v, &u)
	f.mul(&yk, &yk, &di)
	f.add(&yk, &yk, &p.y)
	// (k+1)P = O means kP = -P = (x, x + y).
	var ny fe
	f.add(&ny, &p.x, &p.y)
	last := isZero(&z2)
	csel(&xk, &xk, &p.x, last)
	csel(&yk, &yk, &ny, last)
	if isZero(&z1) == 1 {
		return Infinity()
	}
	return &Point{x: xk, y: yk}
}

// ScalarMult returns k*p. p must be on the curve and not of order 1 or 2
// (x != 0); the sequence of field operations depends only on the curve.
func (c *Curve) ScalarMult(p *Point, k *Scalar) (*Point, error) {
	if p.inf || isZero(&p.x) == 1 {
		return nil, errors.New("koblitz: scalar multiplication of a point of order at most 2")
	}
	return c.secretMult(p, k), nil
}

// secretMult runs the ladder for a secret scalar with the processor's
// data-independent timing mode on (DIT on arm64, DOITM on amd64 where the
// kernel allows it), so instruction timing does not depend on operands.
func (c *Curve) secretMult(p *Point, k *Scalar) *Point {
	var out *Point
	subtle.WithDataIndependentTiming(func() {
		out = c.scalarMult(p, k.v.Bytes(c.n), c.nBits)
	})
	return out
}

// ScalarBaseMult returns k*G.
func (c *Curve) ScalarBaseMult(k *Scalar) *Point {
	return c.secretMult(&c.g, k)
}

// MulPublic returns k*p for a public, non-negative k of any size (an avf
// value, a certificate hash). The ladder runs over the bit length of k,
// which is therefore not hidden: never pass a secret.
func (c *Curve) MulPublic(p *Point, k *big.Int) *Point {
	if p.inf || k.Sign() == 0 {
		return Infinity()
	}
	if isZero(&p.x) == 1 {
		if k.Bit(0) == 0 {
			return Infinity()
		}
		q := *p
		return &q
	}
	return c.scalarMult(p, k.Bytes(), k.BitLen())
}

// InSubgroup reports whether n*p = O, that is p lies in the subgroup of
// order n generated by G (with p on the curve and not at infinity, this is
// the full public key validation of SEC 1 3.2.2.1).
func (c *Curve) InSubgroup(p *Point) bool {
	if p.inf || !c.onCurve(p) || isZero(&p.x) == 1 {
		return false
	}
	_, z1, _, _ := c.ladder(&p.x, c.nb, c.nBits)
	return isZero(&z1) == 1
}

// ---------------------------------------------------------------------------
// Scalars modulo n

// Scalar is an integer modulo the group order.
type Scalar struct {
	c *Curve
	v *bigmod.Nat
}

// NewScalar returns the scalar 0.
func (c *Curve) NewScalar() *Scalar {
	return &Scalar{c: c, v: bigmod.NewNat().ExpandFor(c.n)}
}

// ScalarFromBytes decodes a big-endian integer of at most ScalarSize octets
// that must be below n.
func (c *Curve) ScalarFromBytes(b []byte) (*Scalar, error) {
	if len(b) > len(c.nb) {
		return nil, errors.New("koblitz: scalar too long")
	}
	v, err := bigmod.NewNat().SetBytes(b, c.n)
	if err != nil {
		return nil, errors.New("koblitz: scalar not below the group order")
	}
	return &Scalar{c: c, v: v}, nil
}

// ScalarFromHash converts a hash output to an integer modulo n as Hn of
// SEC 4 2.3: the leftmost floor(log2 n) bits of h, as an integer.
func (c *Curve) ScalarFromHash(h []byte) *Scalar {
	keep := c.nBits - 1 // n is not a power of two
	e := new(big.Int).SetBytes(h)
	if extra := len(h)*8 - keep; extra > 0 {
		e.Rsh(e, uint(extra))
	}
	b := make([]byte, len(c.nb))
	e.FillBytes(b)
	s, err := c.ScalarFromBytes(b)
	if err != nil {
		panic("koblitz: Hn out of range") // impossible: e < 2^(nBits-1) < n
	}
	return s
}

// RandomScalar returns a uniformly random scalar in [1, n-1] (SEC 1
// 3.2.1), by rejection sampling.
func (c *Curve) RandomScalar(rand io.Reader) (*Scalar, error) {
	b := make([]byte, len(c.nb))
	excess := uint(len(b)*8 - c.nBits)
	for range 1000 {
		if _, err := io.ReadFull(rand, b); err != nil {
			return nil, err
		}
		b[0] &= 0xFF >> excess
		s, err := c.ScalarFromBytes(b)
		if err != nil || s.IsZero() {
			continue
		}
		return s, nil
	}
	return nil, errors.New("koblitz: random source keeps failing")
}

// Bytes returns s as ScalarSize big-endian octets.
func (s *Scalar) Bytes() []byte { return s.v.Bytes(s.c.n) }

// IsZero reports whether s is 0.
func (s *Scalar) IsZero() bool { return s.v.IsZero() == 1 }

// Equal reports whether s and t are equal, in constant time.
func (s *Scalar) Equal(t *Scalar) bool { return s.v.Equal(t.v) == 1 }

// AddScalars returns a new scalar a + b mod n.
func (c *Curve) AddScalars(a, b *Scalar) *Scalar {
	r := bigmod.NewNat().Set(a.v)
	r.Add(b.v, c.n)
	return &Scalar{c: c, v: r}
}

// MulScalars returns a new scalar a * b mod n.
func (c *Curve) MulScalars(a, b *Scalar) *Scalar {
	r := bigmod.NewNat().Set(a.v)
	r.Mul(b.v, c.n)
	return &Scalar{c: c, v: r}
}
