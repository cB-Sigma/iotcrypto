// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

// ---------------------------------------------------------------------------
// ECDH in the style of crypto/ecdh. crypto/ecdh.Curve cannot be implemented
// outside the standard library, so the types are this package's own, with
// the same methods.

// ECDHCurve is a brainpool curve for key agreement, used like
// crypto/ecdh.Curve.
type ECDHCurve struct{ c *curve }

var (
	ecdh256 = &ECDHCurve{bp256}
	ecdh384 = &ECDHCurve{bp384}
	ecdh512 = &ECDHCurve{bp512}
)

// ECDHP256r1 returns brainpoolP256r1 for key agreement.
func ECDHP256r1() *ECDHCurve { return ecdh256 }

// ECDHP384r1 returns brainpoolP384r1 for key agreement.
func ECDHP384r1() *ECDHCurve { return ecdh384 }

// ECDHP512r1 returns brainpoolP512r1 for key agreement.
func ECDHP512r1() *ECDHCurve { return ecdh512 }

// ECDHCurveFor returns the key-agreement view of a curve from P256r1,
// P384r1 or P512r1.
func ECDHCurveFor(c elliptic.Curve) (*ECDHCurve, bool) {
	cv, ok := c.(*curve)
	if !ok {
		return nil, false
	}
	switch cv {
	case bp256:
		return ecdh256, true
	case bp384:
		return ecdh384, true
	case bp512:
		return ecdh512, true
	}
	return nil, false
}

// Curve returns the curve as elliptic.Curve, for the functions of this
// package that take one.
func (e *ECDHCurve) Curve() elliptic.Curve { return e.c }

func (e *ECDHCurve) String() string { return e.c.params.Name }

// ECDHPrivateKey is a key-agreement private key, like *ecdh.PrivateKey.
type ECDHPrivateKey struct {
	e   *ECDHCurve
	d   []byte
	pub *ECDHPublicKey
}

// ECDHPublicKey is a key-agreement public key, like *ecdh.PublicKey.
type ECDHPublicKey struct {
	e *ECDHCurve
	q []byte // uncompressed
}

// GenerateKey returns a new random private key.
func (e *ECDHCurve) GenerateKey(rand io.Reader) (*ECDHPrivateKey, error) {
	d, _, err := e.c.randomScalar(rand)
	if err != nil {
		return nil, err
	}
	return e.newPrivate(d)
}

// NewPrivateKey checks that key is a scalar of exactly the curve's size
// (32, 48 or 64 bytes, big-endian) in [1, n-1] and returns it as a key.
func (e *ECDHCurve) NewPrivateKey(key []byte) (*ECDHPrivateKey, error) {
	if _, err := e.c.scalarFromBytes(key); err != nil {
		return nil, err
	}
	return e.newPrivate(append([]byte(nil), key...))
}

func (e *ECDHCurve) newPrivate(d []byte) (*ECDHPrivateKey, error) {
	q, err := e.c.marshalPoint(e.c.scalarBaseMult(d))
	if err != nil {
		return nil, err
	}
	return &ECDHPrivateKey{e: e, d: d, pub: &ECDHPublicKey{e: e, q: q}}, nil
}

// NewPublicKey checks that key is a point on the curve and returns it. It
// takes the uncompressed encoding (0x04 || X || Y), as crypto/ecdh does,
// and also the compressed one (0x02 or 0x03 || X) of SEC 1 2.3.3.
func (e *ECDHCurve) NewPublicKey(key []byte) (*ECDHPublicKey, error) {
	q, err := e.c.pointFromBytes(key)
	if err != nil {
		return nil, err
	}
	b, err := e.c.marshalPoint(q)
	if err != nil {
		return nil, err
	}
	return &ECDHPublicKey{e: e, q: b}, nil
}

// ECDH returns the shared secret: the x-coordinate of d*Q, the curve's size
// in bytes (as RFC 7027 and SEC 1 3.3.1 specify). The scalar
// multiplication is constant time.
func (k *ECDHPrivateKey) ECDH(remote *ECDHPublicKey) ([]byte, error) {
	if remote == nil || remote.e != k.e {
		return nil, errors.New("brainpool: public key is on a different curve")
	}
	return ECDH(k.e.c, k.d, remote.q)
}

// Bytes returns the private scalar, the curve's size in bytes.
func (k *ECDHPrivateKey) Bytes() []byte { return append([]byte(nil), k.d...) }

// Curve returns the key's curve.
func (k *ECDHPrivateKey) Curve() *ECDHCurve { return k.e }

// PublicKey returns the matching public key.
func (k *ECDHPrivateKey) PublicKey() *ECDHPublicKey { return k.pub }

// Public returns the public key (an *ECDHPublicKey), as
// (*ecdh.PrivateKey).Public does.
func (k *ECDHPrivateKey) Public() crypto.PublicKey { return k.pub }

// Equal reports whether x is the same private key, in constant time.
func (k *ECDHPrivateKey) Equal(x crypto.PrivateKey) bool {
	o, ok := x.(*ECDHPrivateKey)
	return ok && o.e == k.e && subtle.ConstantTimeCompare(o.d, k.d) == 1
}

// ECDSA returns the same scalar as an ECDSA signing key.
func (k *ECDHPrivateKey) ECDSA() *PrivateKey {
	p, err := newPrivateKey(k.e.c, append([]byte(nil), k.d...))
	if err != nil {
		panic("brainpool: internal error: " + err.Error())
	}
	return p
}

// Bytes returns the uncompressed encoding 0x04 || X || Y.
func (k *ECDHPublicKey) Bytes() []byte { return append([]byte(nil), k.q...) }

// CompressedBytes returns the compressed encoding 0x02 or 0x03 || X.
func (k *ECDHPublicKey) CompressedBytes() []byte {
	n := k.e.c.size
	return append([]byte{2 | k.q[2*n]&1}, k.q[1:1+n]...)
}

// Curve returns the key's curve.
func (k *ECDHPublicKey) Curve() *ECDHCurve { return k.e }

// Equal reports whether x is the same public key.
func (k *ECDHPublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*ECDHPublicKey)
	return ok && o.e == k.e && subtle.ConstantTimeCompare(o.q, k.q) == 1
}

// ECDSA returns the same point as *ecdsa.PublicKey (for Verify and the
// encodings of this package).
func (k *ECDHPublicKey) ECDSA() *ecdsa.PublicKey {
	n := k.e.c.size
	return &ecdsa.PublicKey{Curve: k.e.c, X: new(big.Int).SetBytes(k.q[1 : 1+n]), Y: new(big.Int).SetBytes(k.q[1+n:])}
}

// ---------------------------------------------------------------------------
// ECDSA in the style of crypto/ecdsa. Public keys are *ecdsa.PublicKey
// whose Curve is P256r1(), P384r1() or P512r1(); private keys are
// *PrivateKey.

// ECDH returns the same scalar as a key-agreement key, like
// (*ecdsa.PrivateKey).ECDH.
func (k *PrivateKey) ECDH() *ECDHPrivateKey {
	e, _ := ECDHCurveFor(k.c)
	p, err := e.newPrivate(append([]byte(nil), k.d...))
	if err != nil {
		panic("brainpool: internal error: " + err.Error())
	}
	return p
}

// Equal reports whether x is the same private key, in constant time.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	o, ok := x.(*PrivateKey)
	return ok && o.c == k.c && subtle.ConstantTimeCompare(o.d, k.d) == 1
}

// PublicKey returns the public key, like (*ecdsa.PrivateKey).PublicKey.
func (k *PrivateKey) PublicKey() *ecdsa.PublicKey { return k.Public().(*ecdsa.PublicKey) }

// ParseRawPrivateKey returns the key with scalar d, which must be exactly
// the curve's size in bytes and in [1, n-1], like ecdsa.ParseRawPrivateKey.
// NewPrivateKey is the lenient form.
func ParseRawPrivateKey(c elliptic.Curve, d []byte) (*PrivateKey, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(cv, append([]byte(nil), d...))
}

// ParseUncompressedPublicKey parses 0x04 || X || Y and checks that the
// point is on the curve, like ecdsa.ParseUncompressedPublicKey.
func ParseUncompressedPublicKey(c elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	return publicKeyFromPoint(cv, b)
}

// ParsePublicKey parses an uncompressed or compressed point (SEC 1 2.3.4)
// and checks that it is on the curve.
func ParsePublicKey(c elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	q, err := cv.pointFromBytes(b)
	if err != nil {
		return nil, err
	}
	x, y := cv.affine(q)
	return &ecdsa.PublicKey{Curve: cv, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// PublicKeyBytes returns the uncompressed encoding of a brainpool public
// key, like (*ecdsa.PublicKey).Bytes.
func PublicKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	_, b, err := pointBytes(pub)
	return b, err
}

// MarshalCompressed returns the compressed encoding of a brainpool public
// key.
func MarshalCompressed(pub *ecdsa.PublicKey) ([]byte, error) {
	c, b, err := pointBytes(pub)
	if err != nil {
		return nil, err
	}
	return append([]byte{2 | b[2*c.size]&1}, b[1:1+c.size]...), nil
}

// SignASN1 signs a digest and returns an ASN.1 DER signature, like
// ecdsa.SignASN1. It is priv.Sign.
func SignASN1(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	return priv.Sign(rand, digest, nil)
}

// VerifyASN1 reports whether sig is a valid ASN.1 DER signature of digest,
// like ecdsa.VerifyASN1. It is Verify.
func VerifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return Verify(pub, digest, sig)
}

// SignP1363 signs a digest and returns the fixed-length signature r || s
// (IEEE P1363, as used by JWS, COSE and the BSI TR-03111 plain format), r
// and s each the curve's size in bytes.
func SignP1363(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	der, err := priv.Sign(rand, digest, nil)
	if err != nil {
		return nil, err
	}
	r, s, err := parseSignature(der)
	if err != nil {
		return nil, err
	}
	n := priv.c.size
	out := make([]byte, 2*n)
	copy(out[n-len(r):n], r)
	copy(out[2*n-len(s):], s)
	return out, nil
}

// VerifyP1363 reports whether sig, r || s of exactly twice the curve's
// size, is a valid signature of digest.
func VerifyP1363(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil {
		return false
	}
	c, err := toCurve(pub.Curve)
	if err != nil || len(sig) != 2*c.size {
		return false
	}
	return Verify(pub, digest, encodeSignature(sig[:c.size], sig[c.size:]))
}
