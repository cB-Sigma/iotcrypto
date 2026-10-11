// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package ecqv implements Elliptic Curve Qu-Vanstone implicit certificates
// (SEC 4 v1.0) as Zigbee Smart Energy uses them for certificate-based key
// establishment: the 48-octet crypto suite 1 certificate on sect163k1
// (SE 1.4a C.4.2.2.4) and the 74-octet crypto suite 2 certificate on
// sect283k1 (SE 1.4a C.4.2.3.3, the SEC 4 minimal encoding), with
// AES-MMO as the hash (C.4.2.2.6).
//
// It covers the certificate processing a key-establishment partner needs
// (public key extraction, SEC 4 3.5), private key reconstruction by the
// certificate's owner (Cert Reception, SEC 4 3.6), and, for tests and a
// private CA, the requester and CA steps (SEC 4 3.3 and 3.4).
package ecqv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cB-Sigma/iotcrypto/aesmmo"
	"github.com/cB-Sigma/iotcrypto/koblitz"
)

// Suite is a Key Establishment crypto suite, as its bit in the
// KeyEstablishmentSuite bitmap (SE 1.4a Table C-4).
type Suite uint16

const (
	Suite1 Suite = 0x0001 // sect163k1, 48-octet certificates
	Suite2 Suite = 0x0002 // sect283k1, 74-octet certificates
)

// String names the suite ("crypto suite 1" or "crypto suite 2").
func (s Suite) String() string {
	switch s {
	case Suite1:
		return "crypto suite 1"
	case Suite2:
		return "crypto suite 2"
	}
	return fmt.Sprintf("suite 0x%04x", uint16(s))
}

// Curve is the suite's curve, nil for an unknown suite.
func (s Suite) Curve() *koblitz.Curve {
	switch s {
	case Suite1:
		return koblitz.Sect163k1()
	case Suite2:
		return koblitz.Sect283k1()
	}
	return nil
}

// CertSize is the octet length of the suite's certificate (Table C-14).
func (s Suite) CertSize() int {
	switch s {
	case Suite1:
		return 48
	case Suite2:
		return 74
	}
	return 0
}

// Suite 2 field values (SE 1.4a C.4.2.3.3, Table C-13).
const (
	TypeNoExtensions  = 0x00
	CurveSect283k1    = 0x0D
	HashAESMMO        = 0x08
	UsageKeyAgreement = 0x08 // bit 3
	UsageSignature    = 0x80 // bit 7
	ValidForever      = 0xFFFFFFFF
)

// Certificate is a decoded Smart Energy implicit certificate.
type Certificate struct {
	Suite Suite
	Raw   []byte

	// PublicReconstr is the compressed public-key reconstruction point.
	PublicReconstr []byte
	// Subject and Issuer are the 64-bit identifiers as carried, most
	// significant octet first; the subject is the owner's IEEE address.
	Subject uint64
	Issuer  [8]byte

	// Suite 1 only: ten octets of profile data, the first two being the
	// profile identifier.
	ProfileAttributes []byte

	// Suite 2 only.
	Type      byte
	Serial    [8]byte
	CurveID   byte
	HashID    byte
	ValidFrom int64  // Unix seconds, signed 40-bit
	ValidFor  uint32 // seconds after ValidFrom; ValidForever for no end
	KeyUsage  byte
}

// ErrFormat reports a certificate of the wrong size.
var ErrFormat = errors.New("ecqv: certificate has the wrong length for its suite")

// Parse decodes the octets of a certificate of the given suite. It checks
// only the layout; Check applies the Smart Energy field rules and
// PublicKey the cryptographic ones.
func Parse(s Suite, b []byte) (*Certificate, error) {
	if s.CertSize() == 0 {
		return nil, fmt.Errorf("ecqv: unsupported %v", s)
	}
	if len(b) != s.CertSize() {
		return nil, ErrFormat
	}
	c := &Certificate{Suite: s, Raw: append([]byte(nil), b...)}
	r := c.Raw
	switch s {
	case Suite1:
		// PublicReconstrKey(22) || Subject(8) || Issuer(8) || ProfileAttributeData(10)
		c.PublicReconstr = r[0:22]
		c.Subject = binary.BigEndian.Uint64(r[22:30])
		copy(c.Issuer[:], r[30:38])
		c.ProfileAttributes = r[38:48]
	case Suite2:
		// Type(1) || SerialNo(8) || Curve(1) || Hash(1) || Issuer(8) ||
		// ValidFrom(5) || ValidTo(4) || Subject(8) || KeyUsage(1) || PublicReconstrKey(37)
		c.Type = r[0]
		copy(c.Serial[:], r[1:9])
		c.CurveID = r[9]
		c.HashID = r[10]
		copy(c.Issuer[:], r[11:19])
		from := int64(r[19])<<32 | int64(binary.BigEndian.Uint32(r[20:24]))
		if from&(1<<39) != 0 {
			from -= 1 << 40
		}
		c.ValidFrom = from
		c.ValidFor = binary.BigEndian.Uint32(r[24:28])
		c.Subject = binary.BigEndian.Uint64(r[28:36])
		c.KeyUsage = r[36]
		c.PublicReconstr = r[37:74]
	}
	return c, nil
}

// ErrInvalid reports a suite 2 certificate whose type, curve, hash or key
// usage Smart Energy key establishment does not allow (SE 1.4a
// C.3.1.2.3.1.2): the partner answers INVALID_CERTIFICATE.
var ErrInvalid = errors.New("ecqv: certificate type, curve, hash or key usage not allowed for key establishment")

// Check applies the Smart Energy rules to the certificate's fields: for
// suite 2, no extensions, curve sect283k1, hash AES-MMO and the key
// agreement usage bit.
func (c *Certificate) Check() error {
	if c.Suite != Suite2 {
		return nil
	}
	if c.Type != TypeNoExtensions || c.CurveID != CurveSect283k1 || c.HashID != HashAESMMO || c.KeyUsage&UsageKeyAgreement == 0 {
		return ErrInvalid
	}
	return nil
}

// ValidAt reports whether t lies in the certificate's validity period.
// Suite 1 certificates carry none and are always valid.
func (c *Certificate) ValidAt(t time.Time) bool {
	if c.Suite != Suite2 {
		return true
	}
	u := t.Unix()
	if u < c.ValidFrom {
		return false
	}
	return c.ValidFor == ValidForever || u <= c.ValidFrom+int64(c.ValidFor)
}

// NotAfter is the end of the validity period; ok is false when there is
// none (suite 1, or a suite 2 certificate valid forever).
func (c *Certificate) NotAfter() (t time.Time, ok bool) {
	if c.Suite != Suite2 || c.ValidFor == ValidForever {
		return time.Time{}, false
	}
	return time.Unix(c.ValidFrom+int64(c.ValidFor), 0).UTC(), true
}

// hash is e = Hn(Cert) with the AES-MMO hash (SEC 4 2.3).
func hash(curve *koblitz.Curve, raw []byte) *koblitz.Scalar {
	h := aesmmo.Sum(raw)
	return curve.ScalarFromHash(h[:])
}

// PublicKey extracts the certificate owner's public key
// QU = Hn(Cert) * PU + QCA (SEC 4 3.5). The reconstruction point must be a
// valid public key (on the curve, in the order-n subgroup), and so must
// the result.
func PublicKey(c *Certificate, ca *koblitz.Point) (*koblitz.Point, error) {
	curve := c.Suite.Curve()
	pu, err := curve.DecodePoint(c.PublicReconstr)
	if err != nil {
		return nil, fmt.Errorf("ecqv: reconstruction point: %w", err)
	}
	if !curve.InSubgroup(pu) {
		return nil, errors.New("ecqv: reconstruction point outside the order-n subgroup")
	}
	e := hash(curve, c.Raw)
	q, err := curve.ScalarMult(pu, e)
	if err != nil {
		return nil, err
	}
	q = curve.Add(q, ca)
	if q.IsInfinity() {
		return nil, errors.New("ecqv: reconstructed public key is the identity")
	}
	return q, nil
}

// PrivateKey is Cert Reception (SEC 4 3.6): from the requester's secret kU
// and the CA's private-key contribution r it computes dU = r + e*kU mod n
// and checks that dU*G is the key PublicKey extracts.
func PrivateKey(c *Certificate, ca *koblitz.Point, r, kU *koblitz.Scalar) (*koblitz.Scalar, error) {
	curve := c.Suite.Curve()
	qu, err := PublicKey(c, ca)
	if err != nil {
		return nil, err
	}
	e := hash(curve, c.Raw)
	d := curve.AddScalars(r, curve.MulScalars(e, kU))
	if !curve.ScalarBaseMult(d).Equal(qu) {
		return nil, errors.New("ecqv: private key does not match the certificate")
	}
	return d, nil
}

// Request is the requester's first step (SEC 4 3.3): a random kU and the
// request point RU = kU*G.
func Request(s Suite, rand io.Reader) (kU *koblitz.Scalar, ru *koblitz.Point, err error) {
	curve := s.Curve()
	if curve == nil {
		return nil, nil, fmt.Errorf("ecqv: unsupported %v", s)
	}
	if kU, err = curve.RandomScalar(rand); err != nil {
		return nil, nil, err
	}
	return kU, curve.ScalarBaseMult(kU), nil
}

// Issue is the CA's certificate generation (SEC 4 3.4): with a random k it
// sets PU = RU + k*G, encodes the certificate with encode(PU), and returns
// it with the private-key contribution r = e*k + dCA mod n.
func Issue(s Suite, dCA *koblitz.Scalar, ru *koblitz.Point, encode func(pu []byte) []byte, rand io.Reader) (cert []byte, r *koblitz.Scalar, err error) {
	curve := s.Curve()
	if curve == nil {
		return nil, nil, fmt.Errorf("ecqv: unsupported %v", s)
	}
	if !curve.InSubgroup(ru) {
		return nil, nil, errors.New("ecqv: request point is not a valid public key")
	}
	qca := curve.ScalarBaseMult(dCA)
	for range 100 {
		k, err := curve.RandomScalar(rand)
		if err != nil {
			return nil, nil, err
		}
		pu := curve.Add(ru, curve.ScalarBaseMult(k))
		if pu.IsInfinity() {
			continue
		}
		enc, _ := curve.Compress(pu)
		cert = encode(enc)
		if len(cert) != s.CertSize() {
			return nil, nil, ErrFormat
		}
		e := hash(curve, cert)
		q, _ := curve.ScalarMult(pu, e)
		if curve.Add(q, qca).IsInfinity() {
			continue
		}
		return cert, curve.AddScalars(curve.MulScalars(e, k), dCA), nil
	}
	return nil, nil, errors.New("ecqv: could not issue a certificate")
}

// EncodeSuite1 lays out a suite 1 certificate (C.4.2.2.4).
func EncodeSuite1(pu []byte, subject uint64, issuer [8]byte, attrs [10]byte) []byte {
	b := make([]byte, 0, 48)
	b = append(b, pu...)
	b = binary.BigEndian.AppendUint64(b, subject)
	b = append(b, issuer[:]...)
	return append(b, attrs[:]...)
}

// Suite2Fields are the fields of a suite 2 certificate other than the
// reconstruction point.
type Suite2Fields struct {
	Serial    [8]byte
	Issuer    [8]byte
	ValidFrom int64
	ValidFor  uint32
	Subject   uint64
	KeyUsage  byte
}

// EncodeSuite2 lays out a suite 2 certificate (C.4.2.3.3) with type 0,
// curve sect283k1 and hash AES-MMO.
func EncodeSuite2(pu []byte, f Suite2Fields) []byte {
	b := make([]byte, 0, 74)
	b = append(b, TypeNoExtensions)
	b = append(b, f.Serial[:]...)
	b = append(b, CurveSect283k1, HashAESMMO)
	b = append(b, f.Issuer[:]...)
	from := uint64(f.ValidFrom) & (1<<40 - 1)
	b = append(b, byte(from>>32))
	b = binary.BigEndian.AppendUint32(b, uint32(from))
	b = binary.BigEndian.AppendUint32(b, f.ValidFor)
	b = binary.BigEndian.AppendUint64(b, f.Subject)
	b = append(b, f.KeyUsage)
	return append(b, pu...)
}
