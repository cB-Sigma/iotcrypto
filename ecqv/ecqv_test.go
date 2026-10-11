// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ecqv

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iotcrypto/koblitz"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// SE 1.4a annex C.5.1 and C.6.1 preconfigured data.
const (
	ca1       = "0200FDE8A7F3D1084224962A4E7C54E69AC3F04DA6B8"
	cert1Dev1 = "03045FDFC8D85FFB8B3993CB72DDCAA55F00B3E87D6D0000000000000001544553545345434101090006000000000000"
	pub1Dev1  = "030290a1f5c08dad5f2945e335620c7a98fac46666a1"
	cert1Dev2 = "020615E07D30ECA2DAD58002E667D94BC1B4223983070000000000000002544553545345434101090006000000000000"
	pub1Dev2  = "03025BBA38D0C7B5436B68DF728F093E7A1D6C437E6D"

	ca2       = "0207A445022D9F39F49BDC38380026A27A9E0A1799313AB28C5C1A1C6B605154DB1DFF6752"
	cert2Dev1 = "002622A505E8938F270D081112131415161718005292A35BFFFFFFFF0A0B0C0D0E0F10118803" +
		"03B4E9DC543A64333C982308022B54E67E2F15F532551B0A11E2E2C1C1D3097A4324E7ED"
	pub2Dev1  = "0202F4FA2A3040433C6820299D182A1042E41404E337C57F47716B42DFAF970F1580A04C9B"
	cert2Dev2 = "0084A933B37F018DEC0D081112131415161718005292A38AFFFFFFFF0A0B0C0D0E0F10128803" +
		"076277E2F7E2252B16A0E92B6E8771BB3F207946CBD4A45D9A9DF6EDAB8C796A48E89DEC"
	pub2Dev2 = "03030E56F7ADE866E76372764BA20A9FF1FE4CAE522F94839E70F2ADFC1CA3E97F4DDCAF2E"
)

// Covers: SIG-IPE-2751
func TestParseSuite1(t *testing.T) {
	c, err := Parse(Suite1, unhex(t, cert1Dev1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.PublicReconstr, unhex(t, "03045FDFC8D85FFB8B3993CB72DDCAA55F00B3E87D6D")) ||
		c.Subject != 1 || !bytes.Equal(c.Issuer[:], []byte("TESTSECA")) ||
		!bytes.Equal(c.ProfileAttributes, unhex(t, "01090006000000000000")) {
		t.Fatalf("fields: %+v", c)
	}
	if c.Check() != nil || !c.ValidAt(time.Now()) {
		t.Fatal("suite 1 certificate refused")
	}
	if _, err := Parse(Suite1, unhex(t, cert1Dev1)[:47]); err != ErrFormat {
		t.Fatalf("short certificate: %v", err)
	}
	if _, err := Parse(Suite2, unhex(t, cert1Dev1)); err != ErrFormat {
		t.Fatalf("suite 1 octets parsed as suite 2: %v", err)
	}
	if _, err := Parse(Suite(4), unhex(t, cert1Dev1)); err == nil {
		t.Fatal("unknown suite parsed")
	}
}

// Covers: SIG-IPE-2751
func TestParseSuite2(t *testing.T) {
	c, err := Parse(Suite2, unhex(t, cert2Dev1))
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != 0 || !bytes.Equal(c.Serial[:], unhex(t, "2622A505E8938F27")) || c.CurveID != 0x0D || c.HashID != 0x08 ||
		!bytes.Equal(c.Issuer[:], unhex(t, "1112131415161718")) || c.ValidFrom != 0x005292A35B ||
		c.ValidFor != ValidForever || c.Subject != 0x0A0B0C0D0E0F1011 || c.KeyUsage != 0x88 ||
		!bytes.Equal(c.PublicReconstr, unhex(t, "0303B4E9DC543A64333C982308022B54E67E2F15F532551B0A11E2E2C1C1D3097A4324E7ED")) {
		t.Fatalf("fields: %+v", c)
	}
	if err := c.Check(); err != nil {
		t.Fatal(err)
	}
	from := time.Unix(0x005292A35B, 0)
	if c.ValidAt(from.Add(-time.Second)) || !c.ValidAt(from) || !c.ValidAt(from.AddDate(50, 0, 0)) {
		t.Fatal("validity with no end")
	}
	if _, ok := c.NotAfter(); ok {
		t.Fatal("NotAfter for a certificate valid forever")
	}
	// Each field Check covers makes the certificate invalid.
	for _, mut := range []func(b []byte){
		func(b []byte) { b[0] = 1 },    // extensions
		func(b []byte) { b[9] = 0x0C }, // curve
		func(b []byte) { b[10] = 0x01 },
		func(b []byte) { b[36] = UsageSignature }, // no key agreement
	} {
		b := unhex(t, cert2Dev1)
		mut(b)
		c, _ := Parse(Suite2, b)
		if c.Check() != ErrInvalid {
			t.Errorf("mutated certificate passed Check: %x", b)
		}
	}
	// A bounded validity period, and a negative 40-bit ValidFrom.
	b := unhex(t, cert2Dev1)
	copy(b[19:28], unhex(t, "0000000064 00000E10")) // from 100, one hour
	c, _ = Parse(Suite2, b)
	if !c.ValidAt(time.Unix(3700, 0)) || c.ValidAt(time.Unix(3701, 0)) {
		t.Fatal("bounded validity")
	}
	if na, ok := c.NotAfter(); !ok || na.Unix() != 3700 {
		t.Fatal("NotAfter")
	}
	copy(b[19:24], unhex(t, "FFFFFFFFFF"))
	c, _ = Parse(Suite2, b)
	if c.ValidFrom != -1 {
		t.Fatalf("ValidFrom %d, want -1", c.ValidFrom)
	}
}

// Public key extraction reproduces the device public keys of the annex
// from each certificate and the CA key.
//
// Covers: SIG-IPE-2751
func TestPublicKeyVectors(t *testing.T) {
	cases := []struct {
		s              Suite
		ca, cert, want string
	}{
		{Suite1, ca1, cert1Dev1, pub1Dev1},
		{Suite1, ca1, cert1Dev2, pub1Dev2},
		{Suite2, ca2, cert2Dev1, pub2Dev1},
		{Suite2, ca2, cert2Dev2, pub2Dev2},
	}
	for i, tc := range cases {
		curve := tc.s.Curve()
		ca, err := curve.DecodePoint(unhex(t, tc.ca))
		if err != nil || !curve.InSubgroup(ca) {
			t.Fatalf("%d: CA key: %v", i, err)
		}
		c, err := Parse(tc.s, unhex(t, tc.cert))
		if err != nil {
			t.Fatal(err)
		}
		q, err := PublicKey(c, ca)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		got, _ := curve.Compress(q)
		if !bytes.Equal(got, unhex(t, tc.want)) {
			t.Errorf("%d: Q = %x, want %s", i, got, strings.ToLower(tc.want))
		}
		// Any change to the certificate changes the key.
		raw := unhex(t, tc.cert)
		raw[len(raw)/2+3] ^= 1
		c2, _ := Parse(tc.s, raw)
		if q2, err := PublicKey(c2, ca); err == nil && q2.Equal(q) {
			t.Errorf("%d: altered certificate gives the same key", i)
		}
	}
}

// A reconstruction point off the subgroup is refused.
func TestPublicKeyRejects(t *testing.T) {
	curve := Suite1.Curve()
	ca, _ := curve.DecodePoint(unhex(t, ca1))
	raw := unhex(t, cert1Dev1)
	// x = 0 decodes to the point of order 2.
	copy(raw[:22], append([]byte{2}, make([]byte, 21)...))
	c, _ := Parse(Suite1, raw)
	if _, err := PublicKey(c, ca); err == nil {
		t.Fatal("order-2 reconstruction point accepted")
	}
	raw[0] = 5
	c, _ = Parse(Suite1, raw)
	if _, err := PublicKey(c, ca); err == nil {
		t.Fatal("bad point encoding accepted")
	}
}

// A private CA issues certificates of both suites; the requester
// reconstructs its private key, which matches the extracted public key.
//
// Covers: SIG-IPE-2751
func TestIssueAndReconstruct(t *testing.T) {
	for _, s := range []Suite{Suite1, Suite2} {
		curve := s.Curve()
		dCA, _ := curve.RandomScalar(rand.Reader)
		qCA := curve.ScalarBaseMult(dCA)
		kU, ru, err := Request(s, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		encode := func(pu []byte) []byte {
			if s == Suite1 {
				return EncodeSuite1(pu, 0x0011223344556677, [8]byte{'S', 'I', 'G', 'M', 'A', 'C', 'A', '1'}, [10]byte{0x01, 0x09})
			}
			return EncodeSuite2(pu, Suite2Fields{Serial: [8]byte{1}, Issuer: [8]byte{2}, ValidFrom: 1700000000, ValidFor: ValidForever, Subject: 0x0011223344556677, KeyUsage: 0x88})
		}
		raw, r, err := Issue(s, dCA, ru, encode, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(s, raw)
		if err != nil || c.Subject != 0x0011223344556677 || c.Check() != nil {
			t.Fatalf("%v: issued certificate: %v", s, err)
		}
		d, err := PrivateKey(c, qCA, r, kU)
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		q, _ := PublicKey(c, qCA)
		if !curve.ScalarBaseMult(d).Equal(q) {
			t.Fatalf("%v: key pair mismatch", s)
		}
		// A wrong contribution is detected.
		one, _ := curve.ScalarFromBytes([]byte{1})
		if _, err := PrivateKey(c, qCA, curve.AddScalars(r, one), kU); err == nil {
			t.Fatalf("%v: wrong r accepted", s)
		}
	}
}

// Covers: SIG-IPE-2751
func FuzzParse(f *testing.F) {
	f.Add(uint8(1), unhex(f, cert1Dev1))
	f.Add(uint8(2), unhex(f, cert2Dev1))
	f.Add(uint8(2), unhex(f, cert2Dev2))
	f.Add(uint8(1), []byte{})
	cas := map[Suite]*koblitz.Point{}
	for s, h := range map[Suite]string{Suite1: ca1, Suite2: ca2} {
		p, err := s.Curve().DecodePoint(unhex(f, h))
		if err != nil {
			f.Fatal(err)
		}
		cas[s] = p
	}
	f.Fuzz(func(t *testing.T, sel uint8, b []byte) {
		s := Suite(1 + sel%2)
		c, err := Parse(s, b)
		if err != nil {
			if len(b) == s.CertSize() {
				t.Fatalf("right-size certificate refused: %v", err)
			}
			return
		}
		if !bytes.Equal(c.Raw, b) || len(c.PublicReconstr) != s.Curve().PointSize() {
			t.Fatal("layout")
		}
		_ = c.Check()
		_ = c.ValidAt(time.Unix(0, 0))
		if q, err := PublicKey(c, cas[s]); err == nil && !s.Curve().InSubgroup(q) {
			t.Fatal("extracted key outside the subgroup")
		}
	})
}
