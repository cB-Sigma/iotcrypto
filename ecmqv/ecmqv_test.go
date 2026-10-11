// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ecmqv

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

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

// scalar reduces a key modulo n: the C.6.3.4.1 ephemeral key is above n
// (F-1500).
func scalar(t *testing.T, c *koblitz.Curve, h string) *koblitz.Scalar {
	t.Helper()
	k := new(big.Int).SetBytes(unhex(t, h))
	k.Mod(k, new(big.Int).SetBytes(c.Order()))
	b := make([]byte, c.ScalarSize())
	k.FillBytes(b)
	s, err := c.ScalarFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func point(t *testing.T, c *koblitz.Curve, h string) *koblitz.Point {
	t.Helper()
	p, err := c.DecodePoint(unhex(t, h))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type party struct{ d1, d2, q2 string }

// SE 1.4a C.5.3 and C.6.3: both sides derive the annex's Z. U is the
// initiator (device 2), V the responder (device 1); the static public keys
// are those C.5.1/C.6.1 give (their extraction from the certificates is
// tested in package ecqv).
//
// Covers: SIG-IPE-2752
func TestSharedSecretVectors(t *testing.T) {
	cases := []struct {
		c              *koblitz.Curve
		u, v           party
		q1u, q1v, want string
	}{
		{
			c:    koblitz.Sect163k1(),
			u:    party{"01E9DDB5580CF72ECE7F215F0AE594E48DF3E7FEE8", "0013D36DE4B1EA8E22739C381370823F404BFF8862", "0300E117C86D0E7CD128B2F34E9076CFF24AF46D7288"},
			v:    party{"00b8a900fcadebabbfa383b540fce9ed438395eaa7", "03D48C7210DDBCC4FB2E5E7A0AA16A0DB89540820B", "0306AB52062201D995B8B8591F3F086A3A2E214D845E"},
			q1u:  "03025BBA38D0C7B5436B68DF728F093E7A1D6C437E6D",
			q1v:  "030290a1f5c08dad5f2945e335620c7a98fac46666a1",
			want: "00E0D2C3CCD5C106A89C4F6CC26A5F7EC9DF78A7BE",
		},
		{
			c: koblitz.Sect283k1(),
			u: party{"00F2561ADB39EF49C1D62EF5186C6E0C158A5A45BFCE38660931ACC3694592D5ACDE9006",
				"0013D36DE4B1EA8E22739C381370823F404BFF8862B521FECA9871FB3691846D361304B4",
				"0305F3394E15680660EECAA36788D9B6F312B971CE2C9617570BF7DFCD21C972017762C332"},
			v: party{"0151CD0DBCB80474BF7AC9FEEBE39C7A32A63518938FCA9754AAE132BC9C73BE94A7E1BE",
				"03D48C7210DDBCC4FB2E5E7A0AA16A0DB89540820B8DC091AB521EA824AFE117CADE995B",
				"03009A5131CF5B92A016378C0F7F284ECD47F94010F875D43BF1E9A65474ADBFC63696A930"},
			q1u:  "03030E56F7ADE866E76372764BA20A9FF1FE4CAE522F94839E70F2ADFC1CA3E97F4DDCAF2E",
			q1v:  "0202F4FA2A3040433C6820299D182A1042E41404E337C57F47716B42DFAF970F1580A04C9B",
			want: "04F7724A9A77B21D2747CCEF68A457E45246C4BE9F66FD9425227BCB2CC5180EA9CCCB9A",
		},
	}
	for _, tc := range cases {
		c := tc.c
		zu, err := SharedSecret(c, scalar(t, c, tc.u.d1), scalar(t, c, tc.u.d2), point(t, c, tc.u.q2), point(t, c, tc.q1v), point(t, c, tc.v.q2))
		if err != nil {
			t.Fatal(err)
		}
		zv, err := SharedSecret(c, scalar(t, c, tc.v.d1), scalar(t, c, tc.v.d2), point(t, c, tc.v.q2), point(t, c, tc.q1u), point(t, c, tc.u.q2))
		if err != nil {
			t.Fatal(err)
		}
		want := unhex(t, tc.want)
		if !bytes.Equal(zu, want) || !bytes.Equal(zv, want) {
			t.Errorf("%s: Z(U) = %X, Z(V) = %X, want %X", c.Name(), zu, zv, want)
		}
	}
}

// Random key pairs agree; a wrong static key does not.
//
// Covers: SIG-IPE-2752
func TestSharedSecretAgreement(t *testing.T) {
	for _, c := range []*koblitz.Curve{koblitz.Sect163k1(), koblitz.Sect283k1()} {
		key := func() (*koblitz.Scalar, *koblitz.Point) {
			d, err := c.RandomScalar(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return d, c.ScalarBaseMult(d)
		}
		d1u, q1u := key()
		d2u, q2u := key()
		d1v, q1v := key()
		d2v, q2v := key()
		zu, err1 := SharedSecret(c, d1u, d2u, q2u, q1v, q2v)
		zv, err2 := SharedSecret(c, d1v, d2v, q2v, q1u, q2u)
		if err1 != nil || err2 != nil || !bytes.Equal(zu, zv) || len(zu) != c.FieldSize() {
			t.Fatalf("%s: disagreement %v %v", c.Name(), err1, err2)
		}
		_, other := key()
		zx, _ := SharedSecret(c, d1v, d2v, q2v, other, q2u)
		if bytes.Equal(zx, zu) {
			t.Fatalf("%s: wrong static key gave the same secret", c.Name())
		}
		// An order-2 ephemeral key gives h*T = O: invalid.
		t2, err := c.DecodePoint(append([]byte{2}, make([]byte, c.FieldSize())...))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := SharedSecret(c, d1u, d2u, q2u, t2, t2); err != ErrInvalid {
			t.Fatalf("%s: small-order peer keys: %v", c.Name(), err)
		}
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	for _, c := range []*koblitz.Curve{koblitz.Sect163k1(), koblitz.Sect283k1()} {
		d1, _ := c.RandomScalar(rand.Reader)
		d2, _ := c.RandomScalar(rand.Reader)
		q2 := c.ScalarBaseMult(d2)
		q1v := c.ScalarBaseMult(d1)
		b.Run(c.Name(), func(b *testing.B) {
			for b.Loop() {
				_, _ = SharedSecret(c, d1, d2, q2, q1v, q2)
			}
		})
	}
}
