// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func allECDH() []*ECDHCurve { return []*ECDHCurve{ECDHP256r1(), ECDHP384r1(), ECDHP512r1()} }

// The RFC 7027 appendix A key agreements through the crypto/ecdh-style
// API.
//
// Covers: SIG-SEC-677
func TestECDHCurveRFC7027(t *testing.T) {
	for _, v := range rfc7027Vectors {
		e, ok := ECDHCurveFor(v.c)
		if !ok || e.Curve() != v.c || e.String() != v.c.Params().Name {
			t.Fatalf("%s: ECDHCurveFor", v.c.Params().Name)
		}
		a, err := e.NewPrivateKey(mustHex(t, v.dA))
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.NewPrivateKey(mustHex(t, v.dB))
		if err != nil {
			t.Fatal(err)
		}
		wantA := append([]byte{4}, append(mustHex(t, v.xA), mustHex(t, v.yA)...)...)
		if !bytes.Equal(a.PublicKey().Bytes(), wantA) {
			t.Errorf("%s: public key A %x", e, a.PublicKey().Bytes())
		}
		zA, err := a.ECDH(b.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		zB, err := b.ECDH(a.PublicKey())
		if err != nil || !bytes.Equal(zA, zB) || !bytes.Equal(zA, mustHex(t, v.xZ)) {
			t.Errorf("%s: shared %x / %x, %v", e, zA, zB, err)
		}
	}
}

func TestECDHCurveAPI(t *testing.T) {
	for _, e := range allECDH() {
		k, err := e.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := e.NewPrivateKey(k.Bytes())
		if err != nil || !k2.Equal(k) || !k2.PublicKey().Equal(k.PublicKey()) || k2.Curve() != e {
			t.Fatalf("%s: private key round trip: %v", e, err)
		}
		pub := k.PublicKey()
		comp := pub.CompressedBytes()
		if len(comp) != 1+e.c.size || (comp[0] != 2 && comp[0] != 3) {
			t.Fatalf("%s: compressed %x", e, comp)
		}
		fromComp, err := e.NewPublicKey(comp)
		if err != nil || !fromComp.Equal(pub) || !bytes.Equal(fromComp.Bytes(), pub.Bytes()) {
			t.Fatalf("%s: compressed round trip: %v", e, err)
		}
		other := comp[0] ^ 1 // the other root: the negated point
		neg, err := e.NewPublicKey(append([]byte{other}, comp[1:]...))
		if err != nil || neg.Equal(pub) || !bytes.Equal(neg.Bytes()[1:1+e.c.size], pub.Bytes()[1:1+e.c.size]) {
			t.Fatalf("%s: other parity: %v", e, err)
		}
		if pk, ok := k.Public().(*ECDHPublicKey); !ok || !pk.Equal(pub) {
			t.Fatalf("%s: Public", e)
		}
		// The ECDSA and ECDH views of a key are the same scalar and point.
		sk := k.ECDSA()
		if !sk.ECDH().Equal(k) || !sk.PublicKey().Equal(pub.ECDSA()) {
			t.Fatalf("%s: ECDSA bridge", e)
		}
		// Wrong inputs.
		if _, err := e.NewPrivateKey(k.Bytes()[1:]); err == nil {
			t.Errorf("%s: short private key accepted", e)
		}
		if _, err := e.NewPrivateKey(e.c.params.N.FillBytes(make([]byte, e.c.size))); err == nil {
			t.Errorf("%s: private key n accepted", e)
		}
		bad := bytes.Clone(comp)
		for i := 0; i < 256; i++ { // find an x with no point
			bad[len(bad)-1] = byte(i)
			if _, err := e.NewPublicKey(bad); err != nil {
				break
			}
			if i == 255 {
				t.Errorf("%s: every x decompressed", e)
			}
		}
		if _, err := e.NewPublicKey(append([]byte{5}, comp[1:]...)); err == nil {
			t.Errorf("%s: prefix 5 accepted", e)
		}
		for _, o := range allECDH() {
			if o == e {
				continue
			}
			ok, _ := o.GenerateKey(rand.Reader)
			if _, err := k.ECDH(ok.PublicKey()); err == nil {
				t.Errorf("%s: key on %s accepted", e, o)
			}
		}
	}
	if _, ok := ECDHCurveFor(elliptic.P256()); ok {
		t.Error("P-256 accepted")
	}
}

// Point compression agrees with the reference arithmetic for points of
// both parities, and ParsePKIXPublicKey takes a compressed point.
func TestCompressedPoints(t *testing.T) {
	for _, c := range allCurves() {
		for range 16 {
			k, _ := GenerateKey(c, rand.Reader)
			pub := k.PublicKey()
			comp, err := MarshalCompressed(pub)
			if err != nil {
				t.Fatal(err)
			}
			if want := byte(2 + pub.Y.Bit(0)); comp[0] != want {
				t.Fatalf("%s: prefix %d, y parity %d", c.Params().Name, comp[0], pub.Y.Bit(0))
			}
			back, err := ParsePublicKey(c, comp)
			if err != nil || !back.Equal(pub) {
				t.Fatalf("%s: decompress: %v", c.Params().Name, err)
			}
			unc, _ := PublicKeyBytes(pub)
			if !bytes.Equal(unc, elliptic.Marshal(c, pub.X, pub.Y)) {
				t.Fatal("PublicKeyBytes")
			}
			if back, err := ParsePublicKey(c, unc); err != nil || !back.Equal(pub) {
				t.Fatalf("uncompressed: %v", err)
			}
			if _, err := ParseUncompressedPublicKey(c, comp); err == nil {
				t.Fatal("ParseUncompressedPublicKey took a compressed point")
			}
		}
		// A compressed SubjectPublicKeyInfo.
		k, _ := GenerateKey(c, rand.Reader)
		spki, _ := MarshalPKIXPublicKey(k.PublicKey())
		comp, _ := MarshalCompressed(k.PublicKey())
		unc, _ := PublicKeyBytes(k.PublicKey())
		cspki := bytes.Replace(spki, unc, comp, 1)
		cspki[1] -= byte(len(unc) - len(comp)) // outer length (short form for P-256 and P-384)
		if c.Params().BitSize < 512 {
			cspki[len(cspki)-len(comp)-2] -= byte(len(unc) - len(comp)) // BIT STRING length
			pub, err := ParsePKIXPublicKey(cspki)
			if err != nil || !pub.Equal(k.PublicKey()) {
				t.Errorf("%s: compressed SPKI: %v", c.Params().Name, err)
			}
		}
	}
}

// Keys OpenSSL writes with compressed points (SEC 1 private key with an
// embedded compressed public key, and a compressed SubjectPublicKeyInfo)
// parse, and match each other.
//
// Covers: SIG-SEC-677
func TestOpenSSLCompressedKeys(t *testing.T) {
	ossl := opensslPath(t)
	dir := t.TempDir()
	for _, c := range allCurves() {
		name := c.Params().Name
		runOpenSSL(t, ossl, dir, "ecparam", "-name", name, "-genkey", "-noout", "-conv_form", "compressed", "-out", "k.pem")
		runOpenSSL(t, ossl, dir, "ec", "-in", "k.pem", "-pubout", "-conv_form", "compressed", "-out", "pub.pem")
		k, err := ParseECPrivateKey(readPEM(t, filepath.Join(dir, "k.pem"), "EC PRIVATE KEY"))
		if err != nil {
			t.Fatalf("%s: private key: %v", name, err)
		}
		spki := readPEM(t, filepath.Join(dir, "pub.pem"), "PUBLIC KEY")
		if len(spki) > 1+2*k.c.size+30 {
			t.Fatalf("%s: OpenSSL wrote an uncompressed key", name)
		}
		pub, err := ParsePKIXPublicKey(spki)
		if err != nil || !pub.Equal(k.PublicKey()) {
			t.Fatalf("%s: compressed public key: %v", name, err)
		}
	}
}

// The crypto/ecdsa-style functions: DER and P1363 signatures, raw keys.
//
// Covers: SIG-SEC-677
func TestECDSAStyleAPI(t *testing.T) {
	digest := sha256.Sum256([]byte("message"))
	for _, c := range allCurves() {
		name := c.Params().Name
		k, _ := GenerateKey(c, rand.Reader)
		pub := k.PublicKey()
		der, err := SignASN1(rand.Reader, k, digest[:])
		if err != nil || !VerifyASN1(pub, digest[:], der) || !ecdsa.VerifyASN1(pub, digest[:], der) {
			t.Fatalf("%s: SignASN1: %v", name, err)
		}
		raw, err := SignP1363(rand.Reader, k, digest[:])
		if err != nil || len(raw) != 2*k.c.size || !VerifyP1363(pub, digest[:], raw) {
			t.Fatalf("%s: SignP1363: %v", name, err)
		}
		bad := bytes.Clone(raw)
		bad[0] ^= 1
		if VerifyP1363(pub, digest[:], bad) || VerifyP1363(pub, digest[:], raw[1:]) || VerifyP1363(nil, digest[:], raw) {
			t.Fatalf("%s: bad P1363 signature accepted", name)
		}
		k2, err := ParseRawPrivateKey(c, k.Bytes())
		if err != nil || !k2.Equal(k) {
			t.Fatalf("%s: ParseRawPrivateKey: %v", name, err)
		}
		if _, err := ParseRawPrivateKey(c, k.Bytes()[1:]); err == nil {
			t.Errorf("%s: short raw key accepted", name)
		}
		if _, err := ParseRawPrivateKey(c, append([]byte{0}, k.Bytes()...)); err == nil {
			t.Errorf("%s: long raw key accepted", name)
		}
		other, _ := GenerateKey(c, rand.Reader)
		if k.Equal(other) || k.Equal(k.ECDSA()) {
			t.Errorf("%s: Equal", name)
		}
	}
	if _, err := ParseRawPrivateKey(elliptic.P256(), make([]byte, 32)); err == nil {
		t.Error("P-256 accepted")
	}
	if _, err := ParsePublicKey(elliptic.P256(), []byte{4}); err == nil {
		t.Error("P-256 accepted")
	}
}

// FuzzParsePublicKey feeds arbitrary encodings to the point and key
// parsers: no panics, and whatever parses re-encodes to an equal key.
func FuzzParsePublicKey(f *testing.F) {
	k, _ := GenerateKey(P256r1(), rand.Reader)
	unc, _ := PublicKeyBytes(k.PublicKey())
	comp, _ := MarshalCompressed(k.PublicKey())
	spki, _ := MarshalPKIXPublicKey(k.PublicKey())
	sec1, _ := MarshalECPrivateKey(k)
	p8, _ := MarshalPKCS8PrivateKey(k)
	for _, s := range [][]byte{unc, comp, spki, sec1, p8, {0}, {2}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, c := range allCurves() {
			if pub, err := ParsePublicKey(c, b); err == nil {
				again, err := ParsePublicKey(c, elliptic.Marshal(c, pub.X, pub.Y))
				if err != nil || !again.Equal(pub) {
					t.Fatalf("re-encoding: %v", err)
				}
			}
		}
		if pub, err := ParsePKIXPublicKey(b); err == nil {
			der, err := MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := ParsePKIXPublicKey(der); err != nil || !again.Equal(pub) {
				t.Fatalf("SPKI re-encoding: %v", err)
			}
		}
		if k, err := ParseECPrivateKey(b); err == nil {
			der, _ := MarshalECPrivateKey(k)
			if again, err := ParseECPrivateKey(der); err != nil || !again.Equal(k) {
				t.Fatalf("SEC 1 re-encoding: %v", err)
			}
		}
		_, _ = ParsePKCS8PrivateKey(b)
		_, _ = ParseCertificate(b)
		_, _ = ParseCertificateRequest(b)
		_ = IsBrainpoolCertificate(b)
	})
}

func BenchmarkECDH(b *testing.B) {
	for _, e := range allECDH() {
		b.Run(e.String(), func(b *testing.B) {
			k, _ := e.GenerateKey(rand.Reader)
			peer, _ := e.GenerateKey(rand.Reader)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := k.ECDH(peer.PublicKey()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	digest := sha256.Sum256([]byte("message"))
	for _, c := range allCurves() {
		b.Run(c.Params().Name, func(b *testing.B) {
			k, _ := GenerateKey(c, rand.Reader)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := k.Sign(rand.Reader, digest[:], nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	digest := sha256.Sum256([]byte("message"))
	for _, c := range allCurves() {
		b.Run(c.Params().Name, func(b *testing.B) {
			k, _ := GenerateKey(c, rand.Reader)
			sig, _ := k.Sign(rand.Reader, digest[:], nil)
			pub := k.PublicKey()
			b.ReportAllocs()
			for b.Loop() {
				if !Verify(pub, digest[:], sig) {
					b.Fatal("verify")
				}
			}
		})
	}
}
