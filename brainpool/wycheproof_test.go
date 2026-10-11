// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The Wycheproof files under testdata/wycheproof are gzipped copies of
// C2SP/wycheproof testvectors_v1 (commit in PROVENANCE.md).

func readWycheproof(t *testing.T, name string, v any) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "wycheproof", name+".json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(zr).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func wHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type wycheproofECDSA struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		PublicKey struct {
			Curve        string `json:"curve"`
			Uncompressed string `json:"uncompressed"`
		} `json:"publicKey"`
		PublicKeyDer string `json:"publicKeyDer"`
		SHA          string `json:"sha"`
		Tests        []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
			Msg     string   `json:"msg"`
			Sig     string   `json:"sig"`
			Result  string   `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func wycheproofHash(t *testing.T, name string) hash.Hash {
	switch name {
	case "SHA-256":
		return sha256.New()
	case "SHA-384":
		return sha512.New384()
	case "SHA-512":
		return sha512.New()
	case "SHA3-256":
		return sha3.New256()
	case "SHA3-384":
		return sha3.New384()
	case "SHA3-512":
		return sha3.New512()
	}
	t.Fatalf("hash %q", name)
	return nil
}

// TestWycheproofECDSA verifies every signature of Wycheproof's brainpool
// r1 ECDSA files, in DER (Verify, VerifyASN1) and IEEE P1363 (VerifyP1363)
// form, with SHA-2 and SHA-3. Valid signatures must verify, invalid ones
// must not; the files have no "acceptable" results. The group's public key
// is parsed both from its SubjectPublicKeyInfo and from the raw point.
//
// Covers: SIG-SEC-677
func TestWycheproofECDSA(t *testing.T) {
	for _, f := range []struct {
		file  string
		p1363 bool
	}{
		{"ecdsa_brainpoolP256r1_sha256_test", false},
		{"ecdsa_brainpoolP384r1_sha384_test", false},
		{"ecdsa_brainpoolP512r1_sha512_test", false},
		{"ecdsa_brainpoolP256r1_sha3_256_test", false},
		{"ecdsa_brainpoolP384r1_sha3_384_test", false},
		{"ecdsa_brainpoolP512r1_sha3_512_test", false},
		{"ecdsa_brainpoolP256r1_sha256_p1363_test", true},
		{"ecdsa_brainpoolP384r1_sha384_p1363_test", true},
		{"ecdsa_brainpoolP512r1_sha512_p1363_test", true},
	} {
		t.Run(f.file, func(t *testing.T) {
			var w wycheproofECDSA
			readWycheproof(t, f.file, &w)
			ran := 0
			for _, g := range w.TestGroups {
				pub, err := ParsePKIXPublicKey(wHex(t, g.PublicKeyDer))
				if err != nil {
					t.Fatalf("public key: %v", err)
				}
				if pub.Curve.Params().Name != g.PublicKey.Curve {
					t.Fatalf("curve %s, want %s", pub.Curve.Params().Name, g.PublicKey.Curve)
				}
				raw, err := ParseUncompressedPublicKey(pub.Curve, wHex(t, g.PublicKey.Uncompressed))
				if err != nil || !raw.Equal(pub) {
					t.Fatalf("raw public key: %v", err)
				}
				for _, tc := range g.Tests {
					ran++
					h := wycheproofHash(t, g.SHA)
					h.Write(wHex(t, tc.Msg))
					digest := h.Sum(nil)
					sig := wHex(t, tc.Sig)
					var ok bool
					if f.p1363 {
						ok = VerifyP1363(pub, digest, sig)
					} else {
						ok = Verify(pub, digest, sig)
						if ok != VerifyASN1(pub, digest, sig) {
							t.Fatalf("tcId %d: Verify and VerifyASN1 differ", tc.TcID)
						}
					}
					switch tc.Result {
					case "valid":
						if !ok {
							t.Errorf("tcId %d (%s %v): valid signature rejected", tc.TcID, tc.Comment, tc.Flags)
						}
					case "invalid":
						if ok {
							t.Errorf("tcId %d (%s %v): invalid signature accepted", tc.TcID, tc.Comment, tc.Flags)
						}
					default:
						t.Fatalf("tcId %d: result %q not handled", tc.TcID, tc.Result)
					}
				}
			}
			if ran != w.NumberOfTests {
				t.Fatalf("ran %d of %d", ran, w.NumberOfTests)
			}
		})
	}
}

type wycheproofECDH struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		Curve    string `json:"curve"`
		Encoding string `json:"encoding"`
		Tests    []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
			Public  string   `json:"public"`
			Private string   `json:"private"`
			Shared  string   `json:"shared"`
			Result  string   `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// TestWycheproofECDH runs Wycheproof's brainpool r1 ECDH files: the peer's
// key is a DER SubjectPublicKeyInfo (ParsePKIXPublicKey), the private key
// an integer. Valid cases must give the expected secret; invalid ones (off
// the curve, on another curve, malformed) must fail; "acceptable" ones
// (lax ASN.1, explicit parameters) may fail, but if they succeed the
// secret must be right. Compressed points are acceptable in Wycheproof's
// view and must work here. The secret is computed with both
// the crypto/ecdh-style API and the ECDH function.
//
// Covers: SIG-SEC-677
func TestWycheproofECDH(t *testing.T) {
	for _, file := range []string{"ecdh_brainpoolP256r1_test", "ecdh_brainpoolP384r1_test", "ecdh_brainpoolP512r1_test"} {
		t.Run(file, func(t *testing.T) {
			var w wycheproofECDH
			readWycheproof(t, file, &w)
			ran, accepted, refused := 0, 0, 0
			for _, g := range w.TestGroups {
				if g.Encoding != "asn" {
					t.Fatalf("encoding %q", g.Encoding)
				}
				for _, tc := range g.Tests {
					ran++
					shared, err := wycheproofShared(t, g.Curve, wHex(t, tc.Public), wHex(t, tc.Private))
					switch {
					case tc.Result == "valid" && err != nil:
						t.Errorf("tcId %d (%s %v): %v", tc.TcID, tc.Comment, tc.Flags, err)
					case slices.Contains(tc.Flags, "CompressedPublic") && err != nil:
						t.Errorf("tcId %d (%s %v): compressed key refused: %v", tc.TcID, tc.Comment, tc.Flags, err)
					case tc.Result == "invalid" && err == nil:
						t.Errorf("tcId %d (%s %v): invalid case accepted", tc.TcID, tc.Comment, tc.Flags)
					case err == nil && !bytes.Equal(shared, wHex(t, tc.Shared)):
						t.Errorf("tcId %d (%s %v): secret %x, want %s", tc.TcID, tc.Comment, tc.Flags, shared, tc.Shared)
					case tc.Result == "acceptable" && err == nil:
						accepted++
					case tc.Result == "acceptable":
						refused++
					}
				}
			}
			if ran != w.NumberOfTests {
				t.Fatalf("ran %d of %d", ran, w.NumberOfTests)
			}
			t.Logf("%d cases; of the acceptable ones %d accepted, %d refused", ran, accepted, refused)
		})
	}
}

func wycheproofShared(t *testing.T, curveName string, spki, priv []byte) ([]byte, error) {
	pub, err := ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	if pub.Curve.Params().Name != curveName {
		return nil, errors.New("key on another curve")
	}
	e, _ := ECDHCurveFor(pub.Curve)
	k, err := NewPrivateKey(pub.Curve, priv)
	if err != nil {
		return nil, err
	}
	point, err := PublicKeyBytes(pub)
	if err != nil {
		return nil, err
	}
	remote, err := e.NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	z, err := k.ECDH().ECDH(remote)
	if err != nil {
		return nil, err
	}
	z2, err := ECDH(pub.Curve, k.Bytes(), remote.Bytes())
	if err != nil || !bytes.Equal(z, z2) {
		t.Fatalf("ECDH function and ECDH method differ: %v", err)
	}
	return z, nil
}
