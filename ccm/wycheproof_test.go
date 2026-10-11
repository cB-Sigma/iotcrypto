// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package ccm

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// wycheproofAEAD is the subset of Wycheproof's aead_test_schema_v1 that the
// CCM file uses.
type wycheproofAEAD struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		IVSize  int `json:"ivSize"`
		KeySize int `json:"keySize"`
		TagSize int `json:"tagSize"`
		Tests   []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
			Key     string   `json:"key"`
			IV      string   `json:"iv"`
			AAD     string   `json:"aad"`
			Msg     string   `json:"msg"`
			CT      string   `json:"ct"`
			Tag     string   `json:"tag"`
			Result  string   `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func readGzipJSON(t *testing.T, path string, v any) {
	t.Helper()
	f, err := os.Open(path)
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

// TestWycheproof runs every test of Wycheproof's aes_ccm_test.json (see
// PROVENANCE.md for the commit). Valid vectors must seal to the given
// ciphertext and tag and open again; invalid ones are either refused by New
// (nonce or tag sizes CCM does not define) or must fail to open. There are
// no "acceptable" results in the file; one would fail the test.
func TestWycheproof(t *testing.T) {
	var f wycheproofAEAD
	readGzipJSON(t, "testdata/wycheproof/aes_ccm_test.json.gz", &f)
	if f.Algorithm != "AES-CCM" {
		t.Fatalf("algorithm %q", f.Algorithm)
	}
	ran, refused := 0, 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			ran++
			key, iv := unhex(t, tc.Key), unhex(t, tc.IV)
			aad, msg := unhex(t, tc.AAD), unhex(t, tc.Msg)
			ct, tag := unhex(t, tc.CT), unhex(t, tc.Tag)
			blk, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("tcId %d: %v", tc.TcID, err)
			}
			a, err := New(blk, g.IVSize/8, g.TagSize/8)
			if err != nil || g.IVSize%8 != 0 {
				if tc.Result == "valid" {
					t.Fatalf("tcId %d (iv %d bits, tag %d bits): valid vector refused: %v", tc.TcID, g.IVSize, g.TagSize, err)
				}
				refused++
				continue
			}
			sealed := append(append([]byte(nil), ct...), tag...)
			switch tc.Result {
			case "valid":
				if got := a.Seal(nil, iv, msg, aad); !bytes.Equal(got, sealed) {
					t.Fatalf("tcId %d: sealed %x, want %x", tc.TcID, got, sealed)
				}
				got, err := a.Open(nil, iv, sealed, aad)
				if err != nil || !bytes.Equal(got, msg) {
					t.Fatalf("tcId %d: open %x, %v", tc.TcID, got, err)
				}
			case "invalid":
				if got, err := a.Open(nil, iv, sealed, aad); err == nil {
					t.Fatalf("tcId %d (%s %v): invalid vector opened to %s", tc.TcID, tc.Comment, tc.Flags, hex.EncodeToString(got))
				}
			default:
				t.Fatalf("tcId %d: result %q not handled", tc.TcID, tc.Result)
			}
		}
	}
	if ran != f.NumberOfTests {
		t.Fatalf("ran %d of %d tests", ran, f.NumberOfTests)
	}
	t.Logf("%d Wycheproof vectors, %d refused at New for undefined parameters", ran, refused)
}
