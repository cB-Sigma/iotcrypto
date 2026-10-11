// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// referenceVector is one entry of testdata/reference.json. The sealed
// values were produced by an independent implementation (Python
// cryptography's AESCCM, OpenSSL underneath); the four SP 800-38C
// entries also equal the published Appendix C outputs. Long additional
// data is stored as a repeating unit (aad_unit) cut to aad_len bytes.
type referenceVector struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Nonce   string `json:"nonce"`
	AAD     string `json:"aad"`
	AADUnit string `json:"aad_unit"`
	AADLen  int    `json:"aad_len"`
	Plain   string `json:"plain"`
	Tag     int    `json:"tag"`
	Sealed  string `json:"sealed"`
}

// TestReferenceVectors runs NIST SP 800-38C Appendix C examples 1 to 4,
// every nonce length (7 to 13) with every tag length (4 to 16, even) for
// AES-128, -192 and -256, and additional data on both sides of the
// 0xFF00 boundary where the length encoding changes (RFC 3610 2.2). This
// covers the configurations of every caller: Matter (13/16), MQTT-SN v2
// (13/8, 13/16), wireless M-Bus and OMS (13/8, 13/16), TLS and DTLS
// (12/16, 12/8).
func TestReferenceVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []referenceVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 300 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		key, nonce, plain, want := unhex(t, v.Key), unhex(t, v.Nonce), unhex(t, v.Plain), unhex(t, v.Sealed)
		ad := unhex(t, v.AAD)
		if v.AADUnit != "" {
			ad = bytes.Repeat(unhex(t, v.AADUnit), v.AADLen/(len(v.AADUnit)/2)+1)[:v.AADLen]
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		a, err := New(blk, len(nonce), v.Tag)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got := a.Seal(nil, nonce, plain, ad); !bytes.Equal(got, want) {
			t.Fatalf("%s: sealed %s, want %s", v.Name, hex.EncodeToString(got), v.Sealed)
		}
		got, err := a.Open(nil, nonce, want, ad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: open %x, %v", v.Name, got, err)
		}
		bad := append([]byte(nil), want...)
		bad[len(bad)-1] ^= 0x80
		if _, err := a.Open(nil, nonce, bad, ad); err != ErrOpen {
			t.Fatalf("%s: a changed tag opened (%v)", v.Name, err)
		}
	}
}
