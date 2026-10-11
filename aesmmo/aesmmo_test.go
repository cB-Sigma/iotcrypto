// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package aesmmo

import (
	"bytes"
	"encoding/hex"
	mrand "math/rand/v2"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// Known answers: the install code example of BDB 3.1 6.11.1.2, and the
// key derivation hashes of SE 1.4a C.5.3.3.3 and C.6.3.3.3 (Z || counter).
//
// Covers: SIG-IPE-2753
func TestKnownAnswers(t *testing.T) {
	cases := []struct{ in, out string }{
		{"83FE D340 7A93 9723 A5C6 39B2 6916 D505 C3B5", "66B6900981E1EE3CA4206B6B861C02BB"},
		{"00E0D2C3CCD5C106A89C4F6CC26A5F7EC9DF78A7BE 00000001", "90F967B22C8357C10C1C04788DE9E848"},
		{"00E0D2C3CCD5C106A89C4F6CC26A5F7EC9DF78A7BE 00000002", "86D58AAA998E2FAEFAF9FEF49606543A"},
		{"04F7724A9A77B21D2747CCEF68A457E45246C4BE9F66FD9425227BCB2CC5180EA9CCCB9A 00000001", "ED380A00296600FB6B893025DE5FD137"},
		{"04F7724A9A77B21D2747CCEF68A457E45246C4BE9F66FD9425227BCB2CC5180EA9CCCB9A 00000002", "AA4689C70BE0FAF0C9BE534ABD9F4CDC"},
	}
	for _, tc := range cases {
		got := Sum(unhex(t, tc.in))
		if !bytes.Equal(got[:], unhex(t, tc.out)) {
			t.Errorf("MMO(%s) = %X, want %s", tc.in, got, tc.out)
		}
	}
}

// Writing in pieces gives the digest of the whole, across both padding
// forms (below and at or above 2^16 bits), and Sum leaves the state alone.
func TestIncremental(t *testing.T) {
	r := mrand.New(mrand.NewPCG(1, 1))
	for _, n := range []int{0, 1, 13, 14, 15, 16, 17, 31, 32, 33, 8191, 8192, 8193, 9000} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(r.Uint32())
		}
		want := Sum(msg)
		h := New()
		for p := msg; len(p) > 0; {
			k := min(len(p), 1+r.IntN(40))
			h.Write(p[:k])
			p = p[k:]
		}
		if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
			t.Fatalf("len %d: incremental digest differs", n)
		}
		if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
			t.Fatalf("len %d: Sum changed the state", n)
		}
	}
	// Messages whose lengths differ only across the 2^16-bit boundary do not
	// collide through padding.
	a, b := Sum(make([]byte, 8191)), Sum(make([]byte, 8192))
	if a == b {
		t.Fatal("padding collision at the length boundary")
	}
}
