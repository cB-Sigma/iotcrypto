// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package kmac

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// The six KMACXOF samples NIST publishes for SP 800-185 (KMACXOF_samples):
// the same key, data and customization strings as the KMAC samples, with
// right_encode(0) in place of the output length.
// Covers: SIG-IPE-2913
func TestNISTXOFSamples(t *testing.T) {
	key := unhex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	tag := []byte("My Tagged Application")
	for _, c := range []struct {
		name   string
		k256   bool
		x, s   []byte
		n      int
		expect string
	}{
		{"sample 1", false, seq(4), nil, 32, "CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35"},
		{"sample 2", false, seq(4), tag, 32, "31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C"},
		{"sample 3", false, seq(200), tag, 32, "47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F"},
		{"sample 4", true, seq(4), tag, 64, "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B"},
		{"sample 5", true, seq(200), nil, 64, "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B"},
		{"sample 6", true, seq(200), tag, 64, "D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D"},
	} {
		var got []byte
		if c.k256 {
			got = SumXOF256(key, c.x, c.n, c.s)
		} else {
			got = SumXOF128(key, c.x, c.n, c.s)
		}
		if !bytes.Equal(got, unhex(c.expect)) {
			t.Errorf("%s = %X", c.name, got)
		}
		// The XOF output does not depend on how much is read: a longer
		// read starts with the same bytes, and reads may be split.
		var x *XOF
		if c.k256 {
			x = NewXOF256(key, c.s)
		} else {
			x = NewXOF128(key, c.s)
		}
		x.Write(c.x[:1])
		x.Write(c.x[1:])
		long := make([]byte, 3*c.n)
		if _, err := io.ReadFull(x, long[:5]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(x, long[5:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(long[:c.n], got) {
			t.Errorf("%s: streamed output %X", c.name, long[:c.n])
		}
	}
}

// KMAC and KMACXOF of the same inputs differ (the length is encoded in
// one and not in the other), and Reset restarts with the same key.
func TestXOFDiffersAndResets(t *testing.T) {
	k := []byte("key")
	if bytes.Equal(SumXOF256(k, []byte("abc"), 32, nil), Sum256(k, []byte("abc"), 32, nil)) {
		t.Fatal("KMACXOF256 equals KMAC256")
	}
	x := NewXOF256(k, nil)
	x.Write([]byte("abc"))
	a := make([]byte, 32)
	x.Read(a)
	x.Reset()
	x.Write([]byte("abc"))
	b := make([]byte, 32)
	x.Read(b)
	if !bytes.Equal(a, b) || !bytes.Equal(a, SumXOF256(k, []byte("abc"), 32, nil)) {
		t.Fatal("reset or one-shot differs")
	}
	if x.BlockSize() != rate256 || NewXOF128(k, nil).BlockSize() != rate128 {
		t.Fatal("block sizes")
	}
}

func TestXOFWriteAfterReadPanics(t *testing.T) {
	x := NewXOF128([]byte("k"), nil)
	x.Read(make([]byte, 1))
	defer func() {
		if recover() == nil {
			t.Fatal("Write after Read did not panic")
		}
	}()
	x.Write([]byte("late"))
}

// wycheproofMAC is the subset of Wycheproof's mac_test_schema_v1 used by
// the KMAC files.
type wycheproofMAC struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		KeySize int `json:"keySize"`
		TagSize int `json:"tagSize"`
		Tests   []struct {
			TcID    int    `json:"tcId"`
			Comment string `json:"comment"`
			Key     string `json:"key"`
			Msg     string `json:"msg"`
			Tag     string `json:"tag"`
			Result  string `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// TestWycheproof runs Wycheproof's kmac128_no_customization_test.json and
// kmac256_no_customization_test.json (see PROVENANCE.md for the commit):
// valid tags must be reproduced, modified ones must not compare equal.
func TestWycheproof(t *testing.T) {
	for _, file := range []struct {
		path string
		alg  string
		sum  func(k, x []byte, size int, s []byte) []byte
	}{
		{"testdata/wycheproof/kmac128_no_customization_test.json.gz", "KMAC128", Sum128},
		{"testdata/wycheproof/kmac256_no_customization_test.json.gz", "KMAC256", Sum256},
	} {
		f, err := os.Open(file.path)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		var v wycheproofMAC
		err = json.NewDecoder(zr).Decode(&v)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if v.Algorithm != file.alg {
			t.Fatalf("%s: algorithm %q", file.path, v.Algorithm)
		}
		ran := 0
		for _, g := range v.TestGroups {
			for _, tc := range g.Tests {
				ran++
				key, _ := hex.DecodeString(tc.Key)
				msg, _ := hex.DecodeString(tc.Msg)
				tag, _ := hex.DecodeString(tc.Tag)
				got := file.sum(key, msg, g.TagSize/8, nil)
				ok := hmac.Equal(got, tag)
				switch tc.Result {
				case "valid":
					if !ok {
						t.Errorf("%s tcId %d (%s): %x, want %x", file.alg, tc.TcID, tc.Comment, got, tag)
					}
				case "invalid":
					if ok {
						t.Errorf("%s tcId %d (%s): modified tag accepted", file.alg, tc.TcID, tc.Comment)
					}
				default:
					t.Fatalf("%s tcId %d: result %q not handled", file.alg, tc.TcID, tc.Result)
				}
			}
		}
		if ran != v.NumberOfTests {
			t.Fatalf("%s: ran %d of %d", file.alg, ran, v.NumberOfTests)
		}
	}
}

func BenchmarkSum256(b *testing.B) {
	key := make([]byte, 32)
	msg := make([]byte, 1024)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		Sum256(key, msg, 64, nil)
	}
}
