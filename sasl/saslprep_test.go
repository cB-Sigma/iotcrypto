// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import "testing"

// The examples of RFC 4013 section 3: mapping to nothing, unchanged ASCII,
// compatibility normalisation, and the prohibited and bidirectional
// failures.
//
// Covers: SIG-IPE-3627
func TestSASLprepRFC4013Examples(t *testing.T) {
	for _, c := range []struct {
		in, want string
		fails    bool
	}{
		{in: "I­X", want: "IX"},
		{in: "user", want: "user"},
		{in: "USER", want: "USER"},
		{in: "ª", want: "a"},
		{in: "Ⅸ", want: "IX"},
		{in: "\u0007", fails: true},
		{in: "ا1", fails: true},
	} {
		got, err := SASLprep(c.in)
		if c.fails {
			if err == nil {
				t.Errorf("%q: prepared to %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// The client sends the prepared user name.
//
// Covers: SIG-IPE-3627
func TestClientPreparesUserName(t *testing.T) {
	fixRandom(t, "abc", "QSXCR+Q6sek8bf92")
	var first string
	_ = Client(SCRAMSHA256, "Ⅸ", "pencil", func(msg []byte, last bool) ([]byte, error) {
		first = string(msg)
		return nil, Error("aborted")
	})
	if first != "n,,n=IX,r=abc" {
		t.Errorf("client first %q", first)
	}
	_ = ClientWith(SCRAMSHA256, "Ⅸ", "pencil", Options{NoSASLprep: true}, func(msg []byte, last bool) ([]byte, error) {
		first = string(msg)
		return nil, Error("aborted")
	})
	if first != "n,,n=Ⅸ,r=abc" {
		t.Errorf("unprepared client first %q", first)
	}
}
