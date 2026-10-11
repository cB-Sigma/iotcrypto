// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The published example exchanges: RFC 5802 section 5 (SCRAM-SHA-1) and
// RFC 7677 section 3 (SCRAM-SHA-256), user "user", password "pencil".
var vectors = []struct {
	mech, cnonce, snonce, salt string
	clientFirst, serverFirst   string
	clientFinal, serverFinal   string
}{
	{
		mech:        SCRAMSHA1,
		cnonce:      "fyko+d2lbbFgONRv9qkxdawL",
		snonce:      "3rfcNHYJY1ZVvWVs7j",
		salt:        "QSXCR+Q6sek8bf92",
		clientFirst: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
		serverFirst: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
		clientFinal: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
		serverFinal: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
	},
	{
		mech:        SCRAMSHA256,
		cnonce:      "rOprNGfwEbeRWgbNEkqO",
		snonce:      "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
		salt:        "W22ZaJ0SNY7soEsUEjb6gQ==",
		clientFirst: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		clientFinal: "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
		serverFinal: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
	},
}

// fixRandom makes the next nonce and salt the given ones.
func fixRandom(t *testing.T, n, salt string) {
	t.Helper()
	oldN, oldS := newNonce, newSalt
	t.Cleanup(func() { newNonce, newSalt = oldN, oldS })
	s, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		t.Fatal(err)
	}
	newNonce = func() string { return n }
	newSalt = func() []byte { return append([]byte(nil), s...) }
}

func pencil(u string) (string, bool) { return "pencil", u == "user" }

// The client's messages are byte for byte the published ones, and it
// accepts the published verifier.
//
// Covers: SIG-IPE-3627
func TestScramClientVectors(t *testing.T) {
	for _, v := range vectors {
		fixRandom(t, v.cnonce, v.salt)
		var sent []string
		err := Client(v.mech, "user", "pencil", func(msg []byte, last bool) ([]byte, error) {
			sent = append(sent, string(msg))
			if !last {
				return []byte(v.serverFirst), nil
			}
			return []byte(v.serverFinal), nil
		})
		if err != nil {
			t.Fatalf("%s: %v", v.mech, err)
		}
		if len(sent) != 2 || sent[0] != v.clientFirst || sent[1] != v.clientFinal {
			t.Errorf("%s: sent %q", v.mech, sent)
		}
	}
}

// The server's messages are byte for byte the published ones.
//
// Covers: SIG-IPE-3627
func TestScramServerVectors(t *testing.T) {
	for _, v := range vectors {
		fixRandom(t, v.snonce, v.salt)
		s, err := NewScramServer(v.mech, pencil)
		if err != nil {
			t.Fatal(err)
		}
		sf, err := s.First([]byte(v.clientFirst))
		if err != nil || string(sf) != v.serverFirst {
			t.Fatalf("%s first: %q, %v", v.mech, sf, err)
		}
		u, fin, err := s.Final([]byte(v.clientFinal))
		if err != nil || u != "user" || string(fin) != v.serverFinal {
			t.Errorf("%s final: %q %q, %v", v.mech, u, fin, err)
		}
	}
}

func condition(err error) string {
	var e Error
	if errors.As(err, &e) {
		return string(e)
	}
	if err == nil {
		return "ok"
	}
	return "other: " + err.Error()
}

// The server's refusals and the RFC 6120 condition each gets.
//
// Covers: SIG-IPE-3627
func TestScramServerRefusals(t *testing.T) {
	v := vectors[0]
	first := func(cf string) (*ScramServer, error) {
		fixRandom(t, v.snonce, v.salt)
		s, _ := NewScramServer(v.mech, func(u string) (string, bool) {
			pw, ok := map[string]string{"user": "pencil", "a,b=c": "pencil", "blank": ""}[u]
			return pw, ok
		})
		_, err := s.First([]byte(cf))
		return s, err
	}
	for _, c := range []struct{ name, cf, want string }{
		{"no gs2 header", "n=user,r=x", "malformed-request"},
		{"unknown gs2 flag", "x,,n=user,r=x", "malformed-request"},
		{"channel binding asked for", "p=tls-unique,,n=user,r=x", "invalid-mechanism"},
		{"mandatory extension", "n,,m=ext,n=user,r=x", "malformed-request"},
		{"empty user", "n,,n=,r=x", "malformed-request"},
		{"no user", "n,,r=x", "malformed-request"},
		{"empty nonce", "n,,n=user,r=", "malformed-request"},
		{"no nonce", "n,,n=user", "malformed-request"},
		{"bad saslname escape", "n,,n=us=41er,r=x", "malformed-request"},
		{"other authzid", "n,a=admin,n=user,r=x", "invalid-authzid"},
		{"same authzid", "n,a=user,n=user,r=x", "ok"},
		{"escaped authzid", "n,a=a=2Cb=3Dc,n=a=2Cb=3Dc,r=x", "ok"},
		{"client supports binding (y)", "y,,n=user,r=x", "ok"},
		{"unknown user still challenged", "n,,n=nobody,r=x", "ok"},
	} {
		if _, err := first(c.cf); condition(err) != c.want {
			t.Errorf("first %s: %v, want %s", c.name, err, c.want)
		}
	}

	good := v.clientFinal
	for _, c := range []struct{ name, cf, fin, want string }{
		{"published", v.clientFirst, good, "ok"},
		{"bad proof", v.clientFirst, strings.Replace(good, "p=v0X8", "p=w0X8", 1), "not-authorized"},
		{"nonce mismatch", v.clientFirst, strings.Replace(good, "VvWVs7j,", "VvWVs7k,", 1), "not-authorized"},
		{"channel binding mismatch", v.clientFirst, strings.Replace(good, "c=biws", "c=eSws", 1), "not-authorized"},
		{"no proof", v.clientFirst, good[:strings.LastIndex(good, ",p=")], "malformed-request"},
		{"proof not base64", v.clientFirst, good[:strings.LastIndex(good, ",p=")] + ",p=!!", "malformed-request"},
		{"proof too short", v.clientFirst, good[:strings.LastIndex(good, ",p=")] + ",p=AAAA", "malformed-request"},
		{"unknown user, any proof", "n,,n=nobody,r=fyko+d2lbbFgONRv9qkxdawL", good, "not-authorized"},
		{"user without password", "n,,n=blank,r=fyko+d2lbbFgONRv9qkxdawL", good, "not-authorized"},
	} {
		s, err := first(c.cf)
		if err != nil {
			t.Fatalf("final %s: first: %v", c.name, err)
		}
		_, _, err = s.Final([]byte(c.fin))
		if condition(err) != c.want {
			t.Errorf("final %s: %v, want %s", c.name, err, c.want)
		}
	}

	s, _ := NewScramServer(SCRAMSHA256, pencil)
	if _, _, err := s.Final([]byte(good)); condition(err) != "malformed-request" {
		t.Errorf("final before first: %v", err)
	}
	if _, err := NewScramServer("SCRAM-SHA-512", pencil); condition(err) != "invalid-mechanism" {
		t.Errorf("SHA-512: %v", err)
	}
}

// An escaped user name reaches the password lookup decoded.
//
// Covers: SIG-IPE-3627
func TestScramServerEscapedUser(t *testing.T) {
	var asked string
	s, _ := NewScramServer(SCRAMSHA256, func(u string) (string, bool) { asked = u; return "pencil", true })
	err := Client(SCRAMSHA256, "a,b=c", "pencil", func(msg []byte, last bool) ([]byte, error) {
		if !last {
			if !strings.HasPrefix(string(msg), "n,,n=a=2Cb=3Dc,r=") {
				t.Errorf("client first %q", msg)
			}
			return s.First(msg)
		}
		u, fin, err := s.Final(msg)
		if u != "a,b=c" {
			t.Errorf("user %q", u)
		}
		return fin, err
	})
	if err != nil || asked != "a,b=c" {
		t.Errorf("%q: %v", asked, err)
	}
}

// The client's refusals of a bad server, with our error texts.
//
// Covers: SIG-IPE-3627
func TestScramClientRefusals(t *testing.T) {
	v := vectors[0]
	sf := v.serverFirst
	for _, c := range []struct{ name, first, final, want string }{
		{"nonce not extended", "r=other,s=QSXCR+Q6sek8bf92,i=4096", "", "SCRAM: the server's nonce does not extend ours"},
		{"nonce not lengthened", "r=" + v.cnonce + ",s=QSXCR+Q6sek8bf92,i=4096", "", "SCRAM: the server's nonce does not extend ours"},
		{"no nonce", "s=QSXCR+Q6sek8bf92,i=4096", "", "SCRAM: the server's nonce does not extend ours"},
		{"bad salt", strings.Replace(sf, "s=QSXCR", "s=!SXCR", 1), "", "SCRAM: bad salt"},
		{"zero iterations", strings.Replace(sf, "i=4096", "i=0", 1), "", `SCRAM: iteration count "0"`},
		{"too many iterations", strings.Replace(sf, "i=4096", "i=1000001", 1), "", `SCRAM: iteration count "1000001"`},
		{"iterations not a number", strings.Replace(sf, "i=4096", "i=x", 1), "", `SCRAM: iteration count "x"`},
		{"no iterations", strings.TrimSuffix(sf, ",i=4096"), "", `SCRAM: iteration count ""`},
		{"wrong verifier", sf, "v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "SCRAM: the server's signature does not verify"},
		{"server error", sf, "e=invalid-proof", "SCRAM: the server's signature does not verify"},
		{"empty final", sf, "", "SCRAM: the server's signature does not verify"},
		{"published", sf, v.serverFinal, "ok"},
	} {
		fixRandom(t, v.cnonce, v.salt)
		err := Client(v.mech, "user", "pencil", func(msg []byte, last bool) ([]byte, error) {
			if !last {
				return []byte(c.first), nil
			}
			return []byte(c.final), nil
		})
		got := "ok"
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// A low iteration count is accepted (the server chooses it).
	fixRandom(t, "abc", v.salt)
	srvFirst := "r=abcdef,s=QSXCR+Q6sek8bf92,i=1"
	err := Client(SCRAMSHA256, "user", "pencil", func(msg []byte, last bool) ([]byte, error) {
		if !last {
			return []byte(srvFirst), nil
		}
		return nil, errors.New("stop")
	})
	if err == nil || err.Error() != "stop" {
		t.Errorf("i=1: %v", err)
	}

	sentinel := errors.New("link down")
	if err := Client(SCRAMSHA256, "user", "pencil", func([]byte, bool) ([]byte, error) { return nil, sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("exchange error: %v", err)
	}
	if err := Client("PLAIN", "user", "pencil", nil); condition(err) != "invalid-mechanism" {
		t.Errorf("PLAIN: %v", err)
	}
}

// Passwords are used as given: no SASLprep on either side, so a password
// that SASLprep would change still works between our client and server,
// and one SASLprep would refuse is not refused.
//
// Covers: SIG-IPE-3627
func TestScramNoSASLprep(t *testing.T) {
	for _, pw := range []string{"I­X", "Ⅸ", "tab\there"} {
		s, _ := NewScramServer(SCRAMSHA256, func(string) (string, bool) { return pw, true })
		err := Client(SCRAMSHA256, "user", pw, func(msg []byte, last bool) ([]byte, error) {
			if !last {
				return s.First(msg)
			}
			_, fin, err := s.Final(msg)
			return fin, err
		})
		if err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
	// And the prepared form of a password is a different password.
	s, _ := NewScramServer(SCRAMSHA256, func(string) (string, bool) { return "I­X", true })
	err := Client(SCRAMSHA256, "user", "IX", func(msg []byte, last bool) ([]byte, error) {
		if !last {
			return s.First(msg)
		}
		_, fin, err := s.Final(msg)
		return fin, err
	})
	if condition(err) != "not-authorized" {
		t.Errorf("prepared form: %v", err)
	}
}
