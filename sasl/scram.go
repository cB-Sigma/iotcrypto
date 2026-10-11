// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package sasl is SCRAM-SHA-1 (RFC 5802) and SCRAM-SHA-256 (RFC 7677)
// without channel binding (the -PLUS variants are not offered), for
// protocols that carry SASL exchanges, such as XMPP and MQTT-SN 2.0 AUTH.
// The SCRAM computation and message handling are github.com/xdg-go/scram;
// this package adds its own API, error conditions and texts, wire form
// (nonce and salt sizes) and the checks around it. Passwords are compared as given: SASLprep (RFC 4013) is not
// applied.
//
// The server side is a two-step state (ScramServer) so that callers whose
// messages arrive asynchronously, one packet at a time, can drive it.
package sasl

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/xdg-go/scram"
)

// Mechanism names.
const (
	SCRAMSHA1   = "SCRAM-SHA-1"
	SCRAMSHA256 = "SCRAM-SHA-256"
)

// Iterations is the PBKDF2 iteration count the server asks for (RFC 7677
// section 4 recommends at least 4096).
const Iterations = 4096

// maxIterations is the most the client computes, so that a server cannot
// make it spin.
const maxIterations = 1_000_000

// Error is a SASL failure condition, named as in RFC 6120 6.5.
type Error string

func (e Error) Error() string { return "SASL: " + string(e) }

// Hash is the hash of a SCRAM mechanism, nil for any other name.
func Hash(mech string) func() hash.Hash {
	switch mech {
	case SCRAMSHA1:
		return sha1.New
	case SCRAMSHA256:
		return sha256.New
	}
	return nil
}

func attrs(s string) map[byte]string {
	out := map[byte]string{}
	for _, p := range strings.Split(s, ",") {
		if len(p) >= 2 && p[1] == '=' {
			if _, dup := out[p[0]]; !dup {
				out[p[0]] = p[2:]
			}
		}
	}
	return out
}

// name decodes a saslname (',' as =2C, '=' as =3D).
func name(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == ',':
			return "", false
		case s[i] == '=':
			switch {
			case strings.HasPrefix(s[i:], "=2C"):
				b.WriteByte(',')
			case strings.HasPrefix(s[i:], "=3D"):
				b.WriteByte('=')
			default:
				return "", false
			}
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// Escape encodes a user name as a saslname.
func Escape(s string) string {
	return strings.NewReplacer("=", "=3D", ",", "=2C").Replace(s)
}

func nonce() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

// newNonce and newSalt are the random sources; tests replace them to
// reproduce published exchanges.
var (
	newNonce = nonce
	newSalt  = func() []byte {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return b
	}
)

var errBadName = errors.New("bad saslname")

// ScramServer is the server side of one SCRAM exchange.
type ScramServer struct {
	gen      scram.HashGeneratorFcn
	password func(string) (string, bool)
	conv     *scram.ServerConversation
	user     string
	known    bool
	full     string // the combined nonce
	keyErr   error
}

// NewScramServer starts an exchange for mech; password looks users up.
func NewScramServer(mech string, password func(string) (string, bool)) (*ScramServer, error) {
	h := Hash(mech)
	if h == nil {
		return nil, Error("invalid-mechanism")
	}
	return &ScramServer{gen: scram.HashGeneratorFcn(h), password: password}, nil
}

// lookup derives the stored credentials of a user. An unknown user still
// gets a challenge (with a random salt and password), so the answer does
// not tell which users exist.
func (s *ScramServer) lookup(raw string) (scram.StoredCredentials, error) {
	user, ok := name(raw)
	if !ok || user == "" {
		return scram.StoredCredentials{}, errBadName
	}
	pw, known := s.password(user)
	if !known || pw == "" {
		pw, known = nonce(), false
	}
	s.user, s.known = user, known
	c, _ := s.gen.NewClientUnprepped(user, pw, "")
	cred, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(newSalt()), Iters: Iterations})
	s.keyErr = err
	return cred, err
}

// First reads the client's first message and returns the server's first
// message (the challenge).
func (s *ScramServer) First(first []byte) ([]byte, error) {
	cf := string(first)
	snonce := newNonce()
	srv, _ := s.gen.NewServer(s.lookup)
	conv := srv.WithNonceGenerator(func() string { return snonce }).NewConversation()
	s.conv, s.keyErr = nil, nil
	sf, err := conv.Step(cf)
	switch {
	case err == nil:
	case s.keyErr != nil:
		return nil, Error("temporary-auth-failure")
	case strings.HasPrefix(cf, "p="):
		return nil, Error("invalid-mechanism") // -PLUS is not offered
	default:
		return nil, Error("malformed-request")
	}
	s.full = attrs(sf)['r']
	if s.full == snonce { // the client's nonce is empty
		return nil, Error("malformed-request")
	}
	if gs2 := strings.SplitN(cf, ",", 3); strings.HasPrefix(gs2[1], "a=") {
		if az, ok := name(gs2[1][2:]); !ok || az != s.user {
			return nil, Error("invalid-authzid")
		}
	}
	s.conv = conv
	return []byte(sf), nil
}

// Final checks the client's final message and returns the user and the
// server's final message (the verifier).
func (s *ScramServer) Final(resp []byte) (user string, final []byte, err error) {
	conv := s.conv
	if conv == nil {
		return "", nil, Error("malformed-request")
	}
	s.conv = nil
	fin := string(resp)
	out, err := conv.Step(fin)
	if err != nil {
		switch out {
		case scram.ErrChannelBindingsDontMatch, scram.ErrInvalidProof:
			return "", nil, Error("not-authorized")
		case scram.ErrOtherError:
			// A nonce that is not ours, or a proof of the wrong length.
			if strings.Split(fin, ",")[1] != "r="+s.full {
				return "", nil, Error("not-authorized")
			}
		}
		return "", nil, Error("malformed-request")
	}
	if !conv.Valid() || !s.known {
		return "", nil, Error("not-authorized")
	}
	return s.user, []byte(out), nil
}

// Server runs the server side over a synchronous exchange: first is the
// client's first message; exchange sends a challenge and returns the
// client's response.
func Server(mech string, first []byte, password func(string) (string, bool),
	exchange func(challenge []byte) ([]byte, error)) (user string, final []byte, err error) {
	s, err := NewScramServer(mech, password)
	if err != nil {
		return "", nil, err
	}
	ch, err := s.First(first)
	if err != nil {
		return "", nil, err
	}
	resp, err := exchange(ch)
	if err != nil {
		return "", nil, err
	}
	return s.Final(resp)
}

// checkServerFirst applies our checks to the server's first message before
// anything is computed from it.
func checkServerFirst(sf, cnonce string) error {
	a := attrs(sf)
	if !strings.HasPrefix(a['r'], cnonce) || len(a['r']) == len(cnonce) {
		return errors.New("SCRAM: the server's nonce does not extend ours")
	}
	if _, err := base64.StdEncoding.DecodeString(a['s']); err != nil {
		return errors.New("SCRAM: bad salt")
	}
	if iter, err := strconv.Atoi(a['i']); err != nil || iter < 1 || iter > maxIterations {
		return fmt.Errorf("SCRAM: iteration count %q", a['i'])
	}
	return nil
}

// Client runs the client side over exchange, which sends a message and
// returns the server's next data: a challenge, or (last) the verifier.
func Client(mech, user, password string, exchange func(msg []byte, last bool) ([]byte, error)) error {
	h := Hash(mech)
	if h == nil {
		return Error("invalid-mechanism")
	}
	cnonce := newNonce()
	c, _ := scram.HashGeneratorFcn(h).NewClientUnprepped(user, password, "")
	conv := c.WithMinIterations(1).WithNonceGenerator(func() string { return cnonce }).NewConversation()
	cf, err := conv.Step("")
	if err != nil {
		return err
	}
	sfb, err := exchange([]byte(cf), false)
	if err != nil {
		return err
	}
	sf := string(sfb)
	if err := checkServerFirst(sf, cnonce); err != nil {
		return err
	}
	cfin, err := conv.Step(sf)
	if err != nil {
		return fmt.Errorf("SCRAM: %w", err)
	}
	ok, err := exchange([]byte(cfin), true)
	if err != nil {
		return err
	}
	if _, err := conv.Step(string(ok)); err != nil || !conv.Valid() {
		return errors.New("SCRAM: the server's signature does not verify")
	}
	return nil
}
