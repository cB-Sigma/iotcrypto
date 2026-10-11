// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package sasl is SCRAM (RFC 5802): SCRAM-SHA-1, SCRAM-SHA-256 (RFC 7677)
// and SCRAM-SHA-512, each also as a -PLUS mechanism with TLS channel
// binding (tls-unique and tls-server-end-point of RFC 5929, tls-exporter of
// RFC 9266), for protocols that carry SASL exchanges, such as XMPP and
// MQTT-SN 2.0 AUTH. There is a client and a server; the server looks up
// either passwords or stored keys (salted, so the server need not keep
// passwords).
//
// The SCRAM computation and message handling are github.com/xdg-go/scram;
// this package adds its own API, error conditions and texts, wire form
// (nonce and salt sizes), the checks around it and the channel-binding
// helpers.
//
// # SASLprep
//
// User names and passwords are prepared with SASLprep (RFC 4013, through
// github.com/xdg-go/stringprep) before use, as RFC 5802 5.1 asks. A string
// SASLprep refuses (control characters, unassigned code points, bad
// bidirectional text) or empties is used as given rather than failing, so
// that every password that worked before still works between this package's
// client and server; PostgreSQL treats passwords the same way. The
// normalisation is that of golang.org/x/text, whose Unicode version is newer
// than the 3.2 that RFC 4013 names. Options.NoSASLprep turns preparation
// off (the v0.1 behaviour).
//
// # Mechanism names
//
// SCRAM-SHA-1 and SCRAM-SHA-256 and their -PLUS forms are registered by RFC
// 5802 and RFC 7677. SCRAM-SHA-512 and SCRAM-SHA-512-PLUS are defined by an
// IETF draft (draft-melnikov-scram-sha-512), not an RFC; Apache Kafka
// (SCRAM-SHA-512) and ejabberd, among others, offer them. Hash, Mechanisms and Choose know all six.
//
// # Channel binding
//
// A -PLUS mechanism ties the authentication to the TLS connection it runs
// over, so that a man in the middle who terminates TLS cannot relay it. Both
// sides compute the binding (TLSExporterBinding, TLSUniqueBinding or
// TLSServerEndPointBinding) and pass it in Options.ChannelBinding. A client
// that has a binding but uses a plain mechanism announces it ("y" flag), and
// a server that offered -PLUS refuses that as a downgrade.
//
// The server side is a two-step state (ScramServer) so that callers whose
// messages arrive asynchronously, one packet at a time, can drive it.
package sasl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/xdg-go/scram"
	"github.com/xdg-go/stringprep"
)

// Mechanism names.
const (
	SCRAMSHA1       = "SCRAM-SHA-1"
	SCRAMSHA256     = "SCRAM-SHA-256"
	SCRAMSHA512     = "SCRAM-SHA-512"
	SCRAMSHA1PLUS   = "SCRAM-SHA-1-PLUS"
	SCRAMSHA256PLUS = "SCRAM-SHA-256-PLUS"
	SCRAMSHA512PLUS = "SCRAM-SHA-512-PLUS"
)

// Iterations is the PBKDF2 iteration count the server asks for by default
// (RFC 7677 section 4 recommends at least 4096).
const Iterations = 4096

// iterations512 is the default for SCRAM-SHA-512, which its draft asks to
// be at least 10000.
const iterations512 = 10000

// maxIterations is the most the client computes by default, so that a
// server cannot make it spin.
const maxIterations = 1_000_000

// Error is a SASL failure condition, named as in RFC 6120 6.5.
type Error string

func (e Error) Error() string { return "SASL: " + string(e) }

// Hash is the hash of a SCRAM mechanism (plain or -PLUS), nil for any
// other name.
func Hash(mech string) func() hash.Hash {
	h, _ := parseMech(mech)
	return h
}

// IsPlus reports whether mech is a -PLUS (channel binding) mechanism.
func IsPlus(mech string) bool {
	h, plus := parseMech(mech)
	return h != nil && plus
}

func parseMech(mech string) (h func() hash.Hash, plus bool) {
	base, plus := strings.CutSuffix(mech, "-PLUS")
	switch base {
	case SCRAMSHA1:
		return sha1.New, plus
	case SCRAMSHA256:
		return sha256.New, plus
	case SCRAMSHA512:
		return sha512.New, plus
	}
	return nil, false
}

// preference is the order Mechanisms lists and Choose prefers.
var preference = []string{SCRAMSHA512PLUS, SCRAMSHA256PLUS, SCRAMSHA1PLUS, SCRAMSHA512, SCRAMSHA256, SCRAMSHA1}

// Mechanisms returns the mechanism names a server can offer, strongest
// first: the -PLUS ones only when withBinding (the connection is TLS and
// a ChannelBinding is available).
func Mechanisms(withBinding bool) []string {
	if withBinding {
		return append([]string(nil), preference...)
	}
	return append([]string(nil), preference[3:]...)
}

// Choose returns the strongest SCRAM mechanism among those a server
// offered, or "" if none: a -PLUS one only when withBinding. A client that
// has a binding and sees -PLUS offered must use it; Choose does.
func Choose(offered []string, withBinding bool) string {
	for _, m := range Mechanisms(withBinding) {
		for _, o := range offered {
			if strings.EqualFold(strings.TrimSpace(o), m) {
				return m
			}
		}
	}
	return ""
}

// SASLprep prepares a user name or password as RFC 4013 specifies (stored
// strings: unassigned code points are refused).
func SASLprep(s string) (string, error) { return stringprep.SASLprep.Prepare(s) }

// prepare applies SASLprep unless off, keeping s when SASLprep refuses it or
// empties it.
func prepare(s string, off bool) string {
	if off {
		return s
	}
	p, err := SASLprep(s)
	if err != nil || (p == "" && s != "") {
		return s
	}
	return p
}

// Options adjusts an exchange; the zero value gives the defaults.
type Options struct {
	// ChannelBinding is the binding of the TLS connection the exchange
	// runs over. A -PLUS mechanism needs it. Client: with a plain
	// mechanism, setting it makes the client say that it supports
	// binding. Server: set it when -PLUS mechanisms are offered on this
	// connection; a client that then uses a plain mechanism while
	// claiming binding support is refused as a downgrade.
	ChannelBinding ChannelBinding
	// NoSASLprep uses user names and passwords exactly as given.
	NoSASLprep bool
	// AuthzID is the authorization identity the client sends (client
	// only). The server accepts only an authzid equal to the user.
	AuthzID string
	// Iterations is the PBKDF2 iteration count the server asks for when it
	// looks up passwords, and for unknown users (server only; default
	// Iterations, 10000 for SCRAM-SHA-512).
	Iterations int
	// MaxIterations is the most iterations the client computes (client
	// only; default 1,000,000).
	MaxIterations int
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

// fakeSaltKey keys the salts given to unknown users of a stored-credential
// server, so that the same unknown name always gets the same salt, as a
// known one does.
var fakeSaltKey = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()

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

var errBadName = errors.New("bad saslname")

// Credentials are what a server may store instead of a password (RFC 5802
// 3): the salt, the iteration count, StoredKey = H(ClientKey) and
// ServerKey. They let the server check a client without being able to log
// in as it.
type Credentials struct {
	Salt       []byte
	Iterations int
	StoredKey  []byte
	ServerKey  []byte
}

// NewCredentials derives the stored credentials of a password for a
// mechanism's hash. The password is prepared as the default Options do
// (SASLprep, kept as given where SASLprep refuses it). salt should be
// random, 16 bytes or more; iterations at least 4096.
func NewCredentials(mech, password string, salt []byte, iterations int) (Credentials, error) {
	h := Hash(mech)
	if h == nil {
		return Credentials{}, Error("invalid-mechanism")
	}
	if iterations < 1 || len(salt) == 0 {
		return Credentials{}, errors.New("SCRAM: credentials need a salt and at least one iteration")
	}
	c, _ := scram.HashGeneratorFcn(h).NewClientUnprepped("", prepare(password, false), "")
	sc, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: iterations})
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{Salt: append([]byte(nil), salt...), Iterations: iterations, StoredKey: sc.StoredKey, ServerKey: sc.ServerKey}, nil
}

// ScramServer is the server side of one SCRAM exchange.
type ScramServer struct {
	mech     string
	gen      scram.HashGeneratorFcn
	plus     bool
	opts     Options
	password func(string) (string, bool)
	stored   func(string) (Credentials, bool)
	conv     *scram.ServerConversation
	user     string
	known    bool
	full     string // the combined nonce
	keyErr   error
}

// NewScramServer starts an exchange for mech; password looks users up.
func NewScramServer(mech string, password func(string) (string, bool)) (*ScramServer, error) {
	return NewScramServerWith(mech, password, Options{})
}

// NewScramServerWith is NewScramServer with options, such as the channel
// binding a -PLUS mechanism needs.
func NewScramServerWith(mech string, password func(string) (string, bool), opts Options) (*ScramServer, error) {
	s, err := newServer(mech, opts)
	if err != nil {
		return nil, err
	}
	s.password = password
	return s, nil
}

// NewStoredScramServer starts an exchange whose users are looked up as
// stored Credentials (see NewCredentials) instead of passwords. The
// credentials must have been derived with mech's hash.
func NewStoredScramServer(mech string, lookup func(string) (Credentials, bool), opts Options) (*ScramServer, error) {
	s, err := newServer(mech, opts)
	if err != nil {
		return nil, err
	}
	s.stored = lookup
	return s, nil
}

func newServer(mech string, opts Options) (*ScramServer, error) {
	h, plus := parseMech(mech)
	if h == nil {
		return nil, Error("invalid-mechanism")
	}
	if plus || !opts.ChannelBinding.IsZero() {
		if err := opts.ChannelBinding.check(); err != nil {
			return nil, err
		}
	}
	return &ScramServer{mech: mech, gen: scram.HashGeneratorFcn(h), plus: plus, opts: opts}, nil
}

// lookup derives the stored credentials of a user. An unknown user still
// gets a challenge (with a random salt and password, or a salt fixed per
// name for stored credentials), so the answer does not tell which users
// exist.
func (s *ScramServer) lookup(raw string) (scram.StoredCredentials, error) {
	user, ok := name(raw)
	if !ok || user == "" {
		return scram.StoredCredentials{}, errBadName
	}
	iters := s.opts.Iterations
	switch {
	case iters > 0:
	case s.gen().Size() == sha512.Size:
		iters = iterations512
	default:
		iters = Iterations
	}
	if s.stored != nil {
		c, known := s.stored(user)
		if known && (len(c.Salt) == 0 || c.Iterations < 1 || len(c.StoredKey) != s.gen().Size() || len(c.ServerKey) != s.gen().Size()) {
			s.keyErr = errors.New("SCRAM: stored credentials do not fit the mechanism")
			return scram.StoredCredentials{}, s.keyErr
		}
		s.user, s.known = user, known
		if !known {
			m := hmac.New(sha256.New, fakeSaltKey)
			m.Write([]byte(user))
			c = Credentials{Salt: m.Sum(nil)[:16], Iterations: iters, StoredKey: make([]byte, s.gen().Size()), ServerKey: make([]byte, s.gen().Size())}
			_, _ = rand.Read(c.StoredKey)
		}
		return scram.StoredCredentials{
			KeyFactors: scram.KeyFactors{Salt: string(c.Salt), Iters: c.Iterations},
			StoredKey:  c.StoredKey, ServerKey: c.ServerKey,
		}, nil
	}
	pw, known := s.password(user)
	if !known || pw == "" {
		pw, known = nonce(), false
	}
	s.user, s.known = user, known
	c, _ := s.gen.NewClientUnprepped(user, prepare(pw, s.opts.NoSASLprep), "")
	cred, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(newSalt()), Iters: iters})
	s.keyErr = err
	return cred, err
}

// checkFlag applies the channel-binding rules of RFC 5802 6 to the client's
// gs2 flag before anything else is done with the message.
func (s *ScramServer) checkFlag(cf string) error {
	flag, _, _ := strings.Cut(cf, ",")
	cbType, isP := strings.CutPrefix(flag, "p=")
	switch {
	case s.plus && !isP:
		return Error("malformed-request") // a -PLUS mechanism must bind
	case s.plus && cbType != s.opts.ChannelBinding.Type:
		return Error("invalid-mechanism") // a binding type not offered
	case !s.plus && isP:
		return Error("invalid-mechanism") // binding without -PLUS
	case !s.plus && flag == "y" && !s.opts.ChannelBinding.IsZero():
		return Error("not-authorized") // -PLUS was offered: a downgrade
	}
	return nil
}

// First reads the client's first message and returns the server's first
// message (the challenge).
func (s *ScramServer) First(first []byte) ([]byte, error) {
	cf := string(first)
	s.conv, s.keyErr = nil, nil
	if err := s.checkFlag(cf); err != nil {
		return nil, err
	}
	snonce := newNonce()
	srv, _ := s.gen.NewServer(s.lookup)
	srv = srv.WithNonceGenerator(func() string { return snonce })
	var conv *scram.ServerConversation
	if s.opts.ChannelBinding.IsZero() {
		conv = srv.NewConversation()
	} else {
		cb := scram.ChannelBinding{Type: scram.ChannelBindingType(s.opts.ChannelBinding.Type), Data: append([]byte(nil), s.opts.ChannelBinding.Data...)}
		conv = srv.NewConversationWithChannelBinding(cb)
	}
	sf, err := conv.Step(cf)
	switch {
	case err == nil:
	case s.keyErr != nil:
		return nil, Error("temporary-auth-failure")
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
	return ServerWith(mech, first, password, Options{}, exchange)
}

// ServerWith is Server with options.
func ServerWith(mech string, first []byte, password func(string) (string, bool), opts Options,
	exchange func(challenge []byte) ([]byte, error)) (user string, final []byte, err error) {
	s, err := NewScramServerWith(mech, password, opts)
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
func checkServerFirst(sf, cnonce string, maxIter int) error {
	a := attrs(sf)
	if !strings.HasPrefix(a['r'], cnonce) || len(a['r']) == len(cnonce) {
		return errors.New("SCRAM: the server's nonce does not extend ours")
	}
	if _, err := base64.StdEncoding.DecodeString(a['s']); err != nil {
		return errors.New("SCRAM: bad salt")
	}
	if iter, err := strconv.Atoi(a['i']); err != nil || iter < 1 || iter > maxIter {
		return fmt.Errorf("SCRAM: iteration count %q", a['i'])
	}
	return nil
}

// Client runs the client side over exchange, which sends a message and
// returns the server's next data: a challenge, or (last) the verifier.
func Client(mech, user, password string, exchange func(msg []byte, last bool) ([]byte, error)) error {
	return ClientWith(mech, user, password, Options{}, exchange)
}

// ClientWith is Client with options, such as the channel binding a -PLUS
// mechanism needs.
func ClientWith(mech, user, password string, opts Options, exchange func(msg []byte, last bool) ([]byte, error)) error {
	h, plus := parseMech(mech)
	if h == nil {
		return Error("invalid-mechanism")
	}
	if plus || !opts.ChannelBinding.IsZero() {
		if err := opts.ChannelBinding.check(); err != nil {
			return err
		}
	}
	maxIter := opts.MaxIterations
	if maxIter <= 0 {
		maxIter = maxIterations
	}
	cnonce := newNonce()
	c, _ := scram.HashGeneratorFcn(h).NewClientUnprepped(prepare(user, opts.NoSASLprep), prepare(password, opts.NoSASLprep), prepare(opts.AuthzID, opts.NoSASLprep))
	c = c.WithMinIterations(1).WithNonceGenerator(func() string { return cnonce })
	var conv *scram.ClientConversation
	switch {
	case plus:
		conv = c.NewConversationWithChannelBinding(scram.ChannelBinding{
			Type: scram.ChannelBindingType(opts.ChannelBinding.Type), Data: append([]byte(nil), opts.ChannelBinding.Data...),
		})
	case !opts.ChannelBinding.IsZero():
		conv = c.NewConversationAdvertisingChannelBinding()
	default:
		conv = c.NewConversation()
	}
	cf, err := conv.Step("")
	if err != nil {
		return err
	}
	sfb, err := exchange([]byte(cf), false)
	if err != nil {
		return err
	}
	sf := string(sfb)
	if err := checkServerFirst(sf, cnonce, maxIter); err != nil {
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
