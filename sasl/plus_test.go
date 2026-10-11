// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xdg-go/scram"
)

// Exchanges computed with an independent SCRAM written in Python (hashlib
// and hmac), whose SCRAM-SHA-256 output equals RFC 7677's example. Same
// user, password, nonces and salt as RFC 7677; channel binding data 00 01
// .. 1F (tls-unique: 00 .. 0B).
type plusVector struct {
	mech, cbType string
	cbLen, iters int
	clientFirst  string
	serverFirst  string
	clientFinal  string
	serverFinal  string
	storedKey    string
	serverKey    string
}

var plusVectors = []plusVector{
	{
		mech: SCRAMSHA512, iters: 10000,
		clientFirst: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000",
		clientFinal: "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=sScffJ11LZ4TfY4PVI/6/9rMIHpix12AijdjQOPWK26er2vRtW/osDSi/hegaCFWfI91sJZd0bevncVEhUg0wQ==",
		serverFinal: "v=RjtcFh+1kT0TmNH2klLiCXHiJLvMLwWuSSjecIns8FBSn0XXRb3iv2qU96STCkYC2Go0feONylPqhw46oweC5A==",
		storedKey:   "a1310d29128cf1d0882b6f0187cc5032947f0e5dfd064931e53eef7e6d90190a52d03ef99ef0ef22a4c872c23eda94532135f14f839627aee2507e0c257cfdb0",
		serverKey:   "227165c223010cafb81facbbfe536a441160bfc57b6eeff98d5c668c48c77db4f7e84d78b9398b6248f7d9b33ad02a391f9b2e7dd91f3617cb37c76f830ecb0f",
	},
	{
		mech: SCRAMSHA256PLUS, cbType: TLSExporter, cbLen: 32, iters: 4096,
		clientFirst: "p=tls-exporter,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		clientFinal: "c=cD10bHMtZXhwb3J0ZXIsLAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=QC6CS20quADQRb3mT99YUH+n3VJxUvzuK0K0E1Vrs2M=",
		serverFinal: "v=2GiAgapEppLVlUXbxUDksL3VgYHzuqiK5tR4mhJGgvs=",
		storedKey:   "586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6",
		serverKey:   "c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5",
	},
	{
		mech: SCRAMSHA512PLUS, cbType: TLSServerEndPoint, cbLen: 32, iters: 10000,
		clientFirst: "p=tls-server-end-point,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=10000",
		clientFinal: "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=ewZPlgrB0c+GXdhw5/ec1WkJISnwpRFm7fcM7w6+5ZgzTY6VYfNmUigyauqfivjIyOdMZW3mvzfXqthgNrQFjw==",
		serverFinal: "v=0CTR5Ha8HPZTvpag+il9CHDIVMmWJy2VTWwgfXjVVkMgsK4K3NFvLJQ53247kKhRyMTUxLMxqnVbE2WK6mOvJw==",
		storedKey:   "a1310d29128cf1d0882b6f0187cc5032947f0e5dfd064931e53eef7e6d90190a52d03ef99ef0ef22a4c872c23eda94532135f14f839627aee2507e0c257cfdb0",
		serverKey:   "227165c223010cafb81facbbfe536a441160bfc57b6eeff98d5c668c48c77db4f7e84d78b9398b6248f7d9b33ad02a391f9b2e7dd91f3617cb37c76f830ecb0f",
	},
	{
		mech: SCRAMSHA1PLUS, cbType: TLSUnique, cbLen: 12, iters: 4096,
		clientFirst: "p=tls-unique,,n=user,r=rOprNGfwEbeRWgbNEkqO",
		serverFirst: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
		clientFinal: "c=cD10bHMtdW5pcXVlLCwAAQIDBAUGBwgJCgs=,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=QFkg+ulaqERFv4niHp/atSnglKc=",
		serverFinal: "v=+OU00NmE2EJp2C6JjMHszib3gCQ=",
		storedKey:   "836a44cd7dad31aa226f14c3e187c1264ab5cbcc",
		serverKey:   "64690d8ec98ac155f90b9cfcd2f1b11d9d368ce2",
	},
}

const (
	refCnonce = "rOprNGfwEbeRWgbNEkqO"
	refSnonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	refSalt   = "W22ZaJ0SNY7soEsUEjb6gQ=="
)

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func (v *plusVector) opts() Options {
	if v.cbType == "" {
		return Options{}
	}
	return Options{ChannelBinding: ChannelBinding{Type: v.cbType, Data: seqBytes(v.cbLen)}}
}

// Our client, our password server and our stored-credential server
// reproduce the independent exchanges byte for byte, for SCRAM-SHA-512 and
// the three channel binding types.
//
// Covers: SIG-IPE-3627
func TestPlusAndSHA512Vectors(t *testing.T) {
	for i := range plusVectors {
		v := &plusVectors[i]
		opts := v.opts()

		fixRandom(t, refCnonce, refSalt)
		var sent []string
		err := ClientWith(v.mech, "user", "pencil", opts, func(msg []byte, last bool) ([]byte, error) {
			sent = append(sent, string(msg))
			if !last {
				return []byte(v.serverFirst), nil
			}
			return []byte(v.serverFinal), nil
		})
		if err != nil || len(sent) != 2 || sent[0] != v.clientFirst || sent[1] != v.clientFinal {
			t.Errorf("%s client: sent %q, %v", v.mech, sent, err)
		}

		fixRandom(t, refSnonce, refSalt)
		s, err := NewScramServerWith(v.mech, pencil, opts)
		if err != nil {
			t.Fatal(err)
		}
		sf, err := s.First([]byte(v.clientFirst))
		if err != nil || string(sf) != v.serverFirst {
			t.Fatalf("%s server first: %q, %v", v.mech, sf, err)
		}
		u, fin, err := s.Final([]byte(v.clientFinal))
		if err != nil || u != "user" || string(fin) != v.serverFinal {
			t.Errorf("%s server final: %q %q, %v", v.mech, u, fin, err)
		}

		cred, err := NewCredentials(v.mech, "pencil", mustB64(t, refSalt), v.iters)
		if err != nil || hex.EncodeToString(cred.StoredKey) != v.storedKey || hex.EncodeToString(cred.ServerKey) != v.serverKey {
			t.Errorf("%s credentials: %x %x, %v", v.mech, cred.StoredKey, cred.ServerKey, err)
		}
		fixRandom(t, refSnonce, refSalt)
		ss, err := NewStoredScramServer(v.mech, func(u string) (Credentials, bool) { return cred, u == "user" }, opts)
		if err != nil {
			t.Fatal(err)
		}
		sf, err = ss.First([]byte(v.clientFirst))
		if err != nil || string(sf) != v.serverFirst {
			t.Fatalf("%s stored first: %q, %v", v.mech, sf, err)
		}
		if _, fin, err := ss.Final([]byte(v.clientFinal)); err != nil || string(fin) != v.serverFinal {
			t.Errorf("%s stored final: %q, %v", v.mech, fin, err)
		}
	}
}

// The channel-binding rules of RFC 5802 6 on the server, with the
// condition each refusal gets.
//
// Covers: SIG-IPE-3627
func TestPlusServerRefusals(t *testing.T) {
	cb := ChannelBinding{Type: TLSExporter, Data: seqBytes(32)}
	other := ChannelBinding{Type: TLSExporter, Data: bytes.Repeat([]byte{7}, 32)}
	for _, c := range []struct {
		name       string
		mech       string
		srv        Options
		cli        Options
		rawFirst   string // sent instead of the client's first message
		want       string
		wantClient string
	}{
		{name: "plus, same binding", mech: SCRAMSHA256PLUS, srv: Options{ChannelBinding: cb}, cli: Options{ChannelBinding: cb}, want: "ok"},
		{name: "plus, other connection", mech: SCRAMSHA256PLUS, srv: Options{ChannelBinding: cb}, cli: Options{ChannelBinding: other}, want: "not-authorized"},
		{name: "plus, other type", mech: SCRAMSHA256PLUS, srv: Options{ChannelBinding: cb}, cli: Options{ChannelBinding: ChannelBinding{Type: TLSServerEndPoint, Data: seqBytes(32)}}, want: "invalid-mechanism"},
		{name: "plus, client says n", mech: SCRAMSHA256PLUS, srv: Options{ChannelBinding: cb}, rawFirst: "n,,n=user,r=abc", want: "malformed-request"},
		{name: "plus, client says y", mech: SCRAMSHA256PLUS, srv: Options{ChannelBinding: cb}, rawFirst: "y,,n=user,r=abc", want: "malformed-request"},
		{name: "plain, plus offered, client y (downgrade)", mech: SCRAMSHA256, srv: Options{ChannelBinding: cb}, cli: Options{ChannelBinding: cb}, want: "not-authorized"},
		{name: "plain, plus offered, client n", mech: SCRAMSHA256, srv: Options{ChannelBinding: cb}, want: "ok"},
		{name: "plain, not offered, client y", mech: SCRAMSHA256, cli: Options{ChannelBinding: cb}, want: "ok"},
		{name: "plain, client p", mech: SCRAMSHA256, srv: Options{ChannelBinding: cb}, rawFirst: "p=tls-exporter,,n=user,r=abc", want: "invalid-mechanism"},
	} {
		s, err := NewScramServerWith(c.mech, pencil, c.srv)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.rawFirst != "" {
			if _, err := s.First([]byte(c.rawFirst)); condition(err) != c.want {
				t.Errorf("%s: %v, want %s", c.name, err, c.want)
			}
			continue
		}
		var srvErr error
		ClientWith(c.mech, "user", "pencil", c.cli, func(msg []byte, last bool) ([]byte, error) {
			if !last {
				sf, err := s.First(msg)
				srvErr = err
				return sf, err
			}
			_, fin, err := s.Final(msg)
			srvErr = err
			return fin, err
		})
		if condition(srvErr) != c.want {
			t.Errorf("%s: server %v, want %s", c.name, srvErr, c.want)
		}
	}

	// Configuration errors.
	if _, err := NewScramServerWith(SCRAMSHA256PLUS, pencil, Options{ChannelBinding: ChannelBinding{Type: "tls-other", Data: []byte{1}}}); err == nil {
		t.Error("unknown binding type accepted")
	}
	if err := ClientWith(SCRAMSHA256PLUS, "user", "pencil", Options{}, nil); err == nil {
		t.Error("-PLUS client without binding accepted")
	}
	if err := ClientWith(SCRAMSHA256PLUS, "user", "pencil", Options{ChannelBinding: ChannelBinding{Type: TLSExporter}}, nil); err == nil {
		t.Error("-PLUS client with empty binding data accepted")
	}
}

// A stored-credential server gives an unknown user the same salt every
// time, as it does a known one, and refuses credentials of the wrong size.
//
// Covers: SIG-IPE-3627
func TestStoredServerUnknownUsers(t *testing.T) {
	cred, err := NewCredentials(SCRAMSHA256, "pencil", []byte("0123456789abcdef"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(u string) (Credentials, bool) { return cred, u == "user" }
	salt := func(user string) string {
		s, _ := NewStoredScramServer(SCRAMSHA256, lookup, Options{})
		sf, err := s.First([]byte("n,,n=" + user + ",r=abc"))
		if err != nil {
			t.Fatal(err)
		}
		return attrs(string(sf))['s'] + "," + attrs(string(sf))['i']
	}
	if salt("nobody") != salt("nobody") || salt("user") != salt("user") || salt("nobody") == salt("other") {
		t.Error("salts of unknown users are not stable per name")
	}
	s, _ := NewStoredScramServer(SCRAMSHA256, lookup, Options{})
	err = Client(SCRAMSHA256, "nobody", "pencil", func(msg []byte, last bool) ([]byte, error) {
		if !last {
			return s.First(msg)
		}
		_, fin, err := s.Final(msg)
		return fin, err
	})
	if err == nil {
		t.Error("unknown user authenticated")
	}
	short := cred
	short.StoredKey = short.StoredKey[:20]
	bad, _ := NewStoredScramServer(SCRAMSHA256, func(string) (Credentials, bool) { return short, true }, Options{})
	if _, err := bad.First([]byte("n,,n=user,r=abc")); condition(err) != "temporary-auth-failure" {
		t.Errorf("short stored key: %v", err)
	}
	if _, err := NewCredentials("PLAIN", "pencil", []byte("salt"), 1); condition(err) != "invalid-mechanism" {
		t.Errorf("PLAIN credentials: %v", err)
	}
	if _, err := NewCredentials(SCRAMSHA256, "pencil", nil, 4096); err == nil {
		t.Error("credentials without salt")
	}
}

func TestMechanismNames(t *testing.T) {
	if got := Choose([]string{"PLAIN", "SCRAM-SHA-1", "scram-sha-256", "SCRAM-SHA-256-PLUS"}, false); got != SCRAMSHA256 {
		t.Errorf("without binding: %q", got)
	}
	if got := Choose([]string{"PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS"}, true); got != SCRAMSHA1PLUS {
		t.Errorf("with binding: %q", got)
	}
	if got := Choose([]string{"PLAIN"}, true); got != "" {
		t.Errorf("none: %q", got)
	}
	if len(Mechanisms(true)) != 6 || len(Mechanisms(false)) != 3 || IsPlus(SCRAMSHA256) || !IsPlus(SCRAMSHA512PLUS) || IsPlus("PLAIN-PLUS") {
		t.Error("mechanism lists")
	}
	for _, m := range Mechanisms(true) {
		if Hash(m) == nil {
			t.Errorf("no hash for %s", m)
		}
	}
}

// selfSigned returns a certificate signed with alg by a fresh key.
func selfSigned(t *testing.T, alg x509.SignatureAlgorithm, key crypto.Signer) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "scram.test"},
		DNSNames:           []string{"scram.test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: alg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TLSServerEndPointBinding picks the hash of RFC 5929 4.1 for each kind
// of certificate and agrees with xdg-go/scram's own computation.
//
// Covers: SIG-IPE-3627
func TestServerEndPointHashes(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		alg  x509.SignatureAlgorithm
		key  crypto.Signer
		want crypto.Hash
	}{
		{x509.ECDSAWithSHA256, p256, crypto.SHA256},
		{x509.ECDSAWithSHA384, p384, crypto.SHA384},
		{x509.ECDSAWithSHA512, p384, crypto.SHA512},
		{x509.SHA256WithRSA, rsaKey, crypto.SHA256},
		{x509.SHA384WithRSAPSS, rsaKey, crypto.SHA384},
		{x509.SHA512WithRSAPSS, rsaKey, crypto.SHA512},
		{x509.PureEd25519, edKey, 0},
	} {
		cert := selfSigned(t, c.alg, c.key)
		der := cert.Certificate[0]
		cb, err := TLSServerEndPointBinding(der)
		if c.want == 0 {
			if err == nil {
				t.Errorf("%v: binding without a hash", c.alg)
			}
			continue
		}
		h := c.want.New()
		h.Write(der)
		if err != nil || cb.Type != TLSServerEndPoint || !bytes.Equal(cb.Data, h.Sum(nil)) {
			t.Errorf("%v: %x, %v", c.alg, cb.Data, err)
		}
		parsed, _ := x509.ParseCertificate(der)
		if xb, err := scram.NewTLSServerEndpointBinding(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}); err == nil && !bytes.Equal(xb.Data, cb.Data) {
			t.Errorf("%v: differs from xdg-go/scram", c.alg)
		}
	}
	if _, err := TLSServerEndPointBinding([]byte{0x30, 0x00}); err == nil {
		t.Error("garbage accepted")
	}
}

// tlsPair runs a TLS handshake over an in-memory pipe and returns both
// connection states.
func tlsPair(t *testing.T, version uint16, cert tls.Certificate) (client, server tls.ConnectionState) {
	t.Helper()
	cc, sc := net.Pipe()
	t.Cleanup(func() { cc.Close(); sc.Close() })
	srv := tls.Server(sc, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	cli := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
	var wg sync.WaitGroup
	var serr error
	wg.Add(1)
	go func() { defer wg.Done(); serr = srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if serr != nil {
		t.Fatal(serr)
	}
	return cli.ConnectionState(), srv.ConnectionState()
}

// SCRAM-*-PLUS over real TLS 1.2 and 1.3 connections with each binding
// type the version has: both sides compute the binding from their own
// connection state, the exchange succeeds, and a client on a different
// connection (a relay) is refused.
//
// Covers: SIG-IPE-3627
func TestPlusOverTLS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := selfSigned(t, x509.ECDSAWithSHA256, key)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		cs, ss := tlsPair(t, version, cert)
		relay, _ := tlsPair(t, version, cert)
		type sides struct {
			name                  string
			client, server, relay func(*tls.ConnectionState) (ChannelBinding, error)
		}
		endPointClient := func(cs *tls.ConnectionState) (ChannelBinding, error) {
			return TLSServerEndPointBinding(cs.PeerCertificates[0].Raw)
		}
		endPointServer := func(*tls.ConnectionState) (ChannelBinding, error) {
			return TLSServerEndPointBinding(cert.Certificate[0])
		}
		kinds := []sides{
			{TLSExporter, TLSExporterBinding, TLSExporterBinding, TLSExporterBinding},
			{TLSServerEndPoint, endPointClient, endPointServer, nil},
			{"default", TLSBinding, TLSBinding, TLSBinding},
		}
		if version == tls.VersionTLS12 {
			kinds = append(kinds, sides{TLSUnique, TLSUniqueBinding, TLSUniqueBinding, TLSUniqueBinding})
		} else if _, err := TLSUniqueBinding(&cs); err == nil {
			t.Error("tls-unique on TLS 1.3")
		}
		for _, k := range kinds {
			ccb, err := k.client(&cs)
			if err != nil {
				t.Fatalf("%x %s client: %v", version, k.name, err)
			}
			scb, err := k.server(&ss)
			if err != nil {
				t.Fatalf("%x %s server: %v", version, k.name, err)
			}
			for _, mech := range []string{SCRAMSHA1PLUS, SCRAMSHA256PLUS, SCRAMSHA512PLUS} {
				if err := exchangeWith(t, mech, "pencil", "pencil", Options{ChannelBinding: scb}, Options{ChannelBinding: ccb}); err != nil {
					t.Errorf("%x %s %s: %v", version, k.name, mech, err)
				}
			}
			if k.relay == nil {
				continue // tls-server-end-point binds to the certificate only
			}
			rcb, err := k.relay(&relay)
			if err != nil {
				t.Fatal(err)
			}
			if err := exchangeWith(t, SCRAMSHA256PLUS, "pencil", "pencil", Options{ChannelBinding: scb}, Options{ChannelBinding: rcb}); err == nil {
				t.Errorf("%x %s: relayed exchange accepted", version, k.name)
			}
		}
	}
	if _, err := TLSExporterBinding(&tls.ConnectionState{}); err == nil {
		t.Error("exporter before handshake")
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
