// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pgPassword is set with initdb. PostgreSQL applies SASLprep to it (soft
// hyphen removed, ROMAN NUMERAL NINE normalised), so its prepared form is
// "pencilIX".
const pgPassword = "pen­cilⅨ"

// startPostgres runs a throw-away PostgreSQL server with TLS and SCRAM
// authentication on a free loopback port, and returns the port.
func startPostgres(t *testing.T) int {
	t.Helper()
	if testing.Short() {
		t.Skip("short mode")
	}
	initdb, err1 := exec.LookPath("initdb")
	postgres, err2 := exec.LookPath("postgres")
	if err1 != nil || err2 != nil {
		t.Skip("PostgreSQL (initdb, postgres) not installed")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte(pgPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ini := exec.Command(initdb, "-D", data, "-U", "tester", "--auth=scram-sha-256", "--pwfile="+pw, "-E", "UTF8", "--no-locale", "--no-instructions")
	ini.Env = append(os.Environ(), "LC_ALL=C")
	out, err := ini.CombinedOutput()
	if err != nil {
		t.Skipf("initdb failed: %v\n%s", err, out)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := selfSigned(t, x509.ECDSAWithSHA256, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	crt := filepath.Join(data, "server.crt")
	kf := filepath.Join(data, "server.key")
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, postgres, "-D", data, "-p", strconv.Itoa(port), "-k", dir,
		"-c", "listen_addresses=127.0.0.1", "-c", "ssl=on", "-c", "ssl_cert_file="+crt, "-c", "ssl_key_file="+kf,
		"-c", "password_encryption=scram-sha-256", "-c", "fsync=off")
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) } // fast shutdown
	cmd.WaitDelay = 10 * time.Second
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Skipf("postgres did not start: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); <-exited })
	deadline := time.Now().Add(20 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			break
		}
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("postgres exited: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres not listening: %v\n%s", err, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return port
}

// pgConn is just enough of the PostgreSQL frontend protocol (version 3) to
// authenticate.
type pgConn struct {
	c *tls.Conn
	r *bufio.Reader
}

func (p *pgConn) send(typ byte, body []byte) error {
	msg := []byte{typ}
	msg = binary.BigEndian.AppendUint32(msg, uint32(4+len(body)))
	_, err := p.c.Write(append(msg, body...))
	return err
}

func (p *pgConn) recv() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n < 4 || n > 1<<20 {
		return 0, nil, errors.New("bad message length")
	}
	body := make([]byte, n-4)
	_, err := io.ReadFull(p.r, body)
	if hdr[0] == 'E' {
		return 0, nil, fmt.Errorf("server error: %q", strings.ReplaceAll(string(body), "\x00", " "))
	}
	return hdr[0], body, err
}

// auth expects an authentication message with code want and returns its
// data.
func (p *pgConn) auth(want uint32) ([]byte, error) {
	typ, body, err := p.recv()
	if err != nil {
		return nil, err
	}
	if typ != 'R' || len(body) < 4 || binary.BigEndian.Uint32(body) != want {
		return nil, fmt.Errorf("unexpected message %c %x (want authentication %d)", typ, body, want)
	}
	return body[4:], nil
}

// pgLogin connects over TLS and authenticates with SCRAM, choosing the
// mechanism with Choose. cb, when not nil, replaces the binding computed
// from the connection.
func pgLogin(t *testing.T, port int, version uint16, password string, opts Options, cb func(ChannelBinding) ChannelBinding) (string, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := raw.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil { // SSLRequest
		return "", err
	}
	var yes [1]byte
	if _, err := io.ReadFull(raw, yes[:]); err != nil || yes[0] != 'S' {
		return "", fmt.Errorf("SSLRequest refused: %q %v", yes, err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
	if err := c.Handshake(); err != nil {
		return "", err
	}
	p := &pgConn{c: c, r: bufio.NewReader(c)}
	startup := binary.BigEndian.AppendUint32(nil, 196608)
	startup = append(startup, "user\x00tester\x00database\x00postgres\x00\x00"...)
	if _, err := c.Write(append(binary.BigEndian.AppendUint32(nil, uint32(4+len(startup))), startup...)); err != nil {
		return "", err
	}
	list, err := p.auth(10) // AuthenticationSASL
	if err != nil {
		return "", err
	}
	offered := strings.Split(strings.TrimRight(string(list), "\x00"), "\x00")
	cs := c.ConnectionState()
	binding, err := TLSServerEndPointBinding(cs.PeerCertificates[0].Raw)
	if err != nil {
		return "", err
	}
	if cb != nil {
		binding = cb(binding)
	}
	opts.ChannelBinding = binding
	mech := Choose(offered, true)
	err = ClientWith(mech, "", password, opts, func(msg []byte, last bool) ([]byte, error) {
		if !last {
			body := append([]byte(mech), 0)
			body = binary.BigEndian.AppendUint32(body, uint32(len(msg)))
			if err := p.send('p', append(body, msg...)); err != nil { // SASLInitialResponse
				return nil, err
			}
			return p.auth(11) // AuthenticationSASLContinue
		}
		if err := p.send('p', msg); err != nil { // SASLResponse
			return nil, err
		}
		return p.auth(12) // AuthenticationSASLFinal
	})
	if err != nil {
		return mech, err
	}
	_, err = p.auth(0) // AuthenticationOk
	return mech, err
}

// Interop with PostgreSQL's server-side SCRAM-SHA-256-PLUS (it offers the
// tls-server-end-point binding), over TLS 1.2 and 1.3: our client logs in,
// SASLprep makes the typed and the prepared password equivalent as on the
// server, and PostgreSQL refuses a wrong binding and an unprepared
// password. Skipped when PostgreSQL is not installed.
//
// Covers: SIG-IPE-3627
func TestPostgreSQLInterop(t *testing.T) {
	port := startPostgres(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, pw := range []string{pgPassword, "pencilIX"} {
			mech, err := pgLogin(t, port, version, pw, Options{}, nil)
			if err != nil || mech != SCRAMSHA256PLUS {
				t.Errorf("TLS %x, password %q: %s, %v", version, pw, mech, err)
			} else {
				t.Logf("TLS %x, password %q: logged in with %s", version, pw, mech)
			}
		}
		if _, err := pgLogin(t, port, version, "pencil", Options{}, nil); err == nil {
			t.Errorf("TLS %x: wrong password accepted", version)
		}
		if _, err := pgLogin(t, port, version, pgPassword, Options{NoSASLprep: true}, nil); err == nil {
			t.Errorf("TLS %x: unprepared password accepted", version)
		}
		flip := func(cb ChannelBinding) ChannelBinding {
			cb.Data = append([]byte(nil), cb.Data...)
			cb.Data[0] ^= 1
			return cb
		}
		if _, err := pgLogin(t, port, version, pgPassword, Options{}, flip); err == nil {
			t.Errorf("TLS %x: wrong channel binding accepted", version)
		}
	}
}
