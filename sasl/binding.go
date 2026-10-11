// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sasl

import (
	"crypto"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	// The hash functions a certificate may name.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Channel binding types (RFC 5056) that the -PLUS mechanisms can carry.
const (
	// TLSUnique is the first Finished message of a TLS 1.2 or earlier
	// handshake (RFC 5929 3). It does not exist in TLS 1.3, and is only
	// safe with the extended master secret (RFC 7627).
	TLSUnique = "tls-unique"
	// TLSServerEndPoint is a hash of the server's certificate (RFC 5929
	// 4). It works with every TLS version but binds to the certificate,
	// not to the connection.
	TLSServerEndPoint = "tls-server-end-point"
	// TLSExporter is 32 bytes of exported keying material with the label
	// "EXPORTER-Channel-Binding" and no context (RFC 9266), the binding
	// for TLS 1.3.
	TLSExporter = "tls-exporter"
)

// ChannelBinding is the type and data of a channel binding. Both sides of a
// -PLUS exchange compute it from their own view of the same TLS connection;
// the exchange fails unless the two agree.
type ChannelBinding struct {
	Type string
	Data []byte
}

// IsZero reports whether no binding is set.
func (cb ChannelBinding) IsZero() bool { return cb.Type == "" && len(cb.Data) == 0 }

func (cb ChannelBinding) check() error {
	switch cb.Type {
	case TLSUnique, TLSServerEndPoint, TLSExporter:
	default:
		return fmt.Errorf("SCRAM: channel binding type %q", cb.Type)
	}
	if len(cb.Data) == 0 {
		return errors.New("SCRAM: empty channel binding data")
	}
	return nil
}

// TLSBinding returns the default binding of a connection: tls-exporter on
// TLS 1.3 (RFC 9266 3), tls-unique on earlier versions (RFC 5802 6.1).
// Peers that support only tls-server-end-point, such as PostgreSQL, need
// TLSServerEndPointBinding instead.
func TLSBinding(cs *tls.ConnectionState) (ChannelBinding, error) {
	if cs != nil && cs.Version >= tls.VersionTLS13 {
		return TLSExporterBinding(cs)
	}
	return TLSUniqueBinding(cs)
}

// TLSExporterBinding returns the tls-exporter binding of a connection
// (RFC 9266). Go refuses to export keying material from a TLS 1.2
// connection without the extended master secret, and so does this.
func TLSExporterBinding(cs *tls.ConnectionState) (ChannelBinding, error) {
	if cs == nil || !cs.HandshakeComplete {
		return ChannelBinding{}, errors.New("SCRAM: TLS handshake not complete")
	}
	data, err := cs.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return ChannelBinding{}, fmt.Errorf("SCRAM: tls-exporter: %w", err)
	}
	return ChannelBinding{Type: TLSExporter, Data: data}, nil
}

// TLSUniqueBinding returns the tls-unique binding of a connection (RFC
// 5929 3). Go leaves it empty for TLS 1.3 and for resumed TLS 1.2
// connections without the extended master secret; both are refused.
func TLSUniqueBinding(cs *tls.ConnectionState) (ChannelBinding, error) {
	if cs == nil || !cs.HandshakeComplete {
		return ChannelBinding{}, errors.New("SCRAM: TLS handshake not complete")
	}
	if len(cs.TLSUnique) == 0 {
		return ChannelBinding{}, errors.New("SCRAM: tls-unique is not available on this connection (TLS 1.3, or resumed without extended master secret)")
	}
	return ChannelBinding{Type: TLSUnique, Data: append([]byte(nil), cs.TLSUnique...)}, nil
}

// TLSServerEndPointBinding returns the tls-server-end-point binding of a
// DER certificate (RFC 5929 4.1): the certificate hashed with the hash of
// its own signature algorithm, SHA-256 when that is MD5 or SHA-1. A client
// passes the server's leaf certificate (ConnectionState.PeerCertificates[0]
// .Raw); a server passes its own (tls.Certificate.Certificate[0]). Only the
// outer signature algorithm is read, so certificates whose keys
// crypto/x509 cannot parse (brainpool, for one) work too. Signature
// algorithms without a single hash, such as Ed25519, have no binding.
func TLSServerEndPointBinding(certDER []byte) (ChannelBinding, error) {
	h, err := endPointHash(certDER)
	if err != nil {
		return ChannelBinding{}, err
	}
	d := h.New()
	d.Write(certDER)
	return ChannelBinding{Type: TLSServerEndPoint, Data: d.Sum(nil)}, nil
}

// Signature algorithm object identifiers (RFC 3279, RFC 4055, RFC 5758,
// RFC 8017).
var (
	oidMD5RSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSHA224RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidDSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidDSASHA224   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 1}
	oidDSASHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// endPointHash reads Certificate.signatureAlgorithm and returns the hash
// RFC 5929 4.1 asks for.
func endPointHash(der []byte) (crypto.Hash, error) {
	var cert struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &cert); err != nil || len(rest) != 0 {
		return 0, errors.New("SCRAM: tls-server-end-point: not a DER certificate")
	}
	oid := cert.SigAlg.Algorithm
	switch {
	case oid.Equal(oidMD5RSA), oid.Equal(oidSHA1RSA), oid.Equal(oidDSASHA1), oid.Equal(oidECDSASHA1),
		oid.Equal(oidSHA256RSA), oid.Equal(oidDSASHA256), oid.Equal(oidECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA224RSA), oid.Equal(oidDSASHA224), oid.Equal(oidECDSASHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA384RSA), oid.Equal(oidECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512RSA), oid.Equal(oidECDSASHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidRSAPSS):
		return pssHash(cert.SigAlg.Parameters)
	}
	return 0, fmt.Errorf("SCRAM: tls-server-end-point is not defined for signature algorithm %v", oid)
}

// pssHash reads the hashAlgorithm of RSASSA-PSS-params (RFC 4055 3.1),
// whose default is SHA-1.
func pssHash(params asn1.RawValue) (crypto.Hash, error) {
	if len(params.FullBytes) == 0 {
		return crypto.SHA256, nil // absent parameters: SHA-1, which maps to SHA-256
	}
	var pss struct {
		Hash pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
		Rest asn1.RawValue            `asn1:"optional"` // MGF, salt length, trailer
		More asn1.RawValue            `asn1:"optional"`
		Last asn1.RawValue            `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(params.FullBytes, &pss); err != nil {
		return 0, errors.New("SCRAM: tls-server-end-point: bad RSASSA-PSS parameters")
	}
	oid := pss.Hash.Algorithm
	if len(oid) == 0 {
		return crypto.SHA256, nil
	}
	switch {
	case oid.Equal(oidSHA1), oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("SCRAM: tls-server-end-point: RSASSA-PSS hash %v", oid)
}
