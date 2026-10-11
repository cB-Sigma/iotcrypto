# iotcrypto

Small cryptographic building blocks that IoT and utility protocols need and that Go's standard library does not have, in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iotcrypto.svg)](https://pkg.go.dev/github.com/cB-Sigma/iotcrypto) [![test](https://github.com/cB-Sigma/iotcrypto/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iotcrypto/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

It covers AES-CCM with any parameters, KMAC and KMACXOF, the Zigbee
AES-MMO hash, the Koblitz curves sect163k1 and sect283k1 with ECQV implicit
certificates and ECMQV (Zigbee Smart Energy key establishment), the
brainpool curves with ECDSA, ECDH, keys, certificates and certificate
requests, and SCRAM with SASLprep and TLS channel binding. No cgo. It was
written for SigmaM2M, a oneM2M platform, and is used in its production code
paths.

## Packages

| Package | What it does | Used for |
|---|---|---|
| `ccm` | AES-CCM as a `crypto/cipher.AEAD`, nonce 7 to 13 bytes, tag 4 to 16 bytes | wireless M-Bus, TLS CCM cipher suites, MQTT-SN, Matter |
| `kmac` | KMAC128 and KMAC256 (fixed output length, `hash.Hash`), KMACXOF128 and KMACXOF256 (any length, `io.Reader`) | IEC 62351-4 end-to-end security, key derivation |
| `aesmmo` | Matyas-Meyer-Oseas hash over AES-128, and HMAC over it | Zigbee install codes, Smart Energy CBKE |
| `koblitz` | sect163k1 and sect283k1: point encodings, constant-time scalar multiplication, scalars modulo n | Smart Energy CBKE suites 1 and 2 |
| `ecqv` | ECQV implicit certificates, suite 1 (48 octets) and suite 2 (74 octets): parse, extract public key, rebuild private key, and a private CA | Smart Energy CBKE |
| `ecmqv` | the ECMQV shared secret on the Koblitz curves | Smart Energy CBKE |
| `brainpool` | brainpoolP256r1, P384r1, P512r1: ECDH with an API shaped like crypto/ecdh, ECDSA (hedged deterministic nonces) with functions shaped like crypto/ecdsa, DER and P1363 signatures, compressed and uncompressed points, PKIX, SEC 1 and PKCS #8 keys, X.509 certificates and PKCS #10 requests | IEC 62351, TLS with brainpool curves (RFC 7027, RFC 8734) |
| `sasl` | SCRAM-SHA-1, SCRAM-SHA-256 and SCRAM-SHA-512, each also -PLUS with tls-unique, tls-server-end-point or tls-exporter channel binding; SASLprep; a client and a two-step server that looks up passwords or stored keys; over github.com/xdg-go/scram | MQTT-SN 2.0 AUTH, XMPP |
| `bigmod` | constant-time modular arithmetic (Go's internal bigmod, exported) | the curves above, finite-field Diffie-Hellman |

`bigmod` is low level and exists for the other packages; its API follows
Go's internal package and may change with it.

## Support matrix

| Feature | Status |
|---|---|
| CCM, any nonce and even tag length (RFC 3610, NIST SP 800-38C) | done; all 24 RFC 3610 vectors, NIST SP 800-38C Appendix C examples 1 to 4, 297 reference values covering every nonce and tag length, and all 552 Wycheproof AES-CCM vectors (including the nonce and tag sizes CCM does not define, which `New` refuses) |
| KMAC128/256 (NIST SP 800-185) | done; NIST's six KMAC samples and 435 Wycheproof KMAC vectors |
| KMACXOF128/256 (NIST SP 800-185 4.3.1) | done; NIST's six KMACXOF samples |
| AES-MMO hash and HMAC | done; Zigbee BDB and Smart Energy known answers |
| sect163k1/sect283k1 (SEC 2) | done; constant-time ladder for secrets, checked with a dudect-style timing test (`SIGMA_DUDECT=1`) |
| ECQV suites 1 and 2 (SEC 4) | done; Smart Energy 1.4a annex vectors. Other ECQV profiles are not |
| ECMQV (SEC 1) | done; Smart Energy 1.4a annex vectors |
| brainpool r1 curves (RFC 5639): ECDSA, ECDH | done; RFC 7027 vectors, OpenSSL interop, 4002 Wycheproof ECDSA vectors (SHA-2 and SHA-3, DER and P1363) and 2534 Wycheproof ECDH vectors |
| brainpool t1 (twisted) curves | not provided: no protocol this module serves uses them (TLS, IEC 62351 and BSI TR-03109 name the r1 curves) |
| SCRAM-SHA-1, -SHA-256, -SHA-512 | done, client and server, on github.com/xdg-go/scram; RFC 5802 and RFC 7677 example exchanges reproduced byte for byte; SCRAM-SHA-512 checked against an independent computation (its draft has no example) |
| SCRAM -PLUS (channel binding) | done: tls-unique, tls-server-end-point (RFC 5929), tls-exporter (RFC 9266), over real TLS 1.2 and 1.3 connections; client checked against PostgreSQL 17's SCRAM-SHA-256-PLUS |
| SASLprep (RFC 4013) | done, on by default; RFC 4013's examples; a string SASLprep refuses is used as given, as PostgreSQL does |

## Choosing a Go package for these

Compared from each package's source at the versions named, in October
2026. Neither Go 1.27.1's standard library nor golang.org/x/crypto
v0.58.0 has CCM, KMAC, AES-MMO, the Koblitz curves, ECQV, ECMQV or the
brainpool curves; both have cSHAKE, on which KMAC is built. Check the
projects themselves before relying on a row.

| Need | this module | Other Go packages |
|---|---|---|
| AES-CCM with any nonce (7 to 13 bytes) and tag (4 to 16, even), as `cipher.AEAD` | `ccm`, no dependencies | pion/dtls/v3 v3.1.10 `pkg/crypto/ccm`: same range, inside the DTLS module (pion/logging, pion/transport). emmansun/gmsm v0.45.0 `cipher.NewCCMWithNonceAndTagSize`: same range, inside a ShangMi (SM2/SM3/SM4) suite |
| KMAC128, KMAC256, KMACXOF | `kmac`: streaming `hash.Hash` and XOF `io.Reader` | roseh.moe/pkg/kmac v1.1.0 (github.com/rhogenson/kmac): one-shot functions on crypto/sha3; its README advises against using it |
| Zigbee AES-MMO hash | `aesmmo` | none found |
| sect163k1, sect283k1 | `koblitz`, constant-time ladder | RyuaNerin/elliptic2 v1.3.0: both curves as `elliptic.Curve`; its README says it is not constant-time |
| ECQV implicit certificates, ECMQV | `ecqv`, `ecmqv` (Smart Energy suites 1 and 2) | none found in Go |
| brainpoolP256r1/P384r1/P512r1 | `brainpool`: constant-time, ECDH shaped like crypto/ecdh, ECDSA shaped like crypto/ecdsa (DER and P1363), compressed points, Wycheproof vectors, X.509 certificates, PKCS #10 requests, PKCS #8 and SEC 1 keys; depends on golang.org/x/crypto | fabianmathias/gobrainpool v1.2.0: constant-time, ECDSA and ECDH with opaque curve handles and byte-only keys (no `big.Int` anywhere in its API), Wycheproof ECDSA vectors, no X.509 or key encodings, Apache-2.0, depends on golang.org/x/crypto; it calls itself a hobby project. ProtonMail/go-crypto v1.5.2 `brainpool`: r1 and t1 curves as `elliptic.CurveParams` on math/big, which Go does not keep constant-time; no ECDSA or X.509 of its own |
| SCRAM-SHA-1/-256/-512 and -PLUS | `sasl`: a two-step server (passwords or stored keys), RFC 6120 failure names, SASLprep on by default with a fallback, channel-binding helpers for the three TLS bindings, mechanism choice; over xdg-go/scram | xdg-go/scram v1.2.0 (Apache-2.0) used directly: client and server conversations, SASLprep, channel binding (-PLUS); SHA-1, SHA-256 and SHA-512 hash functions; one channel binding type per server conversation, as here |

Pick this module when one protocol needs several of these together,
above all Zigbee Smart Energy key establishment (AES-MMO, the Koblitz
curves, ECQV, ECMQV), which no other Go package found covers, or IEC
62351 work that needs brainpool certificates and requests through
crypto/x509. Pick pion/dtls's `ccm` if you already depend on pion, or
gmsm's if you also need SM4-CCM. Pick gobrainpool if you want brainpool
ECDSA and ECDH behind an API with no `big.Int` at all (this module's ECDSA
keys are `*ecdsa.PublicKey`, so that crypto/x509 can carry them), or need
the curve code under Apache-2.0 rather than BSD-3-Clause; pick
ProtonMail/go-crypto if you need the t1 curves and can accept arithmetic
that is not constant time. Use xdg-go/scram directly if you want its
conversation objects with nothing in between; this module adds the
two-step server, stored-key lookup, the channel-binding helpers and the
SASLprep fallback on top of it.

## Install

```sh
go get github.com/cB-Sigma/iotcrypto@latest
```

Requires Go 1.26.0 or later (the `go` line of go.mod).

## Quick start

Seal and open a message with AES-128-CCM, a 13-byte nonce and an 8-byte tag
(from `ExampleNew` in ccm/example_test.go):

```go
import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/cB-Sigma/iotcrypto/ccm"
)

func main() {
	key := bytes.Repeat([]byte{0x40}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := ccm.New(block, 13, 8)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize()) // never reuse a nonce with one key
	header := []byte("header")
	sealed := aead.Seal(nil, nonce, []byte("meter reading 42"), header)
	plain, err := aead.Open(nil, nonce, sealed, header)
	fmt.Printf("%s %v\n", plain, err) // meter reading 42 <nil>
}
```

Every package has a runnable example in its `example_test.go`.

## Documentation

API reference: [pkg.go.dev/github.com/cB-Sigma/iotcrypto](https://pkg.go.dev/github.com/cB-Sigma/iotcrypto).
The package list is in [Packages](#packages) above. PROVENANCE.md lists the
standards each package follows and where every test vector comes from.

## Testing

```sh
go vet ./...
go test -race ./...
```

The OpenSSL interop tests run when `openssl` is installed, and the
PostgreSQL interop test of `sasl` when `initdb` and `postgres` are; each is
skipped otherwise (the PostgreSQL one also with `-short`). The timing tests
of `koblitz` and `brainpool` run only with `SIGMA_DUDECT=1`. The Wycheproof files are
stored gzipped under each package's testdata/wycheproof.

Every parser has a fuzz target: `ccm` FuzzOpen, `sasl` FuzzServer and
FuzzClient, `brainpool` FuzzParsePublicKey (points, keys, certificates,
requests), `ecqv` FuzzParse. Run one with, for example,
`go test -run XXX -fuzz FuzzServer ./sasl`.

Tests carry `// Covers: SIG-...` comments. These are requirement IDs of the
SigmaM2M project's compliance report and have no meaning outside it.

### Interop tested against

- OpenSSL, the version installed where the tests run (brainpool parameters,
  keys including compressed ones, signatures both ways, ECDH, certificate
  chains, certificate requests).
- PostgreSQL 17 (`sasl`): SCRAM-SHA-256-PLUS with tls-server-end-point over
  TLS 1.2 and 1.3, a password that needs SASLprep, and refusal of a wrong
  binding.
- Python cryptography's AESCCM (ccm/testdata/reference.json and one value in
  TestTLSShape), and Python's hashlib and hmac for the SCRAM-SHA-512 and
  -PLUS exchanges in sasl/plus_test.go.
- Wycheproof (C2SP) vectors for AES-CCM, KMAC and brainpool ECDSA and ECDH,
  and other published vectors (see PROVENANCE.md).

Not yet tested against a Zigbee Smart Energy device, a commercial ECQV CA,
or a SCRAM -PLUS server other than PostgreSQL (so tls-unique and
tls-exporter are checked between this package's client and server only).

## Performance

`go test -run XXX -bench . ./...`; Go 1.26.2, Apple M4 Pro, one core per
operation:

| Operation | Time |
|---|---|
| AES-128-CCM seal, 1 KiB (13-byte nonce, 8-byte tag) | 1.4 µs (about 740 MB/s) |
| KMAC256 of 1 KiB, 64-byte tag | 1.7 µs |
| brainpoolP256r1 / P384r1 / P512r1 ECDH | 0.42 / 0.89 / 1.6 ms |
| brainpoolP256r1 / P384r1 / P512r1 ECDSA sign | 0.45 / 0.96 / 1.7 ms |
| brainpoolP256r1 / P384r1 / P512r1 ECDSA verify | 0.86 / 1.8 / 3.2 ms |
| sect163k1 / sect283k1 scalar multiplication | 0.14 / 0.29 ms |
| ECMQV shared secret, sect163k1 / sect283k1 | 0.24 / 0.58 ms |

The curve code is generic constant-time Go on bigmod, several times slower
than the standard library's assembly-backed NIST curves; it is fast enough
for handshakes and certificate work, not for bulk signing.

## Side channels

- `ccm`: tags are compared with crypto/subtle; a failed Open clears its
  output. The block cipher is the caller's: Go's crypto/aes is constant
  time where the CPU has AES instructions (amd64, arm64, s390x, ppc64) and
  uses lookup tables elsewhere.
- `kmac`: SHA-3 has no secret-dependent branches or lookups; compare tags
  with crypto/hmac.Equal.
- `koblitz`, `ecmqv`, `ecqv`: secret scalars go through a fixed-length
  ladder; a dudect-style test checks the timing (`SIGMA_DUDECT=1`).
- `brainpool`: the package documentation lists what is constant time (key
  generation, ECDH, signing) and what is not (verification, parsing, every
  `*big.Int` method, which must only see public data). A dudect-style test
  (`SIGMA_DUDECT=1`) times ECDH and signing with fixed against random
  secret scalars on all three curves; on an Apple M4 Pro with 3000
  measurements per class the largest |t| was 5.74 (brainpoolP512r1 ECDH,
  scalar 1 against random), below the threshold of 10.
- `sasl`: proofs and channel bindings are compared in constant time by
  xdg-go/scram; unknown users get a challenge like known ones (with stored
  credentials, a salt fixed per name), so answers do not tell which users
  exist. PBKDF2 cost is the iteration count; the client refuses counts
  above `Options.MaxIterations` (default 1,000,000).
- `bigmod`: Go's constant-time modular arithmetic.

## Dependencies

- golang.org/x/crypto (BSD-3-Clause), for brainpool (cryptobyte).
- github.com/xdg-go/scram and github.com/xdg-go/stringprep (Apache-2.0),
  for sasl, with golang.org/x/text (BSD-3-Clause). All pure Go.

## Cryptography notice

This repository contains publicly available encryption source code. Every
algorithm in it implements a published standard:

| Package | Standard |
|---|---|
| `ccm` | AES-CCM: RFC 3610, NIST SP 800-38C |
| `kmac` | KMAC and KMACXOF: NIST SP 800-185 |
| `aesmmo` | Matyas-Meyer-Oseas hash over AES: Zigbee specification 05-3474 annex B.6, Zigbee Smart Energy 1.4a |
| `koblitz` | sect163k1 and sect283k1: SEC 2 v2.0; point encodings: SEC 1 v2.0 |
| `ecqv` | ECQV implicit certificates: SEC 4 v1.0 |
| `ecmqv` | ECMQV: SEC 1 v2.0 |
| `brainpool` | brainpool curves: RFC 5639, RFC 7027, RFC 8734; ECDSA and ECDH as in SEC 1 v2.0; deterministic nonces: RFC 6979 |
| `sasl` | SCRAM: RFC 5802, RFC 7677, draft-melnikov-scram-sha-512; channel bindings: RFC 5929, RFC 9266; SASLprep: RFC 4013 |
| `bigmod` | modular arithmetic for the above |

The code has not been validated under FIPS 140 or any other certification
programme. The import, export and use of encryption software are regulated
in some countries. If you use, copy or redistribute this code, you are
responsible for following the rules that apply to you. This notice is not
legal advice.

## Related repositories

- [iotsec](https://github.com/cB-Sigma/iotsec): the security seams
  (TLS profile, audit, keys, crypto policy) that SigmaM2M's protocol
  libraries take from an application.

## Status

v0.x. The API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)), Copyright 2026 Abhinav Gautam. The
`ccm`, `brainpool` and `bigmod` directories are under the BSD-3-Clause
licence, each with its own LICENSE file, because they contain or are shared
with code from Go; [NOTICE](NOTICE) lists every file under another licence
and every third-party credit.
