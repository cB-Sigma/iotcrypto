# iotcrypto

Small cryptographic building blocks that IoT and utility protocols need and that Go's standard library does not have, in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iotcrypto.svg)](https://pkg.go.dev/github.com/cB-Sigma/iotcrypto) [![test](https://github.com/cB-Sigma/iotcrypto/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iotcrypto/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

It covers AES-CCM with any parameters, KMAC, the Zigbee AES-MMO hash, the
Koblitz curves sect163k1 and sect283k1 with ECQV implicit certificates and
ECMQV (Zigbee Smart Energy key establishment), the brainpool curves with
ECDSA, ECDH, keys, certificates and certificate requests, and SCRAM. No cgo.
It was written for SigmaM2M, a oneM2M platform, and is used in its
production code paths.

## Packages

| Package | What it does | Used for |
|---|---|---|
| `ccm` | AES-CCM as a `crypto/cipher.AEAD`, nonce 7 to 13 bytes, tag 4 to 16 bytes | wireless M-Bus, TLS CCM cipher suites, MQTT-SN, Matter |
| `kmac` | KMAC128 and KMAC256 (fixed output length) | IEC 62351-4 end-to-end security |
| `aesmmo` | Matyas-Meyer-Oseas hash over AES-128, and HMAC over it | Zigbee install codes, Smart Energy CBKE |
| `koblitz` | sect163k1 and sect283k1: point encodings, constant-time scalar multiplication, scalars modulo n | Smart Energy CBKE suites 1 and 2 |
| `ecqv` | ECQV implicit certificates, suite 1 (48 octets) and suite 2 (74 octets): parse, extract public key, rebuild private key, and a private CA | Smart Energy CBKE |
| `ecmqv` | the ECMQV shared secret on the Koblitz curves | Smart Energy CBKE |
| `brainpool` | brainpoolP256r1, P384r1, P512r1: ECDSA (hedged deterministic nonces), ECDH, PKIX, SEC 1 and PKCS #8 keys, X.509 certificates and PKCS #10 requests | IEC 62351, TLS with brainpool curves (RFC 7027) |
| `sasl` | SCRAM-SHA-1 and SCRAM-SHA-256 (RFC 5802, RFC 7677) without channel binding: a client and a two-step server, over github.com/xdg-go/scram | MQTT-SN 2.0 AUTH, XMPP |
| `bigmod` | constant-time modular arithmetic (Go's internal bigmod, exported) | the curves above, finite-field Diffie-Hellman |

`bigmod` is low level and exists for the other packages; its API follows
Go's internal package and may change with it.

## Support matrix

| Feature | Status |
|---|---|
| CCM, any nonce and even tag length (RFC 3610, NIST SP 800-38C) | done; all 24 RFC 3610 vectors, NIST SP 800-38C Appendix C examples 1 to 4, and 297 reference values covering every nonce and tag length |
| KMAC128/256 (NIST SP 800-185) | done; NIST samples. The XOF variant is not provided |
| AES-MMO hash and HMAC | done; Zigbee BDB and Smart Energy known answers |
| sect163k1/sect283k1 (SEC 2) | done; constant-time ladder for secrets, checked with a dudect-style timing test (`SIGMA_DUDECT=1`) |
| ECQV suites 1 and 2 (SEC 4) | done; Smart Energy 1.4a annex vectors. Other ECQV profiles are not |
| ECMQV (SEC 1) | done; Smart Energy 1.4a annex vectors |
| brainpool r1 curves (RFC 5639) | done; RFC 7027 vectors and OpenSSL interop. The t1 (twisted) curves are not |
| SCRAM-SHA-1, SCRAM-SHA-256 | done, client and server, on github.com/xdg-go/scram; RFC 5802 and RFC 7677 example exchanges reproduced byte for byte; no -PLUS (channel binding) variants, no SASLprep (passwords compared as given) |

## Choosing a Go package for these

Compared from each package's source at the versions named, in October
2026. Neither Go 1.27.1's standard library nor golang.org/x/crypto
v0.58.0 has CCM, KMAC, AES-MMO, the Koblitz curves, ECQV, ECMQV or the
brainpool curves; both have cSHAKE, on which KMAC is built. Check the
projects themselves before relying on a row.

| Need | this module | Other Go packages |
|---|---|---|
| AES-CCM with any nonce (7 to 13 bytes) and tag (4 to 16, even), as `cipher.AEAD` | `ccm`, no dependencies | pion/dtls/v3 v3.1.10 `pkg/crypto/ccm`: same range, inside the DTLS module (pion/logging, pion/transport). emmansun/gmsm v0.45.0 `cipher.NewCCMWithNonceAndTagSize`: same range, inside a ShangMi (SM2/SM3/SM4) suite |
| KMAC128, KMAC256 | `kmac` | roseh.moe/pkg/kmac v1.1.0 (github.com/rhogenson/kmac): one-shot functions on crypto/sha3; its README advises against using it |
| Zigbee AES-MMO hash | `aesmmo` | none found |
| sect163k1, sect283k1 | `koblitz`, constant-time ladder | RyuaNerin/elliptic2 v1.3.0: both curves as `elliptic.Curve`; its README says it is not constant-time |
| ECQV implicit certificates, ECMQV | `ecqv`, `ecmqv` (Smart Energy suites 1 and 2) | none found in Go |
| brainpoolP256r1/P384r1/P512r1 | `brainpool`: constant-time, ECDSA, ECDH, X.509 certificates, PKCS #10 requests, PKCS #8 and SEC 1 keys | fabianmathias/gobrainpool v1.2.0: constant-time, ECDSA and ECDH, Wycheproof vectors, no X.509 or key encodings; it calls itself a hobby project. ProtonMail/go-crypto v1.5.2 `brainpool`: r1 and t1 curves as `elliptic.CurveParams` on math/big, which Go does not keep constant-time; no ECDSA or X.509 of its own |
| SCRAM-SHA-1, SCRAM-SHA-256 | `sasl`, a two-step server and RFC 6120 failure names over xdg-go/scram | xdg-go/scram v1.2.0 (Apache-2.0) used directly: client and server conversations, SASLprep, channel binding (-PLUS) |

Pick this module when one protocol needs several of these together,
above all Zigbee Smart Energy key establishment (AES-MMO, the Koblitz
curves, ECQV, ECMQV), which no other Go package found covers, or IEC
62351 work that needs brainpool certificates and requests through
crypto/x509. Pick pion/dtls's `ccm` if you already depend on pion, or
gmsm's if you also need SM4-CCM. Pick gobrainpool for brainpool ECDSA and
ECDH alone with an API in the style of crypto/ecdh. Use xdg-go/scram
directly when you need SASLprep or channel binding.

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

The OpenSSL interop tests run when `openssl` is installed and are skipped
otherwise. The timing test of `koblitz` runs only with `SIGMA_DUDECT=1`.

Tests carry `// Covers: SIG-...` comments. These are requirement IDs of the
SigmaM2M project's compliance report and have no meaning outside it.

### Interop tested against

- OpenSSL, the version installed where the tests run (brainpool parameters,
  keys, signatures both ways, ECDH, certificate chains, certificate
  requests).
- Python cryptography's AESCCM (ccm/testdata/reference.json and one value in
  TestTLSShape).
- Published vectors (see PROVENANCE.md).

Not yet tested against a Zigbee Smart Energy device or a commercial ECQV
CA.

## Dependencies

- golang.org/x/crypto (BSD-3-Clause), for brainpool.
- github.com/xdg-go/scram (Apache-2.0), for sasl, which brings in
  github.com/xdg-go/stringprep (Apache-2.0) and golang.org/x/text
  (BSD-3-Clause). All pure Go.

## Cryptography notice

This repository contains publicly available encryption source code. Every
algorithm in it implements a published standard:

| Package | Standard |
|---|---|
| `ccm` | AES-CCM: RFC 3610, NIST SP 800-38C |
| `kmac` | KMAC: NIST SP 800-185 |
| `aesmmo` | Matyas-Meyer-Oseas hash over AES: Zigbee specification 05-3474 annex B.6, Zigbee Smart Energy 1.4a |
| `koblitz` | sect163k1 and sect283k1: SEC 2 v2.0; point encodings: SEC 1 v2.0 |
| `ecqv` | ECQV implicit certificates: SEC 4 v1.0 |
| `ecmqv` | ECMQV: SEC 1 v2.0 |
| `brainpool` | brainpool curves: RFC 5639, RFC 7027; ECDSA and ECDH as in SEC 1 v2.0; deterministic nonces: RFC 6979 |
| `sasl` | SCRAM: RFC 5802, RFC 7677 |
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
