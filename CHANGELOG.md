# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 a minor version may change the API, but v0.2.0 only adds to it.

## v0.2.0 (2026-10-11)

### Added

- `sasl`: SCRAM-SHA-512 (draft-melnikov-scram-sha-512) and the -PLUS
  mechanisms SCRAM-SHA-1-PLUS, SCRAM-SHA-256-PLUS and SCRAM-SHA-512-PLUS.
- `sasl`: channel bindings `TLSExporterBinding` (RFC 9266),
  `TLSUniqueBinding` and `TLSServerEndPointBinding` (RFC 5929), and
  `TLSBinding`, which picks the default for the TLS version.
  `TLSServerEndPointBinding` reads only the certificate's signature
  algorithm, so it works with brainpool certificates too.
- `sasl`: `Options` and the functions that take it: `ClientWith`,
  `ServerWith`, `NewScramServerWith`, and `NewStoredScramServer` with
  `Credentials` and `NewCredentials` for servers that keep salted keys
  instead of passwords.
- `sasl`: `SASLprep`, `Mechanisms`, `Choose` and `IsPlus`.
- `kmac`: KMACXOF128 and KMACXOF256 (`XOF`, `NewXOF128`, `NewXOF256`,
  `SumXOF128`, `SumXOF256`).
- `brainpool`: key agreement shaped like crypto/ecdh (`ECDHCurve`,
  `ECDHP256r1`, `ECDHP384r1`, `ECDHP512r1`, `ECDHCurveFor`,
  `ECDHPrivateKey`, `ECDHPublicKey`).
- `brainpool`: functions shaped like crypto/ecdsa: `SignASN1`,
  `VerifyASN1`, `ParseRawPrivateKey`, `ParseUncompressedPublicKey`,
  `PublicKeyBytes`, `PrivateKey.ECDH`, `PrivateKey.Equal`,
  `PrivateKey.PublicKey`; IEEE P1363 signatures (`SignP1363`,
  `VerifyP1363`); compressed points (`ParsePublicKey`,
  `MarshalCompressed`).
- Tests: Project Wycheproof vectors for AES-CCM (552), KMAC (435),
  brainpool ECDSA (4002, SHA-2 and SHA-3, DER and P1363) and ECDH (2534);
  NIST's KMACXOF samples; RFC 4013's SASLprep examples; SCRAM -PLUS over
  real TLS 1.2 and 1.3 connections; interop with PostgreSQL's
  SCRAM-SHA-256-PLUS; fuzz targets for CCM, the SCRAM client and server
  and the brainpool parsers; a dudect-style timing test of brainpool ECDH
  and signing (`SIGMA_DUDECT=1`); benchmarks.
- README: performance and side-channel sections.

### Changed

- `sasl`: user names and passwords are prepared with SASLprep by default,
  as RFC 5802 asks. A string SASLprep refuses or empties is used as given,
  so every password that worked between this package's client and server
  still does; only passwords that SASLprep changes (non-ASCII spaces, soft
  hyphens, compatibility characters) now also match their prepared form,
  as other SCRAM implementations expect. `Options{NoSASLprep: true}`
  restores the old behaviour.
- `sasl`: `Hash` also knows the SCRAM-SHA-512 and -PLUS names, and
  `NewScramServer` accepts SCRAM-SHA-512. The default iteration count for
  SCRAM-SHA-512 is 10000, as its draft asks.
- `brainpool`: `ParsePKIXPublicKey` (and so certificate and request
  parsing) and the SEC 1 private-key parser (for the embedded public key)
  also accept compressed points, as OpenSSL writes them with
  `-conv_form compressed`. `ECDH` still takes only uncompressed ones, as
  TLS requires.
- `brainpool`: field additions and subtractions no longer copy their
  operands (about 10% faster).

### Not done

- brainpool t1 (twisted) curves: no protocol this module serves uses them.

## v0.1.1 (2026-10-11)

- README: comparison with the other Go packages.

## v0.1.0 (2026-10-11)

- First release: ccm, kmac, aesmmo, koblitz, ecqv, ecmqv, brainpool, sasl
  and bigmod.
