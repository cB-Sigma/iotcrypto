# Provenance

## How the code was written

The code was written for SigmaM2M from the published specifications listed
below. It was not ported from another implementation, with the exceptions
in NOTICE: Go's bigmod and sliceForAppend (copied), and the Go passages in
brainpool and ccm's tests (adapted, marked in each file). No specification
text is reproduced. Comments cite clause numbers only, in our own words.

## Specifications followed

| Package | Specifications (editions) |
|---|---|
| ccm | RFC 3610; NIST SP 800-38C |
| kmac | NIST SP 800-185 (KMAC128, KMAC256 and, since v0.2.0, KMACXOF128 and KMACXOF256 on cSHAKE) |
| aesmmo | Zigbee specification 05-3474, annex B.6 (Matyas-Meyer-Oseas hash); Zigbee Base Device Behavior 3.1, 6.11.1.2 (install codes); Zigbee Smart Energy 1.4a, C.4.2.2.6 and C.4.2.2.7 (hash and HMAC) |
| koblitz | SEC 2 v2.0, 3.2.1 and 3.5.1 (sect163k1, sect283k1); SEC 1 v2.0, 2.3.3 and 2.3.4 (point encodings); the x-only Montgomery ladder of Lopez and Dahab (CHES 1999) |
| ecqv | SEC 4 v1.0 (ECQV implicit certificates); Zigbee Smart Energy 1.4a, C.4.2.2.4 and C.4.2.3.3 (suite 1 and 2 certificates) |
| ecmqv | SEC 1 v2.0, 3.4 (ECMQV); Zigbee Smart Energy 1.4a, C.4.2.4.3 |
| brainpool | RFC 5639 (curves); RFC 7027 (TLS use, ECDH vectors); RFC 8734 (TLS 1.3 groups); RFC 6979 (deterministic nonces, used hedged); SEC 1 v2.0 2.3.3 and 2.3.4 (compressed points); RFC 5280, RFC 5480, RFC 5915, RFC 5208/5958 (encodings); IEEE P1363 signature layout; the complete addition formulas of Renes, Costello and Batina (EUROCRYPT 2016). The API of keys.go (v0.2.0) follows the method and function names of Go's crypto/ecdh and crypto/ecdsa; no code of theirs is copied |
| sasl | RFC 5802 (SCRAM), RFC 7677 (SCRAM-SHA-256), draft-melnikov-scram-sha-512-05 (SCRAM-SHA-512), RFC 4013 (SASLprep, through github.com/xdg-go/stringprep), RFC 5929 (tls-unique, tls-server-end-point), RFC 9266 (tls-exporter), RFC 4055 (RSASSA-PSS parameters, for tls-server-end-point). Moved here from SigmaM2M on 2026-10-06; the same day the SCRAM computation and message handling moved to github.com/xdg-go/scram v1.2.0 (Apache-2.0), with our error conditions, nonce and salt sizes and client checks kept in scram.go. v0.2.0 added SASLprep, the -PLUS mechanisms (binding.go is ours; xdg-go/scram's channel-binding constructors are not used), SCRAM-SHA-512 and stored credentials |
| bigmod | Go's crypto/internal/fips140/bigmod (see NOTICE) |

bigmod/testdata/mod_inv_tests.txt is identical to the file of the same
name in Go 1.26.2's crypto/internal/fips140/bigmod; NOTICE says what is
known about its origin.

## Test vectors and where they come from

Vectors are facts taken from the sources below and cited in the tests.

| Test | Source |
|---|---|
| ccm/testdata/rfc3610.json | RFC 3610 section 8, the 24 packet vectors, transcribed to JSON |
| */testdata/wycheproof/*.json.gz | Project Wycheproof (github.com/C2SP/wycheproof, Apache-2.0), testvectors_v1 at commit 12fd3aaf33eb5fa1f52e026912ee00c054f9d984 (2026-10-06), gzipped unchanged: ccm aes_ccm_test; kmac kmac128_no_customization_test and kmac256_no_customization_test; brainpool ecdh_brainpoolP{256,384,512}r1_test and ecdsa_brainpoolP256r1_sha256, P384r1_sha384, P512r1_sha512 (DER and _p1363) and the three _sha3_ files. Read by TestWycheproof (ccm, kmac), TestWycheproofECDSA and TestWycheproofECDH (brainpool) |
| kmac TestNISTXOFSamples | NIST's six KMACXOF sample computations for SP 800-185 (KMACXOF_samples) |
| sasl TestSASLprepRFC4013Examples | the examples of RFC 4013 section 3 |
| sasl TestPlusAndSHA512Vectors | computed with a short SCRAM written for the purpose in Python (hashlib.pbkdf2_hmac, hmac), not shipped, whose SCRAM-SHA-256 output equals RFC 7677's example; RFC 7677's user, password, nonces and salt, with SHA-512 and with channel binding data 00 01 .. 1F |
| sasl TestPostgreSQLInterop | live: PostgreSQL's server (17.11 when last run), started by the test in a temporary directory; skipped when absent |
| ccm TestTLSShape | one value computed with Python cryptography's AESCCM (independent implementation) |
| ccm/testdata/reference.json (TestReferenceVectors) | computed with Python cryptography 46.0.6 AESCCM (independent implementation): NIST SP 800-38C Appendix C examples 1 to 4 (the outputs equal the published ones), nonce lengths 7 to 13 with every even tag length 4 to 16 for 128-, 192- and 256-bit keys, and additional data of 0xFEFF, 0xFF00 and 70000 bytes |
| kmac TestNISTSamples | NIST's six KMAC sample computations for SP 800-185 (KMAC_samples) |
| aesmmo TestKnownAnswers | the install-code example of BDB 3.1 6.11.1.2; the key-derivation hashes of SE 1.4a C.5.3.3.3 and C.6.3.3.3 |
| koblitz TestSEC2Parameters | SEC 2 v2.0 curve parameters |
| koblitz key-pair tests | SE 1.4a C.5.1, C.5.3, C.6.1 and C.6.3 device and ephemeral keys; further keys generated with `openssl ecparam -genkey` |
| ecqv tests | SE 1.4a C.5.1 and C.6.1 preconfigured data (certificates, CA keys, device keys) |
| ecmqv TestSharedSecretVectors | SE 1.4a C.5.3 and C.6.3 key-establishment examples |
| brainpool | RFC 5639 parameters, cross-checked with OpenSSL's explicit parameters; RFC 7027 appendix A ECDH vectors; live OpenSSL interop tests (skipped when openssl is absent) |
| sasl TestScramClientVectors, TestScramServerVectors | the example exchanges of RFC 5802 section 5 (SCRAM-SHA-1) and RFC 7677 section 3 (SCRAM-SHA-256): nonces, salts and all four messages |
| bigmod/testdata/mod_inv_tests.txt | Go's test data (see NOTICE) |

The Zigbee Smart Energy and Base Device Behavior documents are published by
the Connectivity Standards Alliance. Only numeric example values (keys,
certificates, hashes) are used, as test inputs and expected outputs.

## Source notes referenced in comments

Some comments cite "F-nnnn". F-n refers to an entry in SigmaM2M's register
of specification defects and platform limits; that register is not
published, so the substance of each entry this module refers to is
described here:

- F-1500: in Zigbee Smart Energy 1.4a C.6.3.4.1 the suite 2 responder's
  ephemeral private key is larger than the order of sect283k1. The rest of
  the example (public key, shared secret, MACs) matches that value reduced
  modulo n, so the tests reduce it; keys this module generates are always
  below n.
- F-1024: the Go standard library cannot sign a PKCS #10 request with a
  brainpool key; brainpool.CreateCertificateRequest can.
