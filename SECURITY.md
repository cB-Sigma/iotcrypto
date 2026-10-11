# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's security
advisories:
[github.com/cB-Sigma/iotcrypto/security/advisories/new](https://github.com/cB-Sigma/iotcrypto/security/advisories/new).
Do not open a public issue, pull request or discussion for a suspected
vulnerability.

A useful report says which package and function are affected, the version
or commit, what you expected and what happened, and how to reproduce it
(a test or a short program is ideal).

## In scope

- Timing and other side channels in code that handles secrets: private
  keys, scalars, shared secrets, CCM keys and tags, SCRAM passwords and
  proofs.
- Incorrect results: wrong ciphertexts, tags, signatures, shared secrets,
  hashes or certificate values; accepting what should be refused, such as a
  forged CCM tag, an invalid signature, a point not on the curve or a
  malformed encoding; refusing valid input.
- Key and nonce misuse that the API makes easy or fails to catch, such as
  weak key or nonce generation, a missing length or range check, or
  documentation that leads to unsafe use.
- Panics or excessive resource use on untrusted input.

## Out of scope

- Problems in Go itself or in the dependencies listed in NOTICE; please
  report those to their projects. Tell us as well if this module needs a
  change because of one.
- Nonce reuse by a caller who chooses the nonces: AEAD nonces must be
  unique per key, as the documentation of `ccm.New` says.
- The absence of FIPS 140 or other certification (see the cryptography
  notice in README.md).

## Supported versions

Only the latest v0.x release receives fixes. There are no long-term support
branches before v1.

## What to expect

There is no bug bounty. We aim to acknowledge a report within a few working
days, to agree on the facts with you, and to publish a fix and an advisory
as soon as one is ready. We will credit you in the advisory unless you ask
us not to. Please give us a reasonable time to fix the problem before you
disclose it.
