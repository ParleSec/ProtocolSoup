---
id: sdjwt-002
name: Default _sd_alg of sha-256 when not present at the top level
protocols:
  - oid4vci
  - oid4vp
use_cases:
  - credential-issuance
  - credential-presentation
actors:
  - issuer
  - holder
  - wallet
  - verifier
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
related_concepts:
  - jwt
normative_level: MUST
normative_anchors:
  - rfc: RFC 9901
    sections: ["4.1.1"]
assertion_text: >-
  If the _sd_alg claim is not present at the top level, a default value of
  sha-256 MUST be used.
summary: An SD-JWT payload without a top-level _sd_alg claim has its Disclosure digests computed with sha-256.
aliases:
  - sd_alg default
  - sd-jwt hash algorithm
---
## What this requires

The `_sd_alg` claim names the hash algorithm the Issuer used to compute Disclosure digests. RFC 9901 Section 4.1.1 states: "If the _sd_alg claim is not present at the top level, a default value of sha-256 MUST be used." An Issuer may omit the claim, and a Holder or Verifier that finds no top-level `_sd_alg` hashes each Disclosure with SHA-256.

The same section adds: "To promote interoperability, implementations MUST support the sha-256 hash algorithm." The default is also the algorithm for `sd_hash` in the KB-JWT, which Section 4.3.1 defines as "the _sd_alg element in the Issuer-signed JWT or the default value".

## Why it exists

Digests are only comparable when both sides hash with the same function. Without a fixed default, a payload that omits `_sd_alg` leaves the Verifier to guess, and a wrong guess makes every honest Disclosure look uncommitted. Pinning the default to sha-256, which every implementation must support, removes the guess.

## What non-compliance looks like

A verifier that treats a missing `_sd_alg` as an error rejects valid SD-JWTs from Issuers that rely on the default. One that falls back to some other algorithm computes digests that never match, and reports every presented Disclosure as not referenced by the Issuer-signed JWT.

## How ProtocolSoup tests it

`sdJWTHashAlgorithm` returns `sha-256` when the payload has no `_sd_alg`. When the claim is present it must be a non-empty string without surrounding whitespace, and any value other than `sha-256` is rejected as "unsupported _sd_alg". `SDJWTDisclosureDigest` always hashes with SHA-256, which is consistent because that is the only accepted value. The ProtocolSoup Issuer always writes `"_sd_alg": "sha-256"` explicitly.

`TestSDJWTDisclosureDigestsExtractsNestedCommitments` asserts that `SDJWTDisclosureDigests` returns the two digests from a nested `_sd` array, and `TestSDJWTDisclosureDigestsRejectsUnsupportedAlgorithm` asserts that `"_sd_alg": "sha-512"` is rejected. The first sets `"_sd_alg": "sha-256"` explicitly, so neither listed test exercises the default for a payload with no `_sd_alg`. Other tests in the same file, such as `TestProcessSDJWTDisclosuresRejectsPermanentClaimCollision`, do process payloads without `_sd_alg` whose digests match only under SHA-256, which is indirect evidence.
