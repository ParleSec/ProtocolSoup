---
id: sdjwt-001
name: Same digest value not appearing more than once in the SD-JWT
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
normative_level: MUST NOT
normative_anchors:
  - rfc: RFC 9901
    sections: ["4.1", "7.1"]
assertion_text: The same digest value MUST NOT appear more than once in the SD-JWT.
summary: Every digest in an SD-JWT, in _sd arrays, array markers and recursive Disclosures, is unique, and a repeat rejects the whole SD-JWT.
aliases:
  - duplicate sd-jwt digest
  - repeated _sd digest
---
## What this requires

RFC 9901 Section 4.1 states: "The same digest value MUST NOT appear more than once in the SD-JWT." That covers every place a digest can sit: the `_sd` arrays of objects, `{"...": digest}` array-element markers, and digests carried inside the values of other Disclosures.

The Issuer meets it by never reusing a digest. The receiving side enforces it in Section 7.1 step 4: "If any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected."

## Why it exists

A digest is the Issuer's commitment to exactly one claim at exactly one position. If the same digest appears twice, one Disclosure satisfies both places, so a single claim name and value can be inserted into two different objects or arrays. The Holder and the Verifier then each have to decide which position counts, and two implementations can extract different Processed SD-JWT Payloads from the same signed bytes.

## What non-compliance looks like

An Issuer that builds `_sd` arrays from a reused salt, or copies a digest into a nested object, produces a payload such as a top-level `_sd` and a nested `_sd` both holding the same value. A verifier that collects digests into a set without checking for repeats accepts it and places the disclosed claim wherever its walk happens to reach first.

## How ProtocolSoup tests it

The Issuer draws a fresh 128-bit random salt for every Disclosure in `CreateSDJWTDisclosure`. On receipt, `ProcessSDJWTDisclosures`, which the OID4VP verifier and the wallet harness use, records every digest it meets in `_sd` arrays and `...` markers, including those inside recursively processed Disclosure values, and fails with "duplicate sd-jwt digest" on a repeat. It also rejects two presented Disclosures that hash to the same digest.

`TestSDJWTDisclosureDigestsRejectsDuplicateCommitment` passes a payload whose top-level `_sd` and nested `_sd` both contain `duplicate` to `SDJWTDisclosureDigests` and asserts the "duplicate sd-jwt digest" error. That function walks the Issuer-signed payload only and is not on the production verification path; no listed test exercises the duplicate check inside `ProcessSDJWTDisclosures`.
