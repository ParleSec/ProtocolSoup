---
id: mdoc-002
name: IssuerAuth requires tagged MobileSecurityObjectBytes and a valid MSO
protocols:
  - oid4vci
  - oid4vp
use_cases:
  - credential-issuance
  - credential-presentation
actors:
  - wallet
  - verifier
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["9.1.2.4"]
assertion_text: >-
  IssuerAuth verification requires tagged MobileSecurityObjectBytes and a
  valid MSO version, digest algorithm, document type, device key,
  namespaces, digests, and ordered validity interval.
summary: The IssuerAuth payload must be a CBOR tag 24 wrapped MSO, and the MSO's version, digestAlgorithm, docType, deviceKey, valueDigests and validityInfo must all check out.
aliases:
  - mobile security object
  - mso validation
  - issuerauth payload
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and describes what ProtocolSoup checks. IssuerAuth is a COSE_Sign1 whose payload is MobileSecurityObjectBytes: the MSO encoded as CBOR and wrapped in tag 24 (`#6.24(bstr .cbor MobileSecurityObject)`). A payload that is a bare, untagged MSO is refused.

Once the signature verifies, the decoded MSO must have `version` "1.0", `digestAlgorithm` "SHA-256", a non-empty `docType`, a `deviceKey` that is a valid public P-256 COSE_Key, and non-empty `valueDigests` with no empty namespace and every digest exactly 32 bytes. In `validityInfo` no timestamp may be zero, `signed` must be at or before `validFrom`, `validFrom` must be before `validUntil`, and an `expectedUpdate`, if present, must fall strictly after `signed` and before `validUntil`.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. The MSO is the only thing the issuer signs; every later check depends on it. If the verifier cannot rely on the digest algorithm it cannot recompute any `valueDigests`; a missing or malformed `deviceKey` leaves device authentication with nothing to verify against; and a validity interval that runs backwards makes any "is it current" decision meaningless. Accepting only the tag 24 form leaves one byte shape for the signed payload, so two verifiers cannot disagree about whether the same IssuerAuth is valid.

## What non-compliance looks like

A verifier that accepts either a tagged or a bare MSO accepts IssuerAuth from issuers that others reject. One that skips structural checks accepts an MSO whose `digestAlgorithm` it cannot compute, a `deviceKey` that contains the private scalar, or a `validFrom` equal to `validUntil`.

## How ProtocolSoup tests it

`VerifyIssuerSigned` validates the x5chain, verifies the COSE_Sign1 signature, then calls `decodeMSOFromPayload`, which requires tag 24, and `validateMobileSecurityObject`, which applies every check above, before it compares item digests and the current time.

`TestVerifyIssuerSignedRejectsBareMSOPayload` signs an MSO encoded without tag 24 and asserts verification fails. `TestVerifyIssuerSignedRejectsInvalidMSOFields` runs thirteen cases, each changing one field of an otherwise valid, correctly signed MSO: version "2.0", digest algorithm "SHA-384", empty `docType`, empty device key, device key with private material, empty `valueDigests`, empty namespace name, empty namespace digests, a 1-byte digest, `signed` after `validFrom`, `validFrom` equal to `validUntil`, and `expectedUpdate` equal to `signed` or to `validUntil`. Each asserts only that verification returns an error, not which check failed. Both tests call `VerifyIssuerSignedWithKey`, a variant that skips x5chain validation and has no production caller, but shares the same MSO decoding and validation functions.
