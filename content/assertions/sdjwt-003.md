---
id: sdjwt-003
name: Claim names _sd and ... cause SD-JWT rejection
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
    sections: ["4.1", "7.1"]
assertion_text: >-
  If the claim name is _sd or ..., the SD-JWT MUST be rejected.
summary: A Disclosure whose claim name is _sd or ... makes the whole SD-JWT invalid.
aliases:
  - reserved sd-jwt claim names
  - disclosure claim name _sd
---
## What this requires

An object-property Disclosure is the array `[salt, claim name, claim value]`. When a Holder or Verifier matches such a Disclosure to a digest in an `_sd` array, RFC 9901 Section 7.1 step 3.c.ii.2 states: "If the claim name is _sd or ..., the SD-JWT MUST be rejected." The whole SD-JWT is invalid, not just that one claim.

On the Issuer side, Section 4.1 says the payload "MUST NOT contain the claims _sd or ... except for the purpose of conveying digests", so an Issuer never creates a Disclosure with either name.

## Why it exists

`_sd` and `...` are the two structural keys of SD-JWT: `_sd` holds an object's digest array and `...` marks a hidden array element. A Disclosure that inserts a claim named `_sd` would place attacker-chosen content where the processor expects digests, and Section 7.1 step 3.e then removes all `_sd` keys from the result. A claim named `...` would turn an ordinary object into something that looks like an array-element marker. Either way the Processed SD-JWT Payload stops matching what the Issuer signed.

## What non-compliance looks like

A processor that inserts every disclosed claim by name, without checking reserved names, accepts a Disclosure such as `["salt", "_sd", ["digest"]]`. Depending on processing order, the inserted value either overwrites the real digest array or is silently stripped, and two implementations disagree about which claims the SD-JWT discloses.

## How ProtocolSoup tests it

`CreateSDJWTDisclosure` refuses to build a Disclosure named `_sd` or `...`. `DecodeSDJWTDisclosure`, which every received Disclosure passes through before digest matching in `ProcessSDJWTDisclosures`, rejects a three-element Disclosure with either name, so the SD-JWT fails before any claim is inserted. The check runs on every presented Disclosure, not only those matched to a digest; an unmatched Disclosure would be rejected anyway under Section 7.1 step 5. The claim name is whitespace-trimmed before the comparison.

`TestDecodeSDJWTDisclosureRejectsReservedClaimNames` asserts, for both `_sd` and `...`, that `CreateSDJWTDisclosure` returns an error and that a hand-built base64url Disclosure `["test-salt", name, "value"]` is rejected by `DecodeSDJWTDisclosure`.
