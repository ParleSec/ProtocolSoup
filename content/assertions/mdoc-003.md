---
id: mdoc-003
name: Duplicate element identifiers rejected and value digests verified
protocols:
  - oid4vci
  - oid4vp
use_cases:
  - credential-issuance
  - credential-presentation
actors:
  - issuer
  - wallet
  - verifier
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["9.1.2.3"]
assertion_text: >-
  IssuerSigned namespaces reject duplicate element identifiers and verify
  every value digest.
summary: Each namespace may hold an elementIdentifier only once, and every presented IssuerSignedItem must hash to its valueDigests entry in the MSO.
aliases:
  - mdoc value digests
  - duplicate elementIdentifier
  - issuersigneditem digest
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and describes ProtocolSoup's behaviour. Each IssuerSigned namespace is a list of IssuerSignedItemBytes, and each item carries a `digestID`, a `random` salt, an `elementIdentifier` and an `elementValue`. Within one namespace no `elementIdentifier` may appear twice. ProtocolSoup also refuses a repeated `digestID` in a namespace.

Every presented item is verified: its namespace must exist in the MSO `valueDigests`, its `digestID` must have an entry there, and the SHA-256 digest of the item's full tag 24 encoded bytes must equal that entry. Digests in the MSO with no presented item are not an error; those elements were simply not disclosed.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. The issuer signs only the MSO, so a digest match is the only thing that ties a presented element value to the issuer. Skipping any item lets an unverified value through beside verified ones. Two items with the same `elementIdentifier` force the verifier to choose which `family_name` is the real one, and two verifiers can choose differently, even when both items have valid digests.

## What non-compliance looks like

A verifier that loads items into a map keyed by `elementIdentifier` keeps whichever duplicate comes last, so a namespace containing `family_name` "Smith" and `family_name` "Jones" is read as one or the other. A verifier that checks only the elements its request asked for passes a tampered item that was disclosed but not requested.

## How ProtocolSoup tests it

On issuance, `BuildIssuerNameSpaces` and `BuildValueDigests` refuse duplicate `elementIdentifier` and `digestID` values. On receipt, `VerifyValueDigests`, called from `VerifyIssuerSigned`, applies the duplicate checks and recomputes the digest of every item, failing with "digest mismatch" on any difference. `CollectDisclosedElements` also refuses duplicates when it builds the disclosed claim map.

`TestVerifyValueDigestsRejectsDuplicateElementIdentifier` builds two `family_name` items with different `digestID` values, gives both correct digests, and asserts `VerifyValueDigests` rejects them. `TestBuildIssuerNameSpacesRejectsDuplicateElementIdentifier` asserts that the issuer-side builder rejects the same pair. Neither listed test covers the digest half of the statement; `TestVerifyValueDigestsDetectsTamper`, which flips a byte in an item and asserts rejection, does but is not listed.
