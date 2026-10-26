---
id: sdjwt-004
name: SD-JWT rejected when a disclosure is not referenced by digest
protocols:
  - oid4vp
use_cases:
  - credential-presentation
actors:
  - verifier
  - wallet
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
related_concepts:
  - jwt
normative_level: MUST
normative_anchors:
  - rfc: RFC 9901
    sections: ["7.1", "7.3"]
assertion_text: >-
  If any Disclosure was not referenced by digest value in the
  Issuer-signed JWT (directly or recursively via other Disclosures), the
  SD-JWT MUST be rejected.
summary: A Verifier rejects an SD-JWT that carries a Disclosure whose digest the Issuer never committed to.
aliases:
  - uncommitted disclosure
  - unreferenced sd-jwt disclosure
  - injected disclosure
---
## What this requires

Every Disclosure the Holder presents must be committed to by the Issuer. RFC 9901 Section 7.1 step 5 states: "If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other Disclosures), the SD-JWT MUST be rejected." A digest counts as referenced when it appears in an `_sd` array or `...` marker of the Issuer-signed payload, or inside the value of another Disclosure that is itself referenced.

Section 7.3 requires the Verifier to perform the Section 7.1 checks on every presentation. One unreferenced Disclosure rejects the SD-JWT; the Verifier does not drop it and carry on.

## Why it exists

Disclosures are not signed by the Issuer; only their digests are. Section 9.2 warns that "Holders can manipulate the Disclosures by changing the values of the claims before sending them to the Verifier" and that "A naive Verifier that extracts all claim values from the Disclosures (without checking the hashes) and inserts them into the SD-JWT payload is vulnerable to this attack." Rejecting any Disclosure without a matching digest is what stops a Holder, or anyone in between, from adding claims the Issuer never made.

## What non-compliance looks like

A Holder appends a self-made Disclosure such as `["salt", "age_over_21", true]` to a genuine credential. A verifier that decodes all Disclosures into a claim map, or that silently skips unmatched ones but still reports them, shows the forged claim beside the real ones, under a valid Issuer signature.

## How ProtocolSoup tests it

`ProcessSDJWTDisclosures` tracks which presented Disclosures it inserted while walking the payload, and fails with "disclosure digest for claim ... is not referenced by the issuer payload" for any left over. The OID4VP verifier calls it in `evaluateSDJWTPresentation` and records a failure as the policy reason code `disclosure_invalid`.

`TestDecodeAndVerifyDisclosuresRejectsUncommittedDisclosure` asserts that `DecodeAndVerifyDisclosures` rejects a Disclosure when the digest allow list is empty and accepts it when its digest is listed. That helper is not called by the verifier. The end-to-end evidence is `TestDirectPostPolicyRejectsUncommittedSDJWTDisclosure`: it issues a real credential, appends an `uncommitted` Disclosure, builds a KB-JWT over the result, posts it to the `direct_post` response endpoint, and asserts the verification result has `allowed` false with reason code `disclosure_invalid`.
