---
id: sdjwt-005
name: Recursive disclosure processing at committed positions
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
related_concepts:
  - jwt
normative_level: MUST
normative_anchors:
  - rfc: RFC 9901
    sections: ["4.1.1", "7.1"]
assertion_text: >-
  Disclosures are processed recursively at their committed object or array
  positions, while nested _sd_alg and permanent-claim collisions are
  rejected.
summary: Each Disclosure is inserted where its digest sits, its value is processed recursively, and nested _sd_alg or a clash with a plaintext claim rejects the SD-JWT.
aliases:
  - recursive disclosures
  - sd-jwt array element disclosure
  - processed sd-jwt payload
---
## What this requires

This row is ProtocolSoup's summary of several rules, not a single sentence from RFC 9901. Section 7.1 step 3 places each Disclosure at the position of its digest: an object-property Disclosure is inserted "at the level of the _sd key", an array-element Disclosure replaces the `{"...": digest}` element in place, and in both cases the value is recursively processed so that digests inside it are resolved too. Array markers without a matching Disclosure are removed, and the shape of each Disclosure must match its position (three elements for `_sd`, two for an array).

Two rejections go with it. Section 4.1.1 says `_sd_alg` "MUST NOT be used in any object nested within the payload", and Section 7.1 step 3.c.ii.3 states: "If the claim name already exists at the level of the _sd key, the SD-JWT MUST be rejected."

## Why it exists

Section 9.2 notes that without comparing digests a naive implementation "could not determine the correct place in a nested object where a claim needs to be inserted". A processor that flattens every disclosed claim into the payload root turns `address.city` into a top-level `city`, and an application then reads data from a place the Issuer never put it. The collision rule stops a Disclosure from replacing a claim the Issuer chose to sign in plaintext.

## What non-compliance looks like

A presentation with a recursive `address` Disclosure produces a payload with `city` at the root instead of under `profile.address`. A disclosed `name` silently replaces the plaintext `"name": "Alice"` in the same object. An `_sd_alg` inside a nested object is accepted, leaving two algorithm claims in one payload.

## How ProtocolSoup tests it

`ProcessSDJWTDisclosures` walks the payload, inserts each object-property Disclosure into the object that holds its digest and each array-element Disclosure at the marker's index, processes the inserted value recursively, drops unmatched markers, and removes `_sd` and `_sd_alg`. It rejects `_sd_alg` below the top level, a type mismatch between Disclosure and position, and a claim name already present in the target object.

`TestProcessSDJWTDisclosuresResolvesArrayElementsPositionally` presents one of two hidden `nationalities` elements and asserts the result is `["DE", "FR", "US"]`, with `_sd_alg` removed. `TestProcessSDJWTDisclosuresResolvesRecursiveObjectAtDigestPosition` asserts that `city` from a Disclosure nested inside the `address` Disclosure lands at `profile.address.city` and not at the root. `TestProcessSDJWTDisclosuresRejectsNestedSDAlg` asserts the "only at the top level" error for a nested `_sd_alg`, and `TestProcessSDJWTDisclosuresRejectsPermanentClaimCollision` asserts that a `name` Disclosure beside a plaintext `name` is rejected.
