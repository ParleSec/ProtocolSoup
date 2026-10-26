---
id: sdjwt-000
name: Trailing tilde not omitted when there is no Key Binding JWT
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
    sections: ["4"]
assertion_text: >-
  In the case that there is no Key Binding JWT, the last element MUST be an
  empty string and the last separating tilde character MUST NOT be omitted.
summary: An SD-JWT without a Key Binding JWT always ends in a tilde, even when it carries no Disclosures.
aliases:
  - sd-jwt trailing tilde
  - sd-jwt compact serialization
  - missing final tilde
---
## What this requires

The compact SD-JWT is the Issuer-signed JWT, a tilde, and each Disclosure followed by a tilde, so `issuer-jwt~D.1~D.2~`. RFC 9901 Section 4 states: "In the case that there is no Key Binding JWT, the last element MUST be an empty string and the last separating tilde character MUST NOT be omitted." An SD-JWT with no Disclosures is therefore `issuer-jwt~`, never the bare JWT.

When a KB-JWT is present it takes the place of that empty last element: `issuer-jwt~D.1~KB-JWT`.

## Why it exists

The final tilde is how the two formats are told apart. Section 4 says "The two formats can be distinguished by the final ~ character that is present on an SD-JWT" and "A Verifier that expects an SD-JWT MUST verify that the final tilde-separated component is empty." Without the tilde, the last Disclosure and a KB-JWT occupy the same position and a parser has to guess which one it is holding.

The string with the trailing tilde is also what the KB-JWT signs over. Section 4.3.1 computes `sd_hash` over "the Issuer-signed JWT, a tilde character, and zero or more Disclosures selected for presentation to the Verifier, each followed by a tilde character". A Holder and Verifier that disagree about the trailing tilde compute different `sd_hash` values for the same presentation.

## What non-compliance looks like

An Issuer returns `issuer-jwt~D.1~D.2` from the Credential Endpoint, or a bare JWT with no tilde at all. A lenient parser treats the last segment as a Disclosure; a strict one rejects the credential, and one that keys on position may try to verify `D.2` as a KB-JWT.

## How ProtocolSoup tests it

`BuildSDJWTSerialization` appends the trailing tilde whenever no KB-JWT is passed. The OID4VCI SD-JWT issuer uses it for every issued credential, and the OID4VP verifier uses it to rebuild the SD-JWT that `sd_hash` is checked against. `ParseSDJWTEnvelope` rejects a value with no tilde separator, and rejects a value whose last segment is neither empty nor JWT-shaped (two dots) with "sd-jwt compact serialization without a key binding jwt must end with a tilde".

`TestSDJWTCompactSerializationRequiresTrailingTildeWithoutKBJWT` asserts that `BuildSDJWTSerialization("issuer.jwt.value", ["disclosure"], "")` returns `issuer.jwt.value~disclosure~`, that `ParseSDJWTEnvelope` rejects `issuer.jwt.value` with no tilde, and that the serialised form parses back into one Issuer-signed JWT and one Disclosure. It does not present a value that drops only the final tilde; that case, `issuer.jwt.value~disclosure`, is covered by `TestParseSDJWTEnvelopeRejectsNonCanonicalSeparators`.
