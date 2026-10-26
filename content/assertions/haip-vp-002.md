---
id: haip-vp-002
name: Independently issued SD-JWT VCs validate to a configured trust anchor
protocols:
  - oid4vp
use_cases:
  - credential-presentation
actors:
  - verifier
  - issuer
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
  - key-management
related_concepts:
  - jwt
normative_level: MUST
normative_anchors:
  - rfc: HAIP 1.0
    sections: ["6.1.1"]
assertion_text: >-
  Independently issued SD-JWT VCs are accepted only after their issuer
  signature and leaf-only x5c chain validate to an explicitly configured
  trust anchor.
summary: The verifier accepts an SD-JWT VC from an issuer it has no record of only when the credential's x5c chain validates to a trust anchor the operator configured.
aliases:
  - sd-jwt vc x5c trust anchor
  - external issuer trust
  - issuer certificate key resolution
---
## What this requires

HAIP 1.0 Section 6.1.1 states: "This specification mandates the support for X.509 certificate-based key resolution to validate the issuer signature of an SD-JWT VC." It goes on: "The SD-JWT VC MUST contain the credential issuer's signing certificate along with a trust chain in the x5c JOSE header parameter as described in section 3.5 of [I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header of the SD-JWT VC."

For a verifier this means the issuer's public key comes from the leaf certificate in the issuer-signed JWT's `x5c` header. That key is used only after the chain has been validated to a root the verifier already trusts. A credential whose chain does not reach one of those roots is not accepted.

## Why it exists

HAIP does not give a reason in the text. Without this rule, an SD-JWT VC that carries its own `x5c` would describe its own trust: any party could mint a certificate, sign a credential with it, and present it. Validating the chain to an anchor chosen by the verifier's operator turns "this credential is signed" into "this credential is signed by an issuer this verifier trusts".

## What non-compliance looks like

A verifier takes the leaf key from `x5c` and checks the JWT signature, but never validates the chain. A self-made issuer then passes. A softer failure is a verifier that accepts an `x5c` whose last entry is the self-signed root and builds trust from that root instead of from its own store.

## How ProtocolSoup tests it

Credentials that ProtocolSoup's own issuer minted are checked against the issuer key recorded at issuance. A `dc+sd-jwt` credential with no stored lineage takes the external path. If neither `OID4VP_SD_JWT_TRUST_ANCHOR_PEM` nor `OID4VP_SD_JWT_TRUST_ANCHOR_PEM_FILE` is set, the presentation fails with policy reason `missing_lineage`. Otherwise `externalSDJWTIssuerJWK` parses `x5c` and rejects an empty array. It rejects any self-signed CA certificate in the array with "issuer x5c must exclude the trust anchor", then validates the chain against the configured pool at the current time. The leaf key is then used to verify the issuer signature. Any failure on this path is reported as `credential_signature_invalid`. Intermediates after the leaf are accepted; only the anchor is refused.

`TestExternalSDJWTIssuerRequiresTrustedLeafOnlyX5C` configures a root pool and signs an SD-JWT VC with a leaf-only `x5c`. It asserts that the resolved key verifies the credential. It then signs one with `[leaf, root]` and asserts an error containing "exclude the trust anchor". The test does not cover a chain to an unconfigured root, the missing-anchor case, or the handler that emits the policy reasons.
