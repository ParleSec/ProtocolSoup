---
id: oid4vci
name: OpenID for Verifiable Credential Issuance
use_cases:
  - credential-issuance
  - discovery
actors:
  - issuer
  - holder
  - wallet
  - authorization-server
patterns:
  - back-channel
  - pre-authorized
  - qr-code-handoff
  - signed-assertion
  - key-bound
  - metadata-discovery
problem_domains:
  - verifiable-credentials
  - authorization
  - key-management
related_concepts:
  - jwt
  - jwks
normative_anchors:
  - rfc: OpenID4VCI 1.0
    sections: ["3", "4", "6", "8", "9", "13"]
  - rfc: RFC 9449
    sections: ["4", "5"]
status: live
href: /protocol/oid4vci
summary: Issues verifiable credentials to a wallet via OpenID-based flows.
aliases:
  - vci
  - credential offer
---

OpenID for Verifiable Credential Issuance (OID4VCI) profiles OAuth 2.0 so an
authorised issuer can deliver a verifiable credential to a holder's wallet. It
supports authorisation code and pre-authorised code grants, credential offers
delivered out-of-band (typically by QR), nonce-bound proof of key possession,
and deferred issuance for credentials that require manual approval. The token
endpoint also accepts an optional DPoP proof header (RFC 9449) that binds the
issued access token to a proof-of-possession key instead of a plain bearer
token.
