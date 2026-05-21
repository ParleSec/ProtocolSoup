---
id: oid4vp
name: OpenID for Verifiable Presentations
use_cases:
  - credential-presentation
  - user-login-via-own-idp
actors:
  - verifier
  - holder
  - wallet
patterns:
  - front-channel-redirect
  - out-of-band
  - signed-assertion
  - nonce-bound
  - qr-code-handoff
  - attestation-bound
problem_domains:
  - verifiable-credentials
  - authentication
related_concepts:
  - dcql
  - did-web
  - jwt
normative_anchors:
  - rfc: OpenID4VP 1.0
    sections: ["5", "6.1", "8.2", "8.3", "14"]
status: live
href: /protocol/oid4vp
summary: Requests and verifies verifiable presentations from a wallet.
aliases:
  - vp
---

OpenID for Verifiable Presentations (OID4VP) defines how a verifier requests
a presentation from a holder's wallet using DCQL (Digital Credentials Query
Language) and receives the presentation via direct_post or direct_post.jwt.
Trust between verifier and wallet is established via client_id_scheme values
including redirect_uri, verifier_attestation, and x509_san_dns.
