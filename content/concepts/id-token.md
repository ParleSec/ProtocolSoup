---
id: id-token
name: ID Token
protocols:
  - oidc
use_cases:
  - user-login-via-own-idp
  - single-sign-on
  - step-up-authentication
actors:
  - identity-provider
  - relying-party
patterns:
  - signed-assertion
  - nonce-bound
  - audience-restricted
problem_domains:
  - authentication
related_concepts:
  - jwt
  - jwks
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["2", "3.1.3.7"]
status: live
summary: JWT issued by an OIDC IdP asserting the end-user's identity to a relying party.
aliases:
  - oidc id token
---

The ID Token is a JWT issued by an OpenID Provider that asserts the
authentication event and identity of an end-user to a relying party. The
mandatory claims are `iss`, `sub`, `aud`, `exp`, `iat`, and (when the
authorization request carried one) `nonce`. RP validation includes signature
verification against the issuer's JWKS, audience check, and nonce check.
