---
id: oidc-implicit
name: OIDC implicit flow (legacy)
protocol: oidc
use_cases:
  - user-login-via-own-idp
  - single-page-app-login
actors:
  - relying-party
  - identity-provider
  - user-agent
patterns:
  - front-channel-redirect
  - signed-assertion
  - nonce-bound
problem_domains:
  - authentication
related_concepts:
  - id-token
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["3.2"]
  - rfc: RFC 9700
    sections: ["2.1.2"]
runnable: true
backend_id: oidc_implicit
status: deprecated
href: /protocol/oidc/flow/oidc-implicit
summary: Tokens returned directly via the front channel; superseded by code+PKCE.
---

The implicit flow returns the ID Token (and optionally an access token)
directly in the authorization response fragment, with no back-channel token
exchange. RFC 9700 §2.1.2 explicitly states the implicit grant SHOULD NOT be
used; prefer Authorization Code + PKCE. Kept in the catalog for educational
contrast.
