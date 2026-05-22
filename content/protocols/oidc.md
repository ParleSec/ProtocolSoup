---
id: oidc
name: OpenID Connect
use_cases:
  - user-login-via-own-idp
  - user-login-via-social
  - single-sign-on
  - single-page-app-login
  - mobile-app-login
  - discovery
  - step-up-authentication
actors:
  - relying-party
  - identity-provider
  - authorization-server
  - user-agent
  - public-client
  - confidential-client
patterns:
  - front-channel-redirect
  - back-channel
  - signed-assertion
  - nonce-bound
  - metadata-discovery
  - bearer
problem_domains:
  - authentication
  - federation
  - session-management
  - key-management
  - discovery
related_concepts:
  - jwt
  - jwks
  - id-token
  - access-token
  - pkce
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["3.1", "3.3", "5.3", "15", "16"]
  - rfc: OpenID Connect Discovery 1.0
    sections: ["3", "7"]
status: live
href: /protocol/oidc
summary: Identity layer over OAuth 2.0 that adds verified authentication.
aliases:
  - openid 1.0
  - oidc core
  - openid connect core
---

OpenID Connect adds a verified authentication layer on top of OAuth 2.0. The
relying party receives a signed ID Token that asserts the user's identity, in
addition to (or instead of) an access token. Discovery and JWKS endpoints let
clients self-configure without prior coordination.
