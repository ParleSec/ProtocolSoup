---
id: oidc-authorization-code
name: OIDC authorization code flow
protocol: oidc
use_cases:
  - user-login-via-own-idp
  - single-sign-on
  - delegated-api-access
actors:
  - relying-party
  - identity-provider
  - authorization-server
  - user-agent
patterns:
  - front-channel-redirect
  - back-channel
  - signed-assertion
  - nonce-bound
  - bearer
problem_domains:
  - authentication
  - authorization
  - session-management
related_concepts:
  - id-token
  - jwt
  - access-token
  - pkce
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["3.1", "3.1.2.1", "3.1.3.7"]
runnable: true
backend_id: oidc_authorization_code
status: live
href: /protocol/oidc/flow/oidc-authorization-code
summary: Authorization Code Flow with ID Token; canonical OIDC sign-in.
aliases:
  - oidc auth code
  - openid connect login
---

The Authorization Code Flow with `openid` scope is the recommended OpenID
Connect flow. The relying party receives both an ID Token (asserting the
user's identity) and an access token (for any additional API calls), with the
ID Token bound to a request-provided `nonce`. RFC 9700-aligned deployments
also bind the request with PKCE.
