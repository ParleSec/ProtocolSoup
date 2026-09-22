---
id: implicit
name: OAuth 2.0 implicit grant (legacy)
protocol: oauth2
use_cases:
  - single-page-app-login
  - delegated-api-access
actors:
  - public-client
  - authorization-server
  - user-agent
patterns:
  - front-channel-redirect
  - bearer
problem_domains:
  - authorization
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 6749
    sections: ["3.1.2", "4.2", "4.2.1", "4.2.2", "4.2.2.1"]
  - rfc: RFC 9700
    sections: ["2.1.2"]
  - rfc: RFC 9207
    sections: ["2"]
runnable: true
backend_id: implicit
status: deprecated
href: /protocol/oauth2/flow/implicit
summary: Access token returned in the redirect fragment; no refresh token is issued.
---

The implicit grant (`response_type=token`) returns an access token in the
authorization redirect fragment. There is no token-endpoint exchange and the
authorization server does not issue a refresh token (RFC 6749 §4.2.2).

RFC 9700 §2.1.2 says clients SHOULD NOT use this grant: the token is exposed
to the browser and cannot be sender-constrained the way a token-endpoint
token can. Prefer authorization code + PKCE. ProtocolSoup keeps the grant so
that contrast is a real protocol exchange, not a mock. Only the public
`public-app` client is registered for it. Confidential clients receive
`unauthorized_client` in the fragment. A missing or invalid `client_id` or
`redirect_uri` is not redirected.
