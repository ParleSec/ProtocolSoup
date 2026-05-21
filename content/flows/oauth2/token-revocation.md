---
id: token-revocation
name: OAuth 2.0 token revocation
protocol: oauth2
use_cases:
  - token-revocation
actors:
  - client
  - authorization-server
patterns:
  - back-channel
  - bearer
problem_domains:
  - authorization
  - session-management
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 7009
    sections: ["2", "5"]
runnable: true
backend_id: token_revocation
status: live
href: /protocol/oauth2/flow/token-revocation
summary: Client asks the issuer to invalidate a previously issued access or refresh token.
aliases:
  - revoke endpoint
---

Token revocation (RFC 7009) lets a client invalidate an access or refresh
token at the authorization server, for example on user logout. The server
treats the token (and any tokens derived from it, such as access tokens
issued by exchanging a refresh token) as invalid after the call returns 200.
