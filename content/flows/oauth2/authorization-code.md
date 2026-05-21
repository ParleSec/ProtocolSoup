---
id: authorization-code
name: OAuth 2.0 authorization code grant
protocol: oauth2
use_cases:
  - user-login-via-own-idp
  - delegated-api-access
actors:
  - confidential-client
  - authorization-server
  - resource-server
  - user-agent
patterns:
  - front-channel-redirect
  - back-channel
  - bearer
problem_domains:
  - authorization
  - authentication
related_concepts:
  - access-token
  - jwt
normative_anchors:
  - rfc: RFC 6749
    sections: ["4.1"]
  - rfc: RFC 9700
    sections: ["2.1"]
runnable: true
backend_id: authorization_code
status: live
href: /protocol/oauth2/flow/authorization-code
summary: Server-side web app obtains tokens through a browser-mediated code exchange.
---

The authorization code grant is the canonical OAuth 2.0 flow for confidential
clients. The user agent is redirected to the authorization server to consent,
and the resulting authorization code is exchanged at the token endpoint over
the back channel using the client's secret. The code is single-use and short-
lived.
