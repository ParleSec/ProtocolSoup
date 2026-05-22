---
id: authorization-code-pkce
name: OAuth 2.0 authorization code with PKCE
protocol: oauth2
use_cases:
  - user-login-via-own-idp
  - single-page-app-login
  - mobile-app-login
  - delegated-api-access
  - pkce-protection
actors:
  - public-client
  - authorization-server
  - resource-server
  - user-agent
patterns:
  - front-channel-redirect
  - back-channel
  - bearer
  - pkce-bound
problem_domains:
  - authorization
  - authentication
related_concepts:
  - pkce
  - access-token
normative_anchors:
  - rfc: RFC 6749
    sections: ["4.1"]
  - rfc: RFC 7636
    sections: ["4"]
  - rfc: RFC 9700
    sections: ["2.1.1"]
runnable: true
backend_id: authorization_code_pkce
status: live
href: /protocol/oauth2/flow/authorization-code-pkce
summary: Authorization code flow bound to a PKCE verifier; required for public clients.
aliases:
  - auth code pkce
  - authorization code + pkce
---

PKCE (RFC 7636) binds the authorization request to a code_verifier known only
to the client. The authorization server stores the code_challenge alongside
the issued code; the verifier is presented at the token endpoint and checked
against the challenge. RFC 9700 requires PKCE for all OAuth clients, not just
public ones.
