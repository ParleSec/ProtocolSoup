---
id: pkce
name: PKCE (Proof Key for Code Exchange)
protocols:
  - oauth2
  - oidc
  - oid4vci
use_cases:
  - pkce-protection
  - single-page-app-login
  - mobile-app-login
actors:
  - public-client
  - confidential-client
  - authorization-server
patterns:
  - pkce-bound
  - front-channel-redirect
  - back-channel
problem_domains:
  - authorization
normative_anchors:
  - rfc: RFC 7636
    sections: ["4"]
  - rfc: RFC 9700
    sections: ["2.1.1"]
status: live
summary: Binds an authorization request to a per-request code_verifier.
aliases:
  - proof key for code exchange
  - rfc 7636
---

PKCE (Proof Key for Code Exchange, RFC 7636) protects the authorization code
grant against code interception. The client generates a high-entropy random
`code_verifier`, hashes it into a `code_challenge`, and sends the challenge
with the authorization request. The verifier is presented at the token
endpoint; the AS hashes it and compares against the stored challenge. RFC
9700 §2.1.1 requires PKCE for all clients, public or confidential.
