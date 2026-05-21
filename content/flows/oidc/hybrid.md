---
id: hybrid
name: OIDC hybrid flow
protocol: oidc
use_cases:
  - user-login-via-own-idp
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
problem_domains:
  - authentication
  - authorization
related_concepts:
  - id-token
  - access-token
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["3.3", "3.3.2", "3.3.3"]
runnable: true
backend_id: oidc_hybrid
status: live
href: /protocol/oidc/flow/hybrid
summary: Returns ID Token on front channel and code for back-channel exchange.
---

The hybrid flow returns part of the response (typically an ID Token and an
authorization code) on the front channel, while the access token is obtained
via back-channel code exchange. The `at_hash` and `c_hash` claims in the
returned ID Token bind it to the access token and code respectively.
