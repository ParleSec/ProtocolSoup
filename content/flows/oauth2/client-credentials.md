---
id: client-credentials
name: OAuth 2.0 client credentials grant
protocol: oauth2
use_cases:
  - service-to-service-auth
actors:
  - confidential-client
  - authorization-server
  - resource-server
patterns:
  - back-channel
  - bearer
  - key-bound
problem_domains:
  - authorization
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 6749
    sections: ["4.4"]
  - rfc: RFC 9700
    sections: ["2.5"]
  - rfc: RFC 9449
    sections: ["4", "5"]
runnable: true
backend_id: client_credentials
run_defaults:
  token_mode: dpop
status: live
href: /protocol/oauth2/flow/client-credentials
summary: Confidential client authenticates as itself; no user context.
aliases:
  - m2m token
  - machine-to-machine
---

The client credentials grant is used when a confidential client acts as
itself, not on behalf of a user. The client authenticates directly at the
token endpoint and receives an access token scoped to its own permissions.
This is the canonical flow for service-to-service back-channel calls. Client
authentication and access-token protection are independent choices: the
client authenticates with `client_secret_basic`/`client_secret_post`/
`private_key_jwt`, and separately the token endpoint accepts an optional
DPoP proof header (RFC 9449) that sender-constrains the issued access token
to a proof-of-possession key (`cnf.jkt`, `token_type: DPoP`) instead of the
default plain bearer token.
