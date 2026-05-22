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
problem_domains:
  - authorization
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 6749
    sections: ["4.4"]
  - rfc: RFC 9700
    sections: ["2.5"]
runnable: true
backend_id: client_credentials
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
This is the canonical flow for service-to-service back-channel calls.
