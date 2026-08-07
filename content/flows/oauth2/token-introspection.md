---
id: token-introspection
name: OAuth 2.0 token introspection
protocol: oauth2
use_cases:
  - token-introspection
actors:
  - resource-server
  - authorization-server
patterns:
  - back-channel
  - bearer
  - key-bound
problem_domains:
  - authorization
  - session-management
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 7662
    sections: ["2", "4"]
  - rfc: RFC 9449
    sections: ["6.2"]
runnable: true
backend_id: token_introspection
status: live
href: /protocol/oauth2/flow/token-introspection
summary: Resource server asks the issuer whether a token is active and what it represents.
aliases:
  - introspect endpoint
---

Token introspection (RFC 7662) lets a protected resource ask the
authorization server whether a presented token is active, who it was issued
to, what scopes it carries, and when it expires. It is the canonical way to
validate opaque access tokens that cannot be self-validated. For a
DPoP-bound token (RFC 9449 §6.2), the response also carries a top-level
`cnf.jkt` confirmation and `token_type: DPoP`, since the authorization
server does not itself check a DPoP proof at this endpoint -- the resource
server uses `cnf.jkt` to validate the binding.
