---
id: access-token
name: Access Token
protocols:
  - oauth2
  - oidc
use_cases:
  - delegated-api-access
  - service-to-service-auth
actors:
  - client
  - authorization-server
  - resource-server
patterns:
  - bearer
  - audience-restricted
  - key-bound
problem_domains:
  - authorization
related_concepts:
  - jwt
normative_anchors:
  - rfc: RFC 6749
    sections: ["1.4"]
  - rfc: RFC 6750
    sections: ["1.2", "2"]
status: live
summary: Credential a client presents to a resource server to access a protected resource.
aliases:
  - oauth access token
  - bearer access token
---

An access token represents the authorization granted to a client. The
resource server treats a presented access token (typically as a bearer
credential per RFC 6750) as proof of authorization. Tokens can be opaque
(validated via introspection, RFC 7662) or self-contained JWTs (validated
against the issuer's JWKS).
