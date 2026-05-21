---
id: jwt
name: JSON Web Token (JWT)
protocols:
  - oauth2
  - oidc
  - oid4vci
  - oid4vp
  - ssf
  - spiffe
use_cases:
  - delegated-api-access
  - user-login-via-own-idp
  - service-to-service-auth
  - workload-attestation
  - continuous-evaluation
actors:
  - authorization-server
  - identity-provider
  - resource-server
  - workload
patterns:
  - signed-assertion
  - audience-restricted
  - bearer
  - key-bound
problem_domains:
  - authentication
  - authorization
  - key-management
normative_anchors:
  - rfc: RFC 7519
    sections: ["3", "4"]
  - rfc: RFC 7515
    sections: ["3", "4"]
  - rfc: RFC 7518
    sections: ["3"]
status: live
summary: Compact, URL-safe, signed JSON claims envelope.
aliases:
  - json web tokens
  - rfc 7519
---

A JSON Web Token (RFC 7519) is a compact, URL-safe envelope of JSON claims,
typically signed using JWS (RFC 7515). JWTs are the wire format for OIDC
ID Tokens, OAuth 2.0 access tokens (when self-contained), SETs, JWT-SVIDs,
and many VC formats.
