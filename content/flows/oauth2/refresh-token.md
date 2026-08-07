---
id: refresh-token
name: OAuth 2.0 refresh token exchange
protocol: oauth2
use_cases:
  - token-refresh
actors:
  - client
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
  - rfc: RFC 6749
    sections: ["6"]
  - rfc: RFC 9700
    sections: ["4.14"]
  - rfc: RFC 9449
    sections: ["5"]
runnable: true
backend_id: refresh_token
status: live
href: /protocol/oauth2/flow/refresh-token
summary: Exchanges a refresh token for a fresh access token; supports rotation.
---

The refresh token grant exchanges a previously issued refresh token for a new
access token (and optionally a rotated refresh token) without user
interaction. RFC 9700 §4.14 mandates refresh token rotation and binding to
the original client for public clients to mitigate token theft. When the
refresh token itself is DPoP-bound (RFC 9449 §5, issued to a public client
alongside a DPoP-bound access token), this grant must re-present a matching
DPoP proof; a missing or mismatched proof is rejected with `invalid_grant`.
