---
id: discovery
name: OIDC Discovery
protocol: oidc
use_cases:
  - discovery
actors:
  - relying-party
  - identity-provider
patterns:
  - back-channel
  - metadata-discovery
problem_domains:
  - discovery
  - key-management
related_concepts:
  - jwks
normative_anchors:
  - rfc: OpenID Connect Discovery 1.0
    sections: ["3", "4", "7"]
runnable: true
backend_id: oidc_discovery
status: live
href: /protocol/oidc/flow/discovery
summary: RP locates endpoints, supported features, and JWKS via .well-known.
aliases:
  - openid-configuration
  - well-known/openid-configuration
---

OpenID Connect Discovery defines a `.well-known/openid-configuration`
document published by the issuer. It carries endpoint URLs, supported scopes,
response types, signing algorithms, and a `jwks_uri` pointing at the issuer's
public keys. The RP fetches it once at startup (or on key rollover) to
self-configure.
