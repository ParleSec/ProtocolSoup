---
id: oauth2
name: OAuth 2.0
use_cases:
  - delegated-api-access
  - service-to-service-auth
  - single-page-app-login
  - mobile-app-login
  - token-refresh
  - token-introspection
  - token-revocation
actors:
  - client
  - public-client
  - confidential-client
  - authorization-server
  - resource-server
  - user-agent
patterns:
  - front-channel-redirect
  - back-channel
  - bearer
  - pkce-bound
  - metadata-discovery
  - key-bound
problem_domains:
  - authorization
  - authentication
  - session-management
  - key-management
related_concepts:
  - pkce
  - jwt
  - jwks
  - access-token
normative_anchors:
  - rfc: RFC 6749
    sections: ["1.1", "1.4", "4", "5", "6", "10"]
  - rfc: RFC 6750
    sections: ["1", "2"]
  - rfc: RFC 9700
    sections: ["2.1", "2.5"]
  - rfc: RFC 9449
    sections: ["4", "5", "6.2", "8"]
status: live
href: /protocol/oauth2
summary: Industry-standard authorization framework for delegated API access.
aliases:
  - rfc 6749
  - oauth 2
  - oauth2.0
---

OAuth 2.0 is the authorization framework defined by RFC 6749. It lets a client
application obtain limited access to a resource server on behalf of a resource
owner without exposing credentials. Modern deployments follow RFC 9700, the
OAuth 2.0 Security Best Current Practice (BCP 240). Access tokens (and,
for public clients, refresh tokens) can optionally be sender-constrained
to a client-held key via DPoP (RFC 9449) instead of presented as a plain
bearer token.
