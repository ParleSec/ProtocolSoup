---
id: userinfo
name: OIDC UserInfo endpoint
protocol: oidc
use_cases:
  - delegated-api-access
actors:
  - relying-party
  - identity-provider
patterns:
  - back-channel
  - bearer
problem_domains:
  - authentication
related_concepts:
  - access-token
  - id-token
normative_anchors:
  - rfc: OpenID Connect Core 1.0
    sections: ["5.3", "16.11"]
runnable: true
backend_id: oidc_userinfo
status: live
href: /protocol/oidc/flow/userinfo
summary: RP fetches additional user claims from the IdP using an access token.
---

The UserInfo endpoint returns claims about the authenticated end-user when
presented with a valid access token issued for the `openid` scope. The
`sub` claim returned MUST match the `sub` claim in the ID Token to prevent
token substitution (OIDC Core §16.11).
