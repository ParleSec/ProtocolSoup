---
id: saml
name: SAML 2.0
use_cases:
  - user-login-via-own-idp
  - single-sign-on
  - single-logout
  - federation-trust-establishment
actors:
  - identity-provider
  - service-provider
  - user-agent
patterns:
  - front-channel-redirect
  - signed-assertion
  - xml-signed
  - metadata-discovery
problem_domains:
  - authentication
  - federation
  - session-management
normative_anchors:
  - rfc: SAML 2.0 Core
    sections: ["2", "3"]
  - rfc: SAML 2.0 Bindings
    sections: ["3", "4"]
  - rfc: SAML 2.0 Profiles
    sections: ["4.1", "4.4"]
status: live
href: /protocol/saml
summary: XML-based enterprise SSO via signed assertions between IdP and SP.
---

SAML 2.0 (Security Assertion Markup Language) is the OASIS standard for
exchanging authentication and authorization data between an identity provider
and a service provider. Assertions are XML documents, signed with XMLDsig, and
typically delivered to the SP via HTTP-POST or HTTP-Redirect bindings through
the user's browser.
