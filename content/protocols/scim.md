---
id: scim
name: SCIM 2.0
use_cases:
  - user-provisioning
  - discovery
actors:
  - scim-client
  - scim-service-provider
  - identity-provider
patterns:
  - back-channel
  - bearer
  - metadata-discovery
problem_domains:
  - provisioning
  - discovery
normative_anchors:
  - rfc: RFC 7642
    sections: ["3"]
  - rfc: RFC 7643
    sections: ["4"]
  - rfc: RFC 7644
    sections: ["3"]
status: live
href: /protocol/scim
summary: Cross-domain identity provisioning protocol for users and groups.
---

SCIM 2.0 (System for Cross-domain Identity Management) is the IETF standard
for automating user account lifecycle across systems. Defined across RFC 7642
(definitions), RFC 7643 (core schema), and RFC 7644 (protocol), it lets an
identity provider create, read, update, and deactivate accounts on downstream
service providers.
