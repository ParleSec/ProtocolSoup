---
id: agentauth
name: Agentic Registration
use_cases:
  - agent-registration
  - agent-ownership
  - discovery
actors:
  - agent
  - authorization-server
  - human-owner
patterns:
  - back-channel
  - signed-assertion
  - bearer
  - device-grant
  - metadata-discovery
problem_domains:
  - agent-identity
  - authorization
normative_anchors:
  - rfc: RFC 7523
    sections: ["2.1", "3"]
  - rfc: RFC 8628
    sections: ["3.3", "3.5", "5"]
  - rfc: auth.md
    sections: ["1"]
status: live
href: /protocol/agentauth
summary: Self-registration and claim ceremony for autonomous agents.
---

Agentic Registration (auth.md) lets an autonomous agent register itself over a
back channel, receive a service-signed identity assertion, and exchange that
assertion for an access token using the RFC 7523 JWT bearer grant. A later
claim ceremony, modelled on the RFC 8628 device authorization grant, binds the
agent to a person and widens its scope.
