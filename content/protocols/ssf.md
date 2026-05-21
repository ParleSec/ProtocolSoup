---
id: ssf
name: Shared Signals Framework
use_cases:
  - continuous-evaluation
  - discovery
actors:
  - transmitter
  - receiver
patterns:
  - push-based
  - polling
  - signed-assertion
  - bearer
  - metadata-discovery
problem_domains:
  - security-events
  - session-management
normative_anchors:
  - rfc: RFC 8417
    sections: ["1", "2"]
  - rfc: RFC 8935
    sections: ["1", "2"]
  - rfc: RFC 8936
    sections: ["1", "2"]
  - rfc: OpenID SSF 1.0
    sections: ["3", "5"]
status: live
href: /protocol/ssf
summary: Real-time security event sharing across identity-consuming systems.
---

The Shared Signals Framework (SSF) defines how identity-consuming systems
share Security Event Tokens (SETs, RFC 8417) to coordinate session, account,
and credential state in real time. CAEP and RISC are the two principal
profiles. Push delivery uses RFC 8935; poll delivery uses RFC 8936.
