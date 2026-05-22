---
id: risc
name: RISC (Risk Incident Sharing and Coordination)
protocols:
  - ssf
use_cases:
  - continuous-evaluation
actors:
  - transmitter
  - receiver
patterns:
  - push-based
  - signed-assertion
problem_domains:
  - security-events
normative_anchors:
  - rfc: OpenID RISC 1.0
    sections: ["3", "4"]
status: live
summary: SSF profile for account-level risk events such as compromise and disablement.
---

RISC (Risk Incident Sharing and Coordination) is the SSF profile for
distributing account-level risk events: account disabled, account purged,
credential compromise, identifier change, and account credential change.
RISC events are SETs (RFC 8417) with RISC-specific event types.
