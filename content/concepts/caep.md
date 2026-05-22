---
id: caep
name: CAEP (Continuous Access Evaluation Profile)
protocols:
  - ssf
use_cases:
  - continuous-evaluation
actors:
  - transmitter
  - receiver
patterns:
  - push-based
  - polling
  - signed-assertion
problem_domains:
  - security-events
  - session-management
normative_anchors:
  - rfc: OpenID CAEP 1.0
    sections: ["3", "4"]
status: live
summary: SSF profile for session-level security events.
---

CAEP (Continuous Access Evaluation Profile) is the SSF profile for
distributing session and credential state events: session revoked, token
claims changed, device compliance changed, credential level changed, and
similar. CAEP events are SETs (RFC 8417) with CAEP-specific event types and
subject identifiers.
