---
id: device-code
name: OAuth 2.0 device authorization grant
protocol: oauth2
use_cases:
  - delegated-api-access
actors:
  - public-client
  - authorization-server
  - user-agent
patterns:
  - device-grant
  - polling
  - back-channel
  - out-of-band
  - bearer
problem_domains:
  - authorization
related_concepts:
  - access-token
normative_anchors:
  - rfc: RFC 8628
    sections: ["3.1", "3.2", "3.3", "3.4", "3.5", "4", "5.1", "6.1"]
runnable: true
backend_id: device_code
status: live
href: /protocol/oauth2/flow/device-code
summary: Input-constrained device displays a user_code; the person authorizes on a second device.
aliases:
  - device flow
  - device code
  - RFC 8628
---

The device authorization grant is for clients that cannot run a browser
login themselves (a TV, a CLI, a console). The device POSTs to
`/oauth2/device/authorize`, shows a short `user_code` and
`verification_uri`, and polls `/oauth2/token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` until the person
approves on another device. Polling honors `authorization_pending` and
`slow_down` (interval increased by five seconds) as RFC 8628 §3.5 requires.

This grant is still the correct tool for that constraint. Native apps that
already have a browser should use authorization code + PKCE instead
(RFC 8252). ProtocolSoup wires the real grant so the contrast with modern
redirect-based flows is visible, not simulated. In Looking Glass, Execute
opens the verification URI in the same Protocol Showcase sign-in popup used
by authorization code, while the device client keeps polling.
