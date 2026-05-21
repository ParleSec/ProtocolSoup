---
id: spiffe
name: SPIFFE/SPIRE
use_cases:
  - workload-attestation
  - service-to-service-auth
actors:
  - workload
patterns:
  - mutual-tls
  - certificate-bound
  - key-bound
  - attestation-bound
  - signed-assertion
problem_domains:
  - workload-identity
  - authentication
  - key-management
normative_anchors:
  - rfc: SPIFFE-ID
    sections: ["2"]
  - rfc: X509-SVID
    sections: ["2", "4"]
  - rfc: JWT-SVID
    sections: ["2", "3"]
  - rfc: Workload API
    sections: ["3", "5"]
status: live
href: /protocol/spiffe
summary: Cryptographic identity for workloads via X.509-SVID and JWT-SVID.
---

SPIFFE (Secure Production Identity Framework For Everyone) defines a uniform
identity for workloads that is attested by infrastructure rather than carried
in static credentials. SPIRE is the reference implementation. Identities are
expressed as X.509-SVIDs or JWT-SVIDs scoped by a trust domain.
