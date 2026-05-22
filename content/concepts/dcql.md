---
id: dcql
name: DCQL (Digital Credentials Query Language)
protocols:
  - oid4vp
use_cases:
  - credential-presentation
actors:
  - verifier
  - wallet
  - holder
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
normative_anchors:
  - rfc: OpenID4VP 1.0
    sections: ["6.1"]
status: live
summary: JSON query language verifiers use to request specific verifiable credentials.
aliases:
  - digital credentials query language
---

DCQL is the OID4VP query language verifiers use to express which verifiable
credentials they want from a wallet and how to present them. A DCQL query
declares credential sets, formats, and claim constraints; the wallet matches
its store and produces a presentation per the request. DCQL replaces the
earlier Presentation Exchange (PE) approach in OID4VP 1.0.
