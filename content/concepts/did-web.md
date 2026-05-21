---
id: did-web
name: did:web
protocols:
  - oid4vp
  - oid4vci
use_cases:
  - federation-trust-establishment
  - credential-presentation
actors:
  - verifier
  - issuer
  - wallet
patterns:
  - metadata-discovery
  - signed-assertion
problem_domains:
  - key-management
  - federation
  - verifiable-credentials
normative_anchors:
  - rfc: did:web Method Specification
    sections: ["3"]
status: live
summary: DNS-backed DID method that publishes a DID Document via HTTPS.
---

did:web is a DID method that resolves to an HTTPS-hosted DID Document. The
DNS name in the DID is converted to an HTTPS URL (with optional path) and the
DID Document is fetched from there. Used in OID4VP for verifier and issuer
identifiers when a wallet is configured with a did:web host allowlist.
