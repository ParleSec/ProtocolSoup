---
id: jwks
name: JSON Web Key Set (JWKS)
protocols:
  - oauth2
  - oidc
  - oid4vci
  - oid4vp
  - ssf
use_cases:
  - discovery
actors:
  - authorization-server
  - identity-provider
  - resource-server
  - relying-party
patterns:
  - metadata-discovery
problem_domains:
  - key-management
  - discovery
normative_anchors:
  - rfc: RFC 7517
    sections: ["3", "4"]
status: live
summary: Published set of public keys used to verify JWT signatures.
aliases:
  - jwks_uri
  - rfc 7517
---

A JWKS (JSON Web Key Set, RFC 7517) is a JSON document containing one or more
public keys an issuer uses to sign JWTs. Relying parties fetch the document
from the issuer's `jwks_uri` and use the matching `kid` to verify
signatures. Rotation is performed by publishing new keys ahead of switching
the signing key.
