---
id: haip-vp-001
name: x5c request-object chain excludes the root trust anchor
protocols:
  - oid4vp
use_cases:
  - credential-presentation
actors:
  - verifier
  - wallet
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
  - key-management
related_concepts:
  - jwt
normative_level: MUST
normative_anchors:
  - rfc: HAIP 1.0
    sections: ["5"]
assertion_text: >-
  The x5c request-object certificate chain excludes the root trust anchor.
summary: A HAIP verifier signs its request object with an x5c chain that stops short of the root; the wallet supplies the trust anchor itself.
aliases:
  - x5c trust anchor
  - root certificate in x5c
  - x509_hash request object chain
---
## What this requires

HAIP 1.0 Section 5 sets the rules for signed OpenID4VP requests: "The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header of the signed request." The same paragraph requires the Verifier to use the `x509_hash` Client Identifier Prefix and says "The X.509 certificate signing the request MUST NOT be self-signed."

In practice the `x5c` array starts with the leaf certificate that signed the request object and may carry intermediates, but the root CA is left out. The wallet already holds the roots it trusts and builds the path to one of them on its own.

## Why it exists

HAIP does not give a reason in the text. The concrete risk is that a root delivered inside the message proves nothing: anyone can put a self-signed CA certificate in a header. A wallet that takes the last certificate of `x5c` as its anchor, instead of looking up a root in its own trust store, accepts any request whose sender minted its own CA. Leaving the root out means the wallet has to do the lookup that actually establishes trust.

## What non-compliance looks like

The request object header carries `x5c` as `[leaf, root]`, where the final entry is a CA certificate that verifies under its own key. A strict HAIP wallet can refuse the request outright. A careless one may accept it because the chain "validates" against the root it was handed.

## How ProtocolSoup tests it

The verifier signs `x509_san_dns` and `x509_hash` request objects with the same signer. When it builds the `x5c` header (`x5cHeader` in `verifier_identity.go`), it drops the final certificate of the configured chain if that certificate is a CA and verifies under its own key. With no provisioned chain, the verifier generates a two-certificate chain (CA plus leaf), so only the leaf is sent. The hosted wallet checks request-object chains against its own configured roots. Any certificates after the leaf are used only as intermediates, never as anchors.

`TestCreateAuthorizationRequestBuildsX509SANDNSRequestObject` provisions a leaf and a self-signed root through `OID4VP_X509_SANDNS_CERT_CHAIN_PEM` and creates an `x509_san_dns` request. It then decodes the request object and asserts that `x5c` contains exactly one certificate, that this certificate chains to the root supplied out of band, that its SAN matches `verifier.example`, and that the request signature verifies with the leaf key. The test uses the `x509_san_dns` prefix rather than `x509_hash`. It covers the shared signer, but not the wallet side of this row.
