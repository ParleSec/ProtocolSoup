---
id: mdoc-005
name: Document-signer certificates chain to an IACA root per Annex B
protocols:
  - oid4vci
  - oid4vp
use_cases:
  - credential-issuance
  - credential-presentation
actors:
  - issuer
  - wallet
  - verifier
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
  - key-management
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["B.1"]
assertion_text: >-
  Document-signer certificates satisfy the Annex B profile, chain to an
  independently configured IACA root, and their signing key is bound by
  the COSE signature. When IssuerAuth is signed by the configured trust
  anchor itself (verified chain length 1), as in a self-signed trust-anchor
  mock-wallet shape, the DS-only Annex B profile checks are skipped after
  successful path validation and P-256 key checks.
summary: The IssuerAuth x5chain leaf must chain to a trust anchor the verifier configured itself, meet the document-signer certificate profile, and hold the key that signed IssuerAuth.
aliases:
  - iaca root
  - document signer certificate
  - mdoc x5chain validation
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and describes the profile ProtocolSoup enforces. The IssuerAuth COSE_Sign1 carries the document-signer (DS) certificate, and any intermediates, in the unprotected `x5chain` header (label 33). The verifier validates that chain against IACA roots it was configured with, never against a certificate taken from the credential, and then verifies the COSE signature with the leaf's own public key, which must be ECDSA P-256.

For a DS leaf beneath an IACA, ProtocolSoup's profile requires: Basic Constraints with CA false, key usage of `digitalSignature` only, the mDL DS extended key usage `1.0.18013.5.1.2`, a positive serial number of at most 20 octets, a subject with a two-letter `countryName` and an `organizationName`, a validity period of at most 457 days, subject and authority key identifiers, a CRL distribution point, an `issuerAltName` extension, and an ECDSA-with-SHA256 signature. The registry statement records one exception: when path validation shows the leaf is itself a configured trust anchor, these DS-only checks are skipped, but path validation and the P-256 key check still apply.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. A certificate chain in the credential is only a claim about who signed it; trust comes from a root the verifier chose. Validating against a root the credential supplies lets anyone issue an mDL. Profile checks such as CA false keep a CA key from also acting as a document signer, and checking the signature with the leaf's key is what ties the signed MSO to the certificate that was validated.

## What non-compliance looks like

A verifier trusts whatever root arrives in `x5chain`, so a self-signed certificate passes. Or it validates the chain correctly but verifies the COSE signature with a key from somewhere else, so a valid chain for one issuer vouches for an MSO signed by another. Or it accepts a CA=true certificate beneath the IACA as a document signer.

## How ProtocolSoup tests it

`VerifyIssuerSigned` takes the root pool as a parameter, adds `x5chain` entries only as intermediates, and fails closed when the pool is nil. `extractAndVerifyDocSignerKey` runs path validation, applies `validateDocumentSignerCertificate` unless a verified chain has length 1, checks for a P-256 key, and returns the leaf key that `VerifySign1` uses.

`TestVerifyIssuerSignedRejectsNilRoots` asserts verification fails with no roots. `TestDocumentSignerCertificateProfileRejectsInvalidFields` mutates a valid DS certificate eleven ways (missing EKU, wrong key usage, CA true, no Basic Constraints, overlong validity, missing country, organisation, SKI, AKI, CRL distribution point or `issuerAltName`) and asserts each is rejected; the serial number and signature algorithm checks are not exercised. `TestIssuerAuthSignatureBindsRFC9360X5ChainLeaf` signs with one PKI's key, attaches another PKI's valid chain and roots, and asserts rejection. `TestVerifyIssuerSignedAcceptsTrustAnchorAsDocumentSigner` asserts a self-signed CA=true IACA, alone in `x5chain` and in the root pool, verifies. `TestVerifyIssuerSignedRejectsCADocumentSignerBeneathIACA` asserts a CA=true leaf issued by a separate IACA is rejected. No listed test presents a chain to a root that is not in the configured pool.
