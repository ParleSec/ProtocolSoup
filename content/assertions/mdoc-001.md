---
id: mdoc-001
name: COSE_Key rejects private key material and unsupported curves
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
  - key-bound
problem_domains:
  - verifiable-credentials
  - key-management
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["9.1.2"]
assertion_text: >-
  Public COSE_Key processing rejects private key material and unsupported
  curves.
summary: A COSE_Key read as a public key, such as the MSO deviceKey, is refused if it carries the private scalar d or is not EC2 P-256.
aliases:
  - cose_key private key
  - mdoc device key curve
  - deviceKey validation
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and describes ProtocolSoup's behaviour. The COSE_Key structure itself is defined in RFC 9052 Section 7; in an mdoc it carries the device key inside the MSO (`deviceKeyInfo.deviceKey`). When ProtocolSoup reads a COSE_Key as a public key, the key must be `kty` EC2 (2) with `crv` P-256 (1), must not contain label -4 (`d`, the private scalar), and must have 32-byte x and y coordinates that form a point on the P-256 curve.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. The deviceKey is what device authentication is verified against. If the issuer-signed MSO carries `d`, the private key has been handed to every party that receives the credential, and a valid device signature no longer shows that the holder's device produced it. A key on a curve the verifier does not implement cannot be checked at all, so accepting it would mean accepting a device signature that was never verified.

## What non-compliance looks like

An issuer serialises the holder's full key pair into `deviceKey`, and a verifier that ignores unknown labels accepts it. Or a verifier given `crv` 2 (P-384) coordinates passes them to a P-256 routine, or fails open when parsing does not succeed.

## How ProtocolSoup tests it

`cose.COSEKeyToECPublicKey` checks `kty` and `crv` first, then fails with "public COSE_Key must not contain private scalar d (label -4)" if label -4 is present, then checks the coordinate lengths and parses the point with `ecdsa.ParseUncompressedPublicKey`. It is used by MSO validation, by mdoc device-authentication verification, and by the wallet harness when it checks that the MSO binds its own key.

`TestCOSEKeyToECPublicKeyRejectsPrivateMaterial` generates a P-256 key, encodes it with `ECPrivateKeyToCOSEKey` so that it includes `d`, and asserts that `COSEKeyToECPublicKey` returns an error. The listed test does not cover the curve half of the statement: no listed test passes a COSE_Key with a `crv` other than 1 to `COSEKeyToECPublicKey`.
