---
id: mdoc-004
name: DeviceResponse version is exactly 1.0
protocols:
  - oid4vp
use_cases:
  - credential-presentation
actors:
  - wallet
  - verifier
problem_domains:
  - verifiable-credentials
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["8.3.2.1"]
assertion_text: DeviceResponse version is exactly 1.0.
summary: A DeviceResponse is built, decoded and verified only when its version string is exactly "1.0".
aliases:
  - deviceresponse version
  - mdoc response version
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and describes ProtocolSoup's behaviour. A DeviceResponse is the CBOR map the wallet returns to the verifier, with `version`, `documents` and `status`. Its `version` is a text string and must be exactly "1.0". The comparison is on the string, so on receipt "1", "1.00" or a missing version are all refused.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. The version tells the verifier which structure rules the rest of the map follows. A verifier that accepts a version it does not know reads fields under rules the sender may not have used, and any check it then reports as passed was made against a structure it does not actually understand.

## What non-compliance looks like

A wallet sends `"version": "1.1"`, or leaves `version` out, and the verifier treats the response as 1.0 anyway and goes on to check signatures and digests. Or a wallet encodes `version` as a number rather than a text string and the verifier coerces it.

## How ProtocolSoup tests it

The check sits in three places. `EncodeDeviceResponse` fills an empty `Version` with "1.0" and refuses any other value, so the wallet side cannot send another version. `DecodeDeviceResponse` refuses any wire `version` other than "1.0", with no default for a missing field. `VerifyDeviceResponse` refuses any other version before it looks at `status` or any document.

`TestDeviceResponseRejectsUnsupportedVersion` asserts that all three reject version "2.0": encoding a `DeviceResponse{Version: "2.0"}`, decoding canonical CBOR whose `version` is "2.0", and verifying a `DeviceResponse{Version: "2.0"}`. It does not test a missing or non-string version.
