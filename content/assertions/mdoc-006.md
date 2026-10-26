---
id: mdoc-006
name: Issued mDL credentials contain every mandatory data element
protocols:
  - oid4vci
use_cases:
  - credential-issuance
actors:
  - issuer
  - wallet
patterns:
  - signed-assertion
problem_domains:
  - verifiable-credentials
normative_level: MUST
normative_anchors:
  - rfc: ISO/IEC 18013-5
    sections: ["7.2.1"]
assertion_text: >-
  Issued mDL credentials contain every mandatory org.iso.18013.5.1 data
  element, including a portrait carried as real JPEG bytes.
summary: Every mDL the OID4VCI issuer mints carries the org.iso.18013.5.1 elements marked mandatory, with portrait as a real JPEG byte string.
aliases:
  - mdl mandatory data elements
  - mdl portrait
  - org.iso.18013.5.1
---
## What this requires

ISO/IEC 18013-5 is not openly published, so this page quotes only the registry statement and does not reproduce the standard's element table. An mDL (`docType` `org.iso.18013.5.1.mDL`) issued over OID4VCI must carry every mandatory data element of the `org.iso.18013.5.1` namespace as an IssuerSignedItem covered by the MSO, and `portrait` must be a byte string that decodes as a JPEG image, not a placeholder.

ProtocolSoup's credential configurations mark eleven elements as mandatory and advertise them with `mandatory: true` in `credential_configurations_supported`: `family_name`, `given_name`, `birth_date`, `issue_date`, `expiry_date`, `issuing_country`, `issuing_authority`, `document_number`, `portrait`, `un_distinguishing_sign` and `driving_privileges`. `age_over_21` is also issued but not marked mandatory.

## Why it exists

This is ProtocolSoup's explanation of the consequence, not the standard's stated rationale. A verifier that requests a mandatory element expects every conforming mDL to be able to supply it. A credential missing one cannot answer that request at all, and a `portrait` that is not a decodable image gives a verifier nothing to compare against the person in front of it.

## What non-compliance looks like

An issuer omits `driving_privileges` or `un_distinguishing_sign` because the demo identity has no obvious value for them, or fills `portrait` with a short dummy byte string or a text URL. Wallets store the credential without complaint, and the failure only appears when a verifier asks for the missing element or tries to render the portrait.

## How ProtocolSoup tests it

`buildMDLIssuerSignedItems` builds every element from the identity record and issuance context, and refuses to issue if the record lacks a valid birthdate, `mdl_document_number` or `mdl_driving_privilege_codes`. `issuing_country` and `issuing_authority` come from the document-signer PKI, falling back to "US" and "ProtocolSoup". `generatedMDLPortrait` draws a stylised 96 by 128 avatar seeded from a hash of the holder's names and encodes it with `image/jpeg`, so the bytes are a real JPEG that cannot be mistaken for a photograph of a person.

`TestMsoMdocPreAuthorizedIssuance` runs the full pre-authorized code flow over HTTP, verifies the returned credential with `VerifyIssuerSigned` against the issuer's IACA trust anchor, and checks the MSO binds the proof's device key. It asserts that `family_name`, `given_name`, `birth_date`, `issuing_country`, `document_number` and `portrait` are present, that four of them carry the identity-record values, and that `portrait` decodes with `jpeg.Decode`. It does not assert the presence of `issue_date`, `expiry_date`, `issuing_authority`, `un_distinguishing_sign` or `driving_privileges`, so it proves six of the eleven elements, not every one.
