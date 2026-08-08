package mdoc

import (
	"crypto/x509"
	"fmt"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// VerifiedDocument is the result of verifying a single Document from a
// DeviceResponse (ISO/IEC 18013-5 clause 8.3.2.1.2.2). It carries the
// issuer-verified MobileSecurityObject and the disclosed namespace/element
// values, both of which are trustworthy only because the issuer signature over
// the MSO and the holder deviceSignature both verified.
type VerifiedDocument struct {
	DocType                      string
	MSO                          *MobileSecurityObject
	IssuerAuthorityKeyIdentifier []byte
	DisclosedClaims              map[NameSpace]map[string]any
}

// VerifyDeviceAuth performs holder (device) authentication for one document
// (ISO/IEC 18013-5 clause 9.1.3.4):
//
//  1. Extract the holder device key from the verified MSO deviceKeyInfo.deviceKey.
//  2. Reconstruct DeviceAuthenticationBytes = #6.24(bstr .cbor
//     ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes])
//     from the shared SessionTranscript, the docType, and the DeviceNameSpacesBytes
//     received in the DeviceResponse (never from a transmitted payload).
//  3. Verify the detached deviceSignature COSE_Sign1 against the device key with
//     empty external_aad.
//
// Device-key trust is derivative: the MSO deviceKey is only trustworthy because
// the issuer signature over the MSO already verified, so callers MUST verify the
// issuer (VerifyIssuerSigned) before calling this with the resulting MSO.
func VerifyDeviceAuth(deviceSigned DeviceSigned, sessionTranscriptEncoded []byte, docType string, mso *MobileSecurityObject) error {
	if mso == nil {
		return fmt.Errorf("mdoc: a verified MSO is required to verify device authentication")
	}
	deviceKey, err := intcose.COSEKeyToECPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return fmt.Errorf("mdoc: extract device key from MSO deviceKeyInfo: %w", err)
	}
	// VerifyDeviceSignature reconstructs DeviceAuthenticationBytes with the
	// shared BuildDeviceAuthenticationBytes and verifies the detached signature.
	if err := VerifyDeviceSignature(deviceSigned, sessionTranscriptEncoded, docType, deviceKey); err != nil {
		return err
	}
	return nil
}

// VerifyDocument verifies a single Document end to end (ISO/IEC 18013-5 clauses
// 9.3.1 and 9.1.3.4):
//
//  1. Issuer verification (VerifyIssuerSigned): x5chain PKIX path to the IACA
//     trust anchor, IssuerAuth COSE_Sign1 signature, digest recomputation of the
//     disclosed IssuerSignedItems against the MSO valueDigests, and validityInfo.
//  2. DocType consistency: the Document docType must equal the MSO docType
//     (ISO/IEC 18013-5 clause 9.1.3.4 binds device authentication to this docType).
//  3. Device authentication (VerifyDeviceAuth) against the MSO-bound device key.
//
// roots is the IACA trust anchor pool (the IACA root, not the document-signer
// certificate; the DS cert arrives in the x5chain and chains to the root).
func VerifyDocument(doc Document, sessionTranscriptEncoded []byte, roots *x509.CertPool, now time.Time) (*VerifiedDocument, error) {
	mso, err := VerifyIssuerSigned(doc.IssuerSigned, roots, now)
	if err != nil {
		return nil, fmt.Errorf("mdoc: issuer verification for docType %q: %w", doc.DocType, err)
	}
	if doc.DocType == "" {
		return nil, fmt.Errorf("mdoc: document is missing docType")
	}
	if mso.DocType != "" && doc.DocType != mso.DocType {
		return nil, fmt.Errorf("mdoc: document docType %q does not match MSO docType %q", doc.DocType, mso.DocType)
	}
	if err := VerifyDeviceAuth(doc.DeviceSigned, sessionTranscriptEncoded, doc.DocType, mso); err != nil {
		return nil, fmt.Errorf("mdoc: device authentication for docType %q: %w", doc.DocType, err)
	}
	disclosed, err := CollectDisclosedElements(doc.IssuerSigned)
	if err != nil {
		return nil, err
	}
	issuerAKI, err := IssuerAuthorityKeyIdentifier(doc.IssuerSigned)
	if err != nil {
		return nil, err
	}
	return &VerifiedDocument{
		DocType:                      doc.DocType,
		MSO:                          mso,
		IssuerAuthorityKeyIdentifier: issuerAKI,
		DisclosedClaims:              disclosed,
	}, nil
}

// VerifyDeviceResponse verifies a complete DeviceResponse (ISO/IEC 18013-5
// clause 8.3.2.1.2.2): it requires an overall OK status and at least one
// document, then verifies every document's issuer signature and device
// authentication against the shared SessionTranscript. The SessionTranscript
// must be reconstructed by the verifier from its own inputs (the same shared
// construction the wallet used) so the deviceSignature binding is genuine.
func VerifyDeviceResponse(response DeviceResponse, sessionTranscriptEncoded []byte, roots *x509.CertPool, now time.Time) ([]VerifiedDocument, error) {
	if response.Version != DeviceResponseVersion {
		return nil, fmt.Errorf("mdoc: unsupported DeviceResponse version %q, want %q", response.Version, DeviceResponseVersion)
	}
	if response.Status != DeviceResponseStatusOK {
		return nil, fmt.Errorf("mdoc: DeviceResponse status %d is not OK (0)", response.Status)
	}
	if len(response.Documents) == 0 {
		return nil, fmt.Errorf("mdoc: DeviceResponse carries no documents")
	}
	verified := make([]VerifiedDocument, 0, len(response.Documents))
	for i := range response.Documents {
		vd, err := VerifyDocument(response.Documents[i], sessionTranscriptEncoded, roots, now)
		if err != nil {
			return nil, fmt.Errorf("mdoc: DeviceResponse document %d: %w", i, err)
		}
		verified = append(verified, *vd)
	}
	return verified, nil
}

// CollectDisclosedElements decodes the disclosed IssuerSignedItemBytes of an
// (issuer-verified) IssuerSigned into a namespace -> elementIdentifier ->
// elementValue map. The values are only meaningful after VerifyIssuerSigned has
// confirmed each item's digest against the MSO valueDigests; this is used by the
// verifier to evaluate DCQL namespace/element claim paths.
func CollectDisclosedElements(is IssuerSigned) (map[NameSpace]map[string]any, error) {
	out := make(map[NameSpace]map[string]any, len(is.NameSpaces))
	for ns, items := range is.NameSpaces {
		elements := make(map[string]any, len(items))
		for _, itemBytes := range items {
			item, err := DecodeIssuerSignedItemBytes(itemBytes)
			if err != nil {
				return nil, fmt.Errorf("mdoc: namespace %q: %w", ns, err)
			}
			if _, duplicate := elements[item.ElementIdentifier]; duplicate {
				return nil, fmt.Errorf("mdoc: namespace %q contains duplicate elementIdentifier %q", ns, item.ElementIdentifier)
			}
			elements[item.ElementIdentifier] = item.ElementValue
		}
		out[ns] = elements
	}
	return out, nil
}
