package mdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// BuildMSO constructs a MobileSecurityObject from its constituent parts.
// The MSO is the structure that gets signed by the document signer; it binds
// the valueDigests (per-item hashes), the device key, the document type, and
// the validity window into a single unit.
func BuildMSO(
	valueDigests ValueDigests,
	deviceKey intcose.COSEKey,
	docType string,
	validity ValidityInfo,
) MobileSecurityObject {
	return MobileSecurityObject{
		Version:         MSOVersion,
		DigestAlgorithm: DigestAlgorithmSHA256,
		ValueDigests:    valueDigests,
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
		DocType:         docType,
		ValidityInfo:    validity,
	}
}

// EncodeMSOBytes canonical-encodes the MSO and wraps it in CBOR tag 24
// (#6.24(bstr .cbor MobileSecurityObject)). This is the payload of
// IssuerAuth; the COSE_Sign1 signs these wrapped bytes, not the bare MSO.
func EncodeMSOBytes(mso MobileSecurityObject) ([]byte, error) {
	return intcose.EncodeTagged24(mso)
}

// DecodeMSOBytes unwraps tag 24 and decodes the inner CBOR into a
// MobileSecurityObject. Use the raw tag-24 bytes (not the decoded MSO) when
// verifying the COSE_Sign1 signature.
func DecodeMSOBytes(msoBytes []byte) (MobileSecurityObject, error) {
	inner, err := intcose.DecodeTagged24(msoBytes)
	if err != nil {
		return MobileSecurityObject{}, fmt.Errorf("mdoc: decode MobileSecurityObjectBytes tag 24: %w", err)
	}
	var mso MobileSecurityObject
	if err := intcose.Unmarshal(inner, &mso); err != nil {
		return MobileSecurityObject{}, fmt.Errorf("mdoc: decode MobileSecurityObject: %w", err)
	}
	return mso, nil
}

// BuildIssuerAuth creates the IssuerAuth COSE_Sign1 (untagged, per mdoc wire
// format) over the MobileSecurityObjectBytes. The document-signer private key
// signs the payload; its certificate chain is placed in the unprotected header
// label 33 (x5chain).
func BuildIssuerAuth(msoBytes []byte, dsKey *ecdsa.PrivateKey, chain []*x509.Certificate) ([]byte, error) {
	if len(msoBytes) == 0 {
		return nil, fmt.Errorf("mdoc: empty MobileSecurityObjectBytes")
	}
	unprotected := intcose.UnprotectedHeader{}
	if len(chain) > 0 {
		if err := intcose.SetX5Chain(unprotected, chain); err != nil {
			return nil, fmt.Errorf("mdoc: set x5chain in IssuerAuth: %w", err)
		}
	}
	signed, err := intcose.Sign1Untagged(msoBytes, nil, dsKey, intcose.ES256ProtectedHeader(), unprotected)
	if err != nil {
		return nil, fmt.Errorf("mdoc: sign IssuerAuth: %w", err)
	}
	return signed, nil
}

// ParseIssuerAuth decodes an IssuerAuth (untagged or tagged COSE_Sign1) without
// verifying the signature, returning the raw MobileSecurityObjectBytes payload
// and the parsed Sign1 message. The caller can then verify the signature and
// decode the MSO from the payload.
func ParseIssuerAuth(issuerAuth []byte) (msoBytes []byte, msg *intcose.Sign1Message, err error) {
	msg, err = intcose.ParseSign1(issuerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("mdoc: parse IssuerAuth: %w", err)
	}
	if len(msg.Payload) == 0 {
		return nil, nil, fmt.Errorf("mdoc: IssuerAuth has no payload (detached payload is not supported)")
	}
	return msg.Payload, msg, nil
}
