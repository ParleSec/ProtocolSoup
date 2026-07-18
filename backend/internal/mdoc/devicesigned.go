package mdoc

import (
	"crypto/ecdsa"
	"fmt"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// deviceAuthenticationContext is the fixed context string that is the first
// element of the DeviceAuthentication array (ISO/IEC 18013-5 clause 9.1.3.4).
const deviceAuthenticationContext = "DeviceAuthentication"

// DeviceSignedItems maps an element identifier to its value for device-signed
// data within a namespace (ISO/IEC 18013-5 clause 8.3.2.1.2.2). For mDL
// presentation this is normally empty: all data elements are issuer-signed.
type DeviceSignedItems = map[string]any

// DeviceNameSpaces maps a namespace to its DeviceSignedItems (ISO/IEC 18013-5
// clause 8.3.2.1.2.2). Normally an empty map for mDL.
type DeviceNameSpaces = map[NameSpace]DeviceSignedItems

// DeviceSigned is the holder-authenticated portion of a Document (ISO/IEC
// 18013-5 clause 8.3.2.1.2.2):
//
//	DeviceSigned = {
//	    "nameSpaces" : DeviceNameSpacesBytes,
//	    "deviceAuth" : DeviceAuth
//	}
//
// NameSpacesBytes is the tag-24-wrapped DeviceNameSpaces (present even when the
// inner map is empty). DeviceSignature is the untagged COSE_Sign1 carried under
// DeviceAuth.deviceSignature, transmitted with a detached payload.
type DeviceSigned struct {
	NameSpacesBytes []byte
	DeviceSignature []byte
}

// EncodeDeviceNameSpacesBytes wraps DeviceNameSpaces in CBOR tag 24
// (#6.24(bstr .cbor DeviceNameSpaces)), per ISO/IEC 18013-5 clause 8.3.2.1.2.2.
// The wrapper is emitted even when the map is empty: an unwrapped or omitted
// DeviceNameSpacesBytes changes the DeviceAuthentication bytes and breaks the
// deviceSignature.
func EncodeDeviceNameSpacesBytes(namespaces DeviceNameSpaces) ([]byte, error) {
	if namespaces == nil {
		namespaces = DeviceNameSpaces{}
	}
	encoded, err := intcose.EncodeTagged24(namespaces)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceNameSpacesBytes: %w", err)
	}
	return encoded, nil
}

// BuildDeviceAuthenticationBytes constructs DeviceAuthenticationBytes (ISO/IEC
// 18013-5 clause 9.1.3.4):
//
//	DeviceAuthentication = [
//	    "DeviceAuthentication",
//	    SessionTranscript,
//	    DocType,
//	    DeviceNameSpacesBytes
//	]
//	DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
//
// sessionTranscriptEncoded is the verbatim 3-element SessionTranscript array
// (see SessionTranscript.Encode) and deviceNameSpacesBytes is the tag-24 wrapped
// DeviceNameSpaces. Both are embedded as already-encoded CBOR so the bytes match
// exactly on the holder and verifier sides. The result is the detached payload
// the deviceSignature signs over.
func BuildDeviceAuthenticationBytes(sessionTranscriptEncoded []byte, docType string, deviceNameSpacesBytes []byte) ([]byte, error) {
	if len(sessionTranscriptEncoded) == 0 {
		return nil, fmt.Errorf("mdoc: SessionTranscript is required for DeviceAuthentication")
	}
	if len(deviceNameSpacesBytes) == 0 {
		return nil, fmt.Errorf("mdoc: DeviceNameSpacesBytes is required for DeviceAuthentication")
	}
	deviceAuthentication := []any{
		deviceAuthenticationContext,
		intcose.RawCBOR(sessionTranscriptEncoded),
		docType,
		intcose.RawCBOR(deviceNameSpacesBytes),
	}
	encoded, err := intcose.MarshalDeterministic(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceAuthentication: %w", err)
	}
	deviceAuthenticationBytes, err := intcose.Tagged24FromEncoded(encoded)
	if err != nil {
		return nil, fmt.Errorf("mdoc: wrap DeviceAuthenticationBytes: %w", err)
	}
	return deviceAuthenticationBytes, nil
}

// BuildDeviceSignature signs DeviceAuthenticationBytes with the holder device
// private key and returns the untagged, detached-payload COSE_Sign1 that is the
// deviceSignature (ISO/IEC 18013-5 clause 9.1.3.4). external_aad is empty.
func BuildDeviceSignature(deviceAuthenticationBytes []byte, deviceKey *ecdsa.PrivateKey) ([]byte, error) {
	if deviceKey == nil {
		return nil, fmt.Errorf("mdoc: device private key is required to sign device authentication")
	}
	signature, err := intcose.Sign1DetachedUntagged(
		deviceAuthenticationBytes,
		nil,
		deviceKey,
		intcose.ES256ProtectedHeader(),
		intcose.UnprotectedHeader{},
	)
	if err != nil {
		return nil, fmt.Errorf("mdoc: sign deviceSignature: %w", err)
	}
	return signature, nil
}

// BuildDeviceSigned assembles the DeviceSigned for the OID4VP profile: it wraps
// the (normally empty) DeviceNameSpaces in tag 24, builds the
// DeviceAuthenticationBytes over the shared SessionTranscript, and signs it with
// the device key, producing the detached deviceSignature.
func BuildDeviceSigned(deviceKey *ecdsa.PrivateKey, sessionTranscriptEncoded []byte, docType string, deviceNameSpaces DeviceNameSpaces) (DeviceSigned, error) {
	if deviceKey == nil {
		return DeviceSigned{}, fmt.Errorf("mdoc: device private key is required")
	}
	deviceNameSpacesBytes, err := EncodeDeviceNameSpacesBytes(deviceNameSpaces)
	if err != nil {
		return DeviceSigned{}, err
	}
	deviceAuthenticationBytes, err := BuildDeviceAuthenticationBytes(sessionTranscriptEncoded, docType, deviceNameSpacesBytes)
	if err != nil {
		return DeviceSigned{}, err
	}
	signature, err := BuildDeviceSignature(deviceAuthenticationBytes, deviceKey)
	if err != nil {
		return DeviceSigned{}, err
	}
	return DeviceSigned{
		NameSpacesBytes: deviceNameSpacesBytes,
		DeviceSignature: signature,
	}, nil
}

// VerifyDeviceSignature reconstructs DeviceAuthenticationBytes from the shared
// SessionTranscript, the docType, and the transmitted DeviceNameSpacesBytes,
// then verifies the detached deviceSignature against the device public key (the
// key bound in the MSO deviceKeyInfo.deviceKey). This is the holder-binding
// check performed by the verifier.
func VerifyDeviceSignature(deviceSigned DeviceSigned, sessionTranscriptEncoded []byte, docType string, deviceKey *ecdsa.PublicKey) error {
	if deviceKey == nil {
		return fmt.Errorf("mdoc: device public key is required to verify device authentication")
	}
	if len(deviceSigned.DeviceSignature) == 0 {
		return fmt.Errorf("mdoc: DeviceSigned has no deviceSignature")
	}
	deviceAuthenticationBytes, err := BuildDeviceAuthenticationBytes(sessionTranscriptEncoded, docType, deviceSigned.NameSpacesBytes)
	if err != nil {
		return err
	}
	if _, err := intcose.VerifySign1Detached(deviceSigned.DeviceSignature, deviceAuthenticationBytes, nil, deviceKey); err != nil {
		return fmt.Errorf("mdoc: deviceSignature verification failed: %w", err)
	}
	return nil
}
