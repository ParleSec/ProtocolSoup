package mdoc

import (
	"crypto/ecdsa"
	"fmt"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

const (
	// DeviceResponseVersion is the version of the DeviceResponse structure
	// (ISO/IEC 18013-5 clause 8.3.2.1.2.2). The standard defines "1.0".
	DeviceResponseVersion = "1.0"

	// DeviceResponseStatusOK is the overall return code 0 ("OK", normal
	// processing) from the ISO/IEC 18013-5 clause 8.3.2.1.2.3 status codes.
	DeviceResponseStatusOK uint = 0
)

// Document pairs a disclosed IssuerSigned with the holder's DeviceSigned for a
// single doctype (ISO/IEC 18013-5 clause 8.3.2.1.2.2):
//
//	Document = {
//	    "docType"      : DocType,
//	    "issuerSigned" : IssuerSigned,   ; disclosed subset; MSO unchanged
//	    "deviceSigned" : DeviceSigned
//	}
type Document struct {
	DocType      string
	IssuerSigned IssuerSigned
	DeviceSigned DeviceSigned
}

// DeviceResponse is the top-level mdoc response returned by the wallet (ISO/IEC
// 18013-5 clause 8.3.2.1.2.2):
//
//	DeviceResponse = {
//	    "version"   : tstr,
//	    ? "documents" : [+Document],
//	    "status"    : uint
//	}
type DeviceResponse struct {
	Version   string
	Documents []Document
	Status    uint
}

// deviceAuthWire is the CBOR shape of DeviceAuth carrying a single
// deviceSignature (ISO/IEC 18013-5 clause 9.1.3.4). The COSE_Sign1 is embedded
// verbatim as raw CBOR.
type deviceAuthWire struct {
	DeviceSignature intcose.RawCBOR `cbor:"deviceSignature"`
}

// deviceSignedWire is the CBOR shape of DeviceSigned (ISO/IEC 18013-5 clause
// 8.3.2.1.2.2). nameSpaces is the tag-24 DeviceNameSpacesBytes embedded verbatim.
type deviceSignedWire struct {
	NameSpaces intcose.RawCBOR `cbor:"nameSpaces"`
	DeviceAuth deviceAuthWire  `cbor:"deviceAuth"`
}

// documentWire is the CBOR shape of Document. issuerSigned is the verbatim
// encoded IssuerSigned map (not tag-24 wrapped, per the CDDL).
type documentWire struct {
	DocType      string           `cbor:"docType"`
	IssuerSigned intcose.RawCBOR  `cbor:"issuerSigned"`
	DeviceSigned deviceSignedWire `cbor:"deviceSigned"`
}

// deviceResponseWire is the CBOR shape of DeviceResponse.
type deviceResponseWire struct {
	Version   string         `cbor:"version"`
	Documents []documentWire `cbor:"documents,omitempty"`
	Status    uint           `cbor:"status"`
}

// EncodeDeviceResponse canonical-encodes a DeviceResponse to its ISO/IEC 18013-5
// wire CBOR. Each Document's disclosed IssuerSigned is encoded with
// EncodeIssuerSigned (preserving the verbatim tag-24 item bytes and IssuerAuth),
// and the DeviceSigned embeds the tag-24 DeviceNameSpacesBytes plus the untagged
// detached deviceSignature COSE_Sign1.
func EncodeDeviceResponse(response DeviceResponse) ([]byte, error) {
	version := response.Version
	if version == "" {
		version = DeviceResponseVersion
	}
	if version != DeviceResponseVersion {
		return nil, fmt.Errorf("mdoc: unsupported DeviceResponse version %q, want %q", version, DeviceResponseVersion)
	}
	wire := deviceResponseWire{
		Version: version,
		Status:  response.Status,
	}
	if len(response.Documents) > 0 {
		wire.Documents = make([]documentWire, 0, len(response.Documents))
		for i := range response.Documents {
			doc := response.Documents[i]
			if doc.DocType == "" {
				return nil, fmt.Errorf("mdoc: DeviceResponse document %d has no docType", i)
			}
			issuerSignedEncoded, err := EncodeIssuerSigned(doc.IssuerSigned)
			if err != nil {
				return nil, fmt.Errorf("mdoc: encode document %d issuerSigned: %w", i, err)
			}
			if len(doc.DeviceSigned.NameSpacesBytes) == 0 {
				return nil, fmt.Errorf("mdoc: document %d DeviceSigned is missing DeviceNameSpacesBytes", i)
			}
			if len(doc.DeviceSigned.DeviceSignature) == 0 {
				return nil, fmt.Errorf("mdoc: document %d DeviceSigned is missing deviceSignature", i)
			}
			wire.Documents = append(wire.Documents, documentWire{
				DocType:      doc.DocType,
				IssuerSigned: intcose.RawCBOR(issuerSignedEncoded),
				DeviceSigned: deviceSignedWire{
					NameSpaces: intcose.RawCBOR(doc.DeviceSigned.NameSpacesBytes),
					DeviceAuth: deviceAuthWire{
						DeviceSignature: intcose.RawCBOR(doc.DeviceSigned.DeviceSignature),
					},
				},
			})
		}
	}
	encoded, err := intcose.MarshalDeterministic(wire)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceResponse: %w", err)
	}
	return encoded, nil
}

// DecodeDeviceResponse decodes the ISO/IEC 18013-5 wire CBOR back into a
// DeviceResponse, preserving the verbatim IssuerSigned, DeviceNameSpacesBytes,
// and deviceSignature bytes so digests and signatures verify against what was
// transmitted. This is shared with the verifier.
func DecodeDeviceResponse(data []byte) (DeviceResponse, error) {
	var wire deviceResponseWire
	if err := intcose.Unmarshal(data, &wire); err != nil {
		return DeviceResponse{}, fmt.Errorf("mdoc: decode DeviceResponse: %w", err)
	}
	if wire.Version != DeviceResponseVersion {
		return DeviceResponse{}, fmt.Errorf("mdoc: unsupported DeviceResponse version %q, want %q", wire.Version, DeviceResponseVersion)
	}
	response := DeviceResponse{
		Version: wire.Version,
		Status:  wire.Status,
	}
	if len(wire.Documents) > 0 {
		response.Documents = make([]Document, 0, len(wire.Documents))
		for i, docWire := range wire.Documents {
			issuerSigned, err := DecodeIssuerSigned([]byte(docWire.IssuerSigned))
			if err != nil {
				return DeviceResponse{}, fmt.Errorf("mdoc: decode document %d issuerSigned: %w", i, err)
			}
			response.Documents = append(response.Documents, Document{
				DocType:      docWire.DocType,
				IssuerSigned: issuerSigned,
				DeviceSigned: DeviceSigned{
					NameSpacesBytes: []byte(docWire.DeviceSigned.NameSpaces),
					DeviceSignature: []byte(docWire.DeviceSigned.DeviceAuth.DeviceSignature),
				},
			})
		}
	}
	return response, nil
}

// BuildDocument assembles a single-doctype Document for a DeviceResponse: it
// selects the disclosed IssuerSignedItems with the shared disclosure logic
// (the MSO and its valueDigests are never altered), then builds the DeviceSigned
// over the shared SessionTranscript with the holder device key. requested maps
// each namespace to the element identifiers to reveal; pass nil/empty to
// disclose no namespaces (issuerAuth only). deviceNameSpaces is normally nil
// (an empty map) for mDL.
func BuildDocument(deviceKey *ecdsa.PrivateKey, full IssuerSigned, docType string, sessionTranscriptEncoded []byte, requested map[NameSpace][]string, deviceNameSpaces DeviceNameSpaces) (Document, error) {
	if deviceKey == nil {
		return Document{}, fmt.Errorf("mdoc: device private key is required to build a Document")
	}
	if docType == "" {
		return Document{}, fmt.Errorf("mdoc: docType is required to build a Document")
	}
	disclosed, err := Disclose(full, requested)
	if err != nil {
		return Document{}, err
	}
	deviceSigned, err := BuildDeviceSigned(deviceKey, sessionTranscriptEncoded, docType, deviceNameSpaces)
	if err != nil {
		return Document{}, err
	}
	return Document{
		DocType:      docType,
		IssuerSigned: disclosed,
		DeviceSigned: deviceSigned,
	}, nil
}

// BuildDeviceResponse assembles a single-document DeviceResponse (version "1.0",
// status 0) from a stored credential, disclosing the requested elements and
// signing device authentication with the holder device key over the shared
// SessionTranscript. This is the wallet-side entry point
// and reused by the verifier-facing flows.
func BuildDeviceResponse(deviceKey *ecdsa.PrivateKey, full IssuerSigned, docType string, sessionTranscriptEncoded []byte, requested map[NameSpace][]string, deviceNameSpaces DeviceNameSpaces) (DeviceResponse, error) {
	document, err := BuildDocument(deviceKey, full, docType, sessionTranscriptEncoded, requested, deviceNameSpaces)
	if err != nil {
		return DeviceResponse{}, err
	}
	return DeviceResponse{
		Version:   DeviceResponseVersion,
		Documents: []Document{document},
		Status:    DeviceResponseStatusOK,
	}, nil
}
