// Package mdoc implements the ISO/IEC 18013-5 mdoc credential data model:
// the issuer-signed namespaces, the MobileSecurityObject and its value digests,
// IssuerAuth (COSE_Sign1 over tag-24-wrapped MSO), salted-digest computation
// for selective disclosure, and end-to-end issuer-signed verification.
//
// This package sits on top of internal/cose and does not import any
// protocol or transport code. It is the credential structure in isolation.
package mdoc

import (
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// NameSpace is the mdoc namespace identifier (a CBOR tstr). The mDL namespace
// defined by ISO/IEC 18013-5 is "org.iso.18013.5.1".
type NameSpace = string

// DigestID is the numeric identifier for an IssuerSignedItem within a
// namespace, used as the key in the MSO valueDigests map. Must be unique within
// a namespace.
type DigestID = uint64

// Digest is the raw hash bytes (SHA-256 by default) of an IssuerSignedItemBytes.
type Digest = []byte

const (
	// NameSpaceMDL is the standard mDL namespace (ISO/IEC 18013-5).
	NameSpaceMDL NameSpace = "org.iso.18013.5.1"

	// DocTypeMDL is the document type for a mobile driving licence.
	DocTypeMDL = "org.iso.18013.5.1.mDL"

	// DigestAlgorithmSHA256 is the default and only digest algorithm wired in
	// The MSO digestAlgorithm field is this string.
	DigestAlgorithmSHA256 = "SHA-256"

	// MSOVersion is the version field of the MobileSecurityObject. ISO/IEC
	// 18013-5 clause 9.1.2 defines "1.0".
	MSOVersion = "1.0"
)

// IssuerSignedItem is a single data element within an mdoc namespace (ISO/IEC
// 18013-5 clause 8.3.2.1.2.2). The CBOR map carries four keys:
//
//	digestID          uint
//	random            bstr (>= 16 bytes of entropy)
//	elementIdentifier tstr
//	elementValue      any
//
// The map keys are text strings (not integers), per the standard's CDDL. The
// struct is encoded as a canonical-CBOR map via struct tags that match the
// standard's key names.
type IssuerSignedItem struct {
	DigestID          DigestID `cbor:"digestID"`
	Random            []byte   `cbor:"random"`
	ElementIdentifier string   `cbor:"elementIdentifier"`
	ElementValue      any      `cbor:"elementValue"`
}

// IssuerSignedItemBytes is the tag-24-wrapped (#6.24(bstr .cbor
// IssuerSignedItem)) form. This is what gets hashed for the valueDigests and
// what is carried in IssuerNameSpaces.
type IssuerSignedItemBytes = []byte

// IssuerNameSpaces maps each namespace to its ordered list of
// IssuerSignedItemBytes. Per ISO/IEC 18013-5 clause 8.3.2.1.2.2, the array is
// transmitted as received; the verifier selects the subset it needs.
type IssuerNameSpaces map[NameSpace][]IssuerSignedItemBytes

// IssuerSigned is the top-level issuer-signed structure (ISO/IEC 18013-5 clause
// 8.3.2.1.2.2):
//
//	IssuerSigned = {
//	    ? "nameSpaces" : IssuerNameSpaces,
//	    "issuerAuth"   : IssuerAuth
//	}
//
// IssuerAuth is a COSE_Sign1 carrying the MobileSecurityObjectBytes as payload,
// stored here as raw CBOR bytes.
type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth []byte           `cbor:"issuerAuth"`
}

// ValueDigests maps NameSpace -> DigestID -> Digest. Each namespace carries its
// own digest map so the verifier can confirm which items were included at
// issuance time. (ISO/IEC 18013-5 clause 9.1.2.)
type ValueDigests map[NameSpace]map[DigestID]Digest

// DeviceKeyInfo carries the holder's device key, which is a COSE_Key (EC2/P-256
// here). Optional keyAuthorizations and keyInfo are not modelled because the
// current profile does not use them.
type DeviceKeyInfo struct {
	DeviceKey intcose.COSEKey `cbor:"deviceKey"`
}

// ValidityInfo defines the temporal validity window of the credential (ISO/IEC
// 18013-5 clause 9.1.2):
//
//	ValidityInfo = {
//	    "signed"         : tdate,
//	    "validFrom"      : tdate,
//	    "validUntil"     : tdate,
//	    ? "expectedUpdate" : tdate
//	}
//
// tdate is an RFC 3339 full-date-time string in CBOR (tag 0, tstr).
type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

// MobileSecurityObject is the MSO structure signed by the document signer
// (ISO/IEC 18013-5 clause 9.1.2). It binds the issuer's value digests, the
// holder's device key, document type, and validity window into a single signed
// unit.
type MobileSecurityObject struct {
	Version         string        `cbor:"version"`
	DigestAlgorithm string        `cbor:"digestAlgorithm"`
	ValueDigests    ValueDigests  `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo `cbor:"deviceKeyInfo"`
	DocType         string        `cbor:"docType"`
	ValidityInfo    ValidityInfo  `cbor:"validityInfo"`
}
