// Package cose provides the CBOR and COSE cryptographic substrate for ISO/IEC
// 18013-5 mdoc credentials. It wraps fxamacker/cbor/v2 (CBOR codec) and
// veraison/go-cose (COSE_Sign1) and adds the pieces the mdoc build needs:
// deterministic CBOR for the mdoc data model, COSE_Key conversion to/from the
// platform EC key types, and the x5chain unprotected header used to carry issuer
// certificates.
//
// Two distinct deterministic encodings appear in mdoc and they must not be
// confused:
//
//   - The mdoc data model (IssuerSignedItem, MobileSecurityObject, ...) is
//     encoded per ISO/IEC 18013-5 Section 8.1, which references RFC 7049
//     Section 3.9 "Canonical CBOR". That is length-first map-key sorting.
//   - The COSE layer (the Sig_structure for COSE_Sign1 and serialized protected
//     headers) is encoded per RFC 9052 Section 9, which references RFC 8949
//     Section 4.2.1 core deterministic encoding. That is bytewise-lexical
//     map-key sorting.
//
// These are different key orderings. Using the wrong one silently produces
// bytes that no other implementation reproduces, which breaks MSO digest and
// signature interop. The two encoders below are kept separate for that reason.
package cose

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	// tagEncodedCBOR is CBOR tag 24, "Encoded CBOR data item" (RFC 8949
	// Section 3.4.5.1). mdoc wraps the structures that are hashed or signed
	// (for example IssuerSignedItemBytes and MobileSecurityObjectBytes) in
	// tag 24 so the exact encoded bytes are preserved across the wire and
	// hashed verbatim rather than re-encoded.
	tagEncodedCBOR uint64 = 24

	// tagFullDate is CBOR tag 1004, "full-date" (RFC 8943), a text string in
	// RFC 3339 full-date form (YYYY-MM-DD). ISO/IEC 18013-5 clause 7.2.1 uses
	// full-date for mDL date data elements such as birth_date, issue_date, and
	// expiry_date.
	tagFullDate uint64 = 1004
)

// RawCBOR is pre-encoded CBOR that is embedded verbatim during marshaling
// rather than re-encoded. It is an alias of fxamacker's RawMessage. mdoc needs
// this to carry already-encoded items (the tag-24 IssuerSignedItemBytes and the
// COSE_Sign1 IssuerAuth) inside a larger structure (IssuerSigned) without the
// surrounding encoder re-wrapping them as byte strings, which would corrupt the
// wire form defined in ISO/IEC 18013-5 clause 8.3.2.1.2.2.
type RawCBOR = cbor.RawMessage

var (
	// canonicalEncMode encodes the mdoc data model per ISO/IEC 18013-5
	// Section 8.1 (RFC 7049 Section 3.9 "Canonical CBOR"): shortest-form
	// integers and lengths, definite-length items, and length-first map-key
	// sorting. ISO/IEC 18013-5 does not require map-key sorting, but sorting
	// deterministically is a harmless superset that gives reproducible bytes
	// for our own encoding while still satisfying the three mandatory rules.
	canonicalEncMode cbor.EncMode

	// coseEncMode encodes COSE-layer structures per RFC 9052 Section 9
	// (RFC 8949 Section 4.2.1 core deterministic encoding): bytewise-lexical
	// map-key sorting. This matches the encoder veraison/go-cose uses
	// internally for COSE_Sign1.
	coseEncMode cbor.EncMode

	// decMode decodes CBOR with the conservative options COSE expects:
	// duplicate map keys rejected, indefinite-length items rejected, and
	// integers decoded to int64 so COSE labels compare cleanly.
	decMode cbor.DecMode
)

func init() {
	var err error

	canonicalOpts := cbor.CanonicalEncOptions() // RFC 7049 Section 3.9, length-first
	// ISO/IEC 18013-5 represents tdate (ValidityInfo.signed/validFrom/
	// validUntil) as a tag-0 RFC 3339 date-time string (CBOR Standard Date/Time,
	// RFC 8949 Section 3.4.1). fxamacker defaults to a numeric epoch, which an
	// external mdoc verifier would reject, so pin RFC 3339 text with the tag
	// required.
	canonicalOpts.Time = cbor.TimeRFC3339
	canonicalOpts.TimeTag = cbor.EncTagRequired
	canonicalEncMode, err = canonicalOpts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cose: build canonical CBOR encoder: %v", err))
	}

	coseOpts := cbor.CoreDetEncOptions() // RFC 8949 Section 4.2.1, bytewise-lexical
	coseEncMode, err = coseOpts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("cose: build COSE deterministic CBOR encoder: %v", err))
	}

	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		IntDec:      cbor.IntDecConvertSignedOrFail,
		// Accept the tag-0/tag-1 prefix on time values so tdate (tag 0,
		// RFC 3339 text) decodes back into time.Time.
		TimeTag: cbor.DecTagOptional,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cose: build CBOR decoder: %v", err))
	}
}

// MarshalDeterministic encodes v as canonical CBOR for the mdoc data model
// (ISO/IEC 18013-5 Section 8.1 / RFC 7049 Section 3.9). Use this for every mdoc
// structure whose bytes are hashed into the MSO valueDigests, since stable
// encoding is what lets a verifier recompute the same digest.
func MarshalDeterministic(v any) ([]byte, error) {
	return canonicalEncMode.Marshal(v)
}

// Unmarshal decodes CBOR data into v using the conservative COSE decode mode.
func Unmarshal(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}

// TagEncode encodes v as canonical CBOR and wraps the resulting bytes in a CBOR
// tag. For tag 24 (TagEncodedCBOR) the inner bytes are carried as a byte string,
// producing #6.24(bstr .cbor v) per RFC 8949 Section 3.4.5.1. The wrapped bytes
// are preserved verbatim: a verifier hashes the byte string content as received
// and never re-encodes the inner item.
func TagEncode(tagNumber uint64, v any) ([]byte, error) {
	inner, err := canonicalEncMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cose: encode inner item for tag %d: %w", tagNumber, err)
	}
	return canonicalEncMode.Marshal(cbor.Tag{Number: tagNumber, Content: inner})
}

// EncodeTagged24 is a convenience wrapper around TagEncode for the common mdoc
// case of wrapping a structure in CBOR tag 24 (Encoded CBOR data item).
func EncodeTagged24(v any) ([]byte, error) {
	return TagEncode(tagEncodedCBOR, v)
}

// Tagged24FromEncoded wraps already-encoded CBOR bytes in tag 24
// (#6.24(bstr .cbor X)) without re-encoding them. Use this when the inner item
// was assembled as verbatim CBOR (for example the DeviceAuthentication array,
// whose elements already embed pre-encoded SessionTranscript and
// DeviceNameSpacesBytes), so re-marshalling the structure is neither possible
// nor desirable. The encoded bytes become the tag-24 byte-string content.
func Tagged24FromEncoded(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("cose: cannot tag-24 wrap empty CBOR")
	}
	return canonicalEncMode.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: encoded})
}

// DecodeTagged24 decodes a CBOR tag 24 (Encoded CBOR data item) value and
// returns the inner encoded bytes verbatim, without decoding the inner item.
// Callers that need the original bytes for hashing must use these bytes as-is.
func DecodeTagged24(data []byte) ([]byte, error) {
	var tag cbor.Tag
	if err := decMode.Unmarshal(data, &tag); err != nil {
		return nil, fmt.Errorf("cose: decode tag 24 wrapper: %w", err)
	}
	if tag.Number != tagEncodedCBOR {
		return nil, fmt.Errorf("cose: expected CBOR tag %d, got %d", tagEncodedCBOR, tag.Number)
	}
	inner, ok := tag.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("cose: tag 24 content is %T, want byte string", tag.Content)
	}
	return inner, nil
}

// FullDate returns a value that encodes as CBOR tag 1004 (RFC 8943 "full-date")
// wrapping an RFC 3339 full-date string (YYYY-MM-DD). ISO/IEC 18013-5 uses
// full-date for mDL date elements such as birth_date, issue_date, and
// expiry_date, distinct from tdate (tag 0) used for the MSO validity window.
// The returned value is intended for use as an IssuerSignedItem element value.
func FullDate(t time.Time) any {
	return cbor.Tag{Number: tagFullDate, Content: t.UTC().Format("2006-01-02")}
}
