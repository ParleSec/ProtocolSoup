package mdoc

import (
	"crypto/rand"
	"fmt"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

const (
	// minRandomBytes is the minimum salt length for IssuerSignedItem.Random.
	// ISO/IEC 18013-5 requires sufficient entropy to prevent pre-image attacks;
	// 16 bytes (128 bits) is the floor.
	minRandomBytes = 16
)

// EncodeIssuerSignedItemBytes canonical-encodes the item then wraps it in
// CBOR tag 24 (#6.24(bstr .cbor IssuerSignedItem)). The resulting
// IssuerSignedItemBytes is both what gets hashed for the valueDigests and what
// is transmitted in IssuerNameSpaces.
func EncodeIssuerSignedItemBytes(item IssuerSignedItem) (IssuerSignedItemBytes, error) {
	if len(item.Random) < minRandomBytes {
		return nil, fmt.Errorf("mdoc: IssuerSignedItem.Random must be at least %d bytes, got %d", minRandomBytes, len(item.Random))
	}
	return intcose.EncodeTagged24(item)
}

// DecodeIssuerSignedItemBytes unwraps tag 24 and decodes the inner canonical
// CBOR into an IssuerSignedItem. For digest verification callers should hash
// the raw IssuerSignedItemBytes (the tag-24 form), not the decoded struct.
func DecodeIssuerSignedItemBytes(data IssuerSignedItemBytes) (IssuerSignedItem, error) {
	inner, err := intcose.DecodeTagged24(data)
	if err != nil {
		return IssuerSignedItem{}, fmt.Errorf("mdoc: decode IssuerSignedItemBytes tag 24: %w", err)
	}
	var item IssuerSignedItem
	if err := intcose.Unmarshal(inner, &item); err != nil {
		return IssuerSignedItem{}, fmt.Errorf("mdoc: decode IssuerSignedItem: %w", err)
	}
	return item, nil
}

// NewIssuerSignedItem constructs an IssuerSignedItem with a freshly generated
// random salt of at least minRandomBytes. Use this when issuing a new credential.
func NewIssuerSignedItem(digestID DigestID, elementIdentifier string, elementValue any) (IssuerSignedItem, error) {
	salt := make([]byte, minRandomBytes)
	if _, err := rand.Read(salt); err != nil {
		return IssuerSignedItem{}, fmt.Errorf("mdoc: generate random salt: %w", err)
	}
	return IssuerSignedItem{
		DigestID:          digestID,
		Random:            salt,
		ElementIdentifier: elementIdentifier,
		ElementValue:      elementValue,
	}, nil
}

// issuerSignedWire is the CBOR wire shape of IssuerSigned (ISO/IEC 18013-5
// clause 8.3.2.1.2.2). The pre-encoded tag-24 IssuerSignedItemBytes and the
// COSE_Sign1 IssuerAuth are carried as RawCBOR so they are embedded verbatim;
// modelling them as []byte would re-wrap them as CBOR byte strings and corrupt
// the structure.
type issuerSignedWire struct {
	NameSpaces map[NameSpace][]intcose.RawCBOR `cbor:"nameSpaces,omitempty"`
	IssuerAuth intcose.RawCBOR                 `cbor:"issuerAuth"`
}

// EncodeIssuerSigned canonical-encodes an IssuerSigned into the ISO/IEC 18013-5
// wire form: a CBOR map of the issuer-signed namespaces (each element an
// already-encoded #6.24 IssuerSignedItemBytes) plus the IssuerAuth COSE_Sign1.
// This is what the OID4VCI mso_mdoc credential response carries (base64url of
// these bytes).
func EncodeIssuerSigned(is IssuerSigned) ([]byte, error) {
	if len(is.IssuerAuth) == 0 {
		return nil, fmt.Errorf("mdoc: IssuerSigned has empty issuerAuth")
	}
	wire := issuerSignedWire{IssuerAuth: intcose.RawCBOR(is.IssuerAuth)}
	if len(is.NameSpaces) > 0 {
		wire.NameSpaces = make(map[NameSpace][]intcose.RawCBOR, len(is.NameSpaces))
		for ns, items := range is.NameSpaces {
			raws := make([]intcose.RawCBOR, 0, len(items))
			for _, item := range items {
				raws = append(raws, intcose.RawCBOR(item))
			}
			wire.NameSpaces[ns] = raws
		}
	}
	encoded, err := intcose.MarshalDeterministic(wire)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode IssuerSigned: %w", err)
	}
	return encoded, nil
}

// DecodeIssuerSigned decodes the ISO/IEC 18013-5 wire form back into an
// IssuerSigned, preserving the exact tag-24 item bytes and IssuerAuth bytes so
// digests and signatures verify against what was transmitted.
func DecodeIssuerSigned(data []byte) (IssuerSigned, error) {
	var wire issuerSignedWire
	if err := intcose.Unmarshal(data, &wire); err != nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: decode IssuerSigned: %w", err)
	}
	if len(wire.IssuerAuth) == 0 {
		return IssuerSigned{}, fmt.Errorf("mdoc: decoded IssuerSigned has empty issuerAuth")
	}
	out := IssuerSigned{IssuerAuth: []byte(wire.IssuerAuth)}
	if len(wire.NameSpaces) > 0 {
		out.NameSpaces = make(IssuerNameSpaces, len(wire.NameSpaces))
		for ns, items := range wire.NameSpaces {
			decoded := make([]IssuerSignedItemBytes, 0, len(items))
			for _, item := range items {
				decoded = append(decoded, []byte(item))
			}
			out.NameSpaces[ns] = decoded
		}
	}
	return out, nil
}

// BuildIssuerNameSpaces encodes a map of namespace -> items into
// IssuerNameSpaces (the transmission form). Each item is wrapped in tag 24.
func BuildIssuerNameSpaces(namespaces map[NameSpace][]IssuerSignedItem) (IssuerNameSpaces, error) {
	out := make(IssuerNameSpaces, len(namespaces))
	for ns, items := range namespaces {
		encoded := make([]IssuerSignedItemBytes, 0, len(items))
		seen := make(map[DigestID]struct{}, len(items))
		for _, item := range items {
			if _, dup := seen[item.DigestID]; dup {
				return nil, fmt.Errorf("mdoc: duplicate digestID %d in namespace %q", item.DigestID, ns)
			}
			seen[item.DigestID] = struct{}{}
			b, err := EncodeIssuerSignedItemBytes(item)
			if err != nil {
				return nil, fmt.Errorf("mdoc: encode item %q (digestID %d) in %q: %w", item.ElementIdentifier, item.DigestID, ns, err)
			}
			encoded = append(encoded, b)
		}
		out[ns] = encoded
	}
	return out, nil
}
