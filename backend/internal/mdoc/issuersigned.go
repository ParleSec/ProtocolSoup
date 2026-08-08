package mdoc

import (
	"crypto/rand"
	"fmt"
	"strings"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/fxamacker/cbor/v2"
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

// maxUntrustedNestedLevels mirrors decModeUntrusted's MaxNestedLevels in
// internal/cose. Duplicated here (rather than exported from cose) because
// this gate enforces the cumulative depth *across* tag-24 recursion, which
// cose's per-Unmarshal-call limit cannot see: cose only bounds one decode
// call at a time, and a nesting bomb split across a tag-24 boundary is two
// calls. This constant is the budget the two calls must share.
const maxUntrustedNestedLevels = 16

// CheckUntrustedCBOR decodes externally-supplied mdoc CBOR under the hardened
// untrusted limits (cose.UnmarshalUntrusted: MaxNestedLevels 16,
// MaxArrayElements 1024, MaxMapPairs 1024) and returns the observed nesting
// depth alongside any error. MSOMdocFormat.ParseCredential calls this
// unconditionally, before any typed decode, so every externally-supplied
// credential that reaches the registry inherits it; the wire verification
// paths (mdoc.DecodeDeviceResponse, mdoc.DecodeIssuerSigned called directly)
// are untouched and keep the shared decMode.
//
// It recurses into CBOR tag 24 (Encoded CBOR data item) content because mdoc
// wraps IssuerSignedItemBytes and MobileSecurityObjectBytes in tag 24 as byte
// strings: a single outer decode sees each as an opaque bstr and counts none
// of its internal depth, so a nesting bomb placed inside an
// IssuerSignedItemBytes would pass an outer-only check and then be decoded by
// the typed path under the shared (loose) decode mode. The outer nesting
// level is carried into the recursive decode's depth count, so tag-24
// wrapping cannot be used to reset the budget.
//
// The decode is into `any` solely to enforce the limits; the decoded value is
// discarded once measured. This materialises maps and slices for the whole
// document -- it is not allocation-free -- but the cost is bounded by the
// same limits it enforces and by the caller's byte cap, and it is paid only
// on externally-supplied credentials.
func CheckUntrustedCBOR(data []byte) (int, error) {
	return checkUntrustedCBORDepth(data, 0)
}

func checkUntrustedCBORDepth(data []byte, outerDepth int) (int, error) {
	var decoded any
	if err := intcose.UnmarshalUntrusted(data, &decoded); err != nil {
		return outerDepth, fmt.Errorf("mdoc: untrusted CBOR decode: %w", err)
	}
	return measureUntrustedCBORDepth(decoded, outerDepth)
}

// measureUntrustedCBORDepth walks a value already decoded by
// cose.UnmarshalUntrusted and returns the deepest nesting level reached,
// recursing into tag-24 byte-string content with depth carried forward.
// Counting follows fxamacker's own MaxNestedLevels convention: every map,
// array, and tag adds one level; leaf scalars (strings, numbers, bools, plain
// byte strings) add none.
func measureUntrustedCBORDepth(value any, depth int) (int, error) {
	switch typed := value.(type) {
	case cbor.Tag:
		next := depth + 1
		if next > maxUntrustedNestedLevels {
			return next, fmt.Errorf("mdoc: untrusted CBOR nesting depth %d exceeds maximum %d", next, maxUntrustedNestedLevels)
		}
		if typed.Number == intcose.TagEncodedCBOR {
			if innerBytes, ok := typed.Content.([]byte); ok {
				return checkUntrustedCBORDepth(innerBytes, next)
			}
		}
		return measureUntrustedCBORDepth(typed.Content, next)
	case map[any]any:
		deepest := depth + 1
		if deepest > maxUntrustedNestedLevels {
			return deepest, fmt.Errorf("mdoc: untrusted CBOR nesting depth %d exceeds maximum %d", deepest, maxUntrustedNestedLevels)
		}
		for key, val := range typed {
			keyDepth, err := measureUntrustedCBORDepth(key, depth+1)
			if err != nil {
				return keyDepth, err
			}
			if keyDepth > deepest {
				deepest = keyDepth
			}
			valDepth, err := measureUntrustedCBORDepth(val, depth+1)
			if err != nil {
				return valDepth, err
			}
			if valDepth > deepest {
				deepest = valDepth
			}
		}
		return deepest, nil
	case map[string]any:
		deepest := depth + 1
		if deepest > maxUntrustedNestedLevels {
			return deepest, fmt.Errorf("mdoc: untrusted CBOR nesting depth %d exceeds maximum %d", deepest, maxUntrustedNestedLevels)
		}
		for _, val := range typed {
			valDepth, err := measureUntrustedCBORDepth(val, depth+1)
			if err != nil {
				return valDepth, err
			}
			if valDepth > deepest {
				deepest = valDepth
			}
		}
		return deepest, nil
	case []any:
		deepest := depth + 1
		if deepest > maxUntrustedNestedLevels {
			return deepest, fmt.Errorf("mdoc: untrusted CBOR nesting depth %d exceeds maximum %d", deepest, maxUntrustedNestedLevels)
		}
		for _, element := range typed {
			elementDepth, err := measureUntrustedCBORDepth(element, depth+1)
			if err != nil {
				return elementDepth, err
			}
			if elementDepth > deepest {
				deepest = elementDepth
			}
		}
		return deepest, nil
	default:
		return depth, nil
	}
}

// BuildIssuerNameSpaces encodes a map of namespace -> items into
// IssuerNameSpaces (the transmission form). Each item is wrapped in tag 24.
func BuildIssuerNameSpaces(namespaces map[NameSpace][]IssuerSignedItem) (IssuerNameSpaces, error) {
	out := make(IssuerNameSpaces, len(namespaces))
	for ns, items := range namespaces {
		if strings.TrimSpace(ns) == "" {
			return nil, fmt.Errorf("mdoc: namespace identifier is empty")
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("mdoc: namespace %q contains no IssuerSignedItems", ns)
		}
		encoded := make([]IssuerSignedItemBytes, 0, len(items))
		seen := make(map[DigestID]struct{}, len(items))
		seenElements := make(map[string]struct{}, len(items))
		for _, item := range items {
			if _, dup := seen[item.DigestID]; dup {
				return nil, fmt.Errorf("mdoc: duplicate digestID %d in namespace %q", item.DigestID, ns)
			}
			seen[item.DigestID] = struct{}{}
			if strings.TrimSpace(item.ElementIdentifier) == "" {
				return nil, fmt.Errorf("mdoc: empty elementIdentifier in namespace %q", ns)
			}
			if _, dup := seenElements[item.ElementIdentifier]; dup {
				return nil, fmt.Errorf("mdoc: duplicate elementIdentifier %q in namespace %q", item.ElementIdentifier, ns)
			}
			seenElements[item.ElementIdentifier] = struct{}{}
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
