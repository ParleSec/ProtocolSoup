package mdoc

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// JSONSafeValue converts a CBOR-decoded mdoc element value (as returned by
// CollectDisclosedElements) into a value encoding/json can marshal. Generic
// CBOR decoding yields map[any]any for maps, cbor.Tag for tagged values such
// as full-date (tag 1004, used by mDL birth_date/issue_date/expiry_date), and
// []byte for byte strings. encoding/json cannot marshal map[any]any (a
// non-string map key) and renders cbor.Tag as an opaque struct, so an
// un-normalized mDL element (e.g. the nested driving_privileges array) would
// fail to encode. Normalizing here keeps a disclosed element
// JSON-serializable while preserving the real disclosed value.
func JSONSafeValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case cbor.Tag:
		return JSONSafeValue(typed.Content)
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, val := range typed {
			out[fmt.Sprintf("%v", key)] = JSONSafeValue(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, val := range typed {
			out[key] = JSONSafeValue(val)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, val := range typed {
			out[i] = JSONSafeValue(val)
		}
		return out
	case []byte:
		return base64.RawURLEncoding.EncodeToString(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	default:
		return typed
	}
}

// Disclose returns an IssuerSigned carrying only the requested
// elementIdentifiers per namespace, with issuerAuth unchanged. Selective
// disclosure in mdoc is purely a subset of the IssuerSignedItemBytes array;
// the MSO and its valueDigests are never altered.
//
// requested maps each namespace to the set of elementIdentifiers the holder
// wishes to reveal. Namespaces not in the request are omitted entirely. An
// empty request results in an IssuerSigned with no nameSpaces (only
// issuerAuth).
func Disclose(full IssuerSigned, requested map[NameSpace][]string) (IssuerSigned, error) {
	if len(requested) == 0 {
		return IssuerSigned{IssuerAuth: full.IssuerAuth}, nil
	}
	disclosed := make(IssuerNameSpaces, len(requested))
	for ns, identifiers := range requested {
		nsItems, ok := full.NameSpaces[ns]
		if !ok {
			return IssuerSigned{}, fmt.Errorf("mdoc: requested namespace %q not present in credential", ns)
		}
		wanted := make(map[string]struct{}, len(identifiers))
		for _, id := range identifiers {
			wanted[id] = struct{}{}
		}
		var selected []IssuerSignedItemBytes
		for _, itemBytes := range nsItems {
			item, err := DecodeIssuerSignedItemBytes(itemBytes)
			if err != nil {
				return IssuerSigned{}, fmt.Errorf("mdoc: namespace %q: %w", ns, err)
			}
			if _, ok := wanted[item.ElementIdentifier]; ok {
				selected = append(selected, itemBytes)
			}
		}
		if len(selected) == 0 {
			return IssuerSigned{}, fmt.Errorf("mdoc: namespace %q: none of the requested elements were found", ns)
		}
		disclosed[ns] = selected
	}
	return IssuerSigned{
		NameSpaces: disclosed,
		IssuerAuth: full.IssuerAuth,
	}, nil
}
