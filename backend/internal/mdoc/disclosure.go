package mdoc

import "fmt"

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
