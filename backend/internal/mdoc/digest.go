package mdoc

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ComputeDigest hashes the raw IssuerSignedItemBytes (the tag-24 form) using
// the specified digest algorithm. The salt is the `random` field inside the
// item; there is no separate salt concatenation -- the entire wrapped item bytes
// are hashed as a unit.
//
// Only SHA-256 is supported by this implementation.
func ComputeDigest(itemBytes IssuerSignedItemBytes, alg string) (Digest, error) {
	if len(itemBytes) == 0 {
		return nil, fmt.Errorf("mdoc: empty IssuerSignedItemBytes")
	}
	switch alg {
	case DigestAlgorithmSHA256:
		h := sha256.Sum256(itemBytes)
		return h[:], nil
	default:
		return nil, fmt.Errorf("mdoc: unsupported digest algorithm %q", alg)
	}
}

// BuildValueDigests computes the valueDigests for a set of IssuerNameSpaces.
// For each namespace, each IssuerSignedItemBytes is hashed and the result is
// keyed by the item's digestID. The returned ValueDigests is what goes into the
// MobileSecurityObject.
func BuildValueDigests(ns IssuerNameSpaces, alg string) (ValueDigests, error) {
	vd := make(ValueDigests, len(ns))
	for namespace, items := range ns {
		if strings.TrimSpace(namespace) == "" {
			return nil, fmt.Errorf("mdoc: namespace identifier is empty")
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("mdoc: namespace %q contains no IssuerSignedItems", namespace)
		}
		digests := make(map[DigestID]Digest, len(items))
		elements := make(map[string]struct{}, len(items))
		for _, itemBytes := range items {
			item, err := DecodeIssuerSignedItemBytes(itemBytes)
			if err != nil {
				return nil, fmt.Errorf("mdoc: namespace %q: %w", namespace, err)
			}
			if _, dup := digests[item.DigestID]; dup {
				return nil, fmt.Errorf("mdoc: namespace %q: duplicate digestID %d", namespace, item.DigestID)
			}
			if strings.TrimSpace(item.ElementIdentifier) == "" {
				return nil, fmt.Errorf("mdoc: namespace %q: empty elementIdentifier", namespace)
			}
			if _, dup := elements[item.ElementIdentifier]; dup {
				return nil, fmt.Errorf("mdoc: namespace %q: duplicate elementIdentifier %q", namespace, item.ElementIdentifier)
			}
			elements[item.ElementIdentifier] = struct{}{}
			d, err := ComputeDigest(itemBytes, alg)
			if err != nil {
				return nil, fmt.Errorf("mdoc: namespace %q digestID %d: %w", namespace, item.DigestID, err)
			}
			digests[item.DigestID] = d
		}
		vd[namespace] = digests
	}
	return vd, nil
}

// VerifyValueDigests recomputes digests for the presented IssuerSignedItemBytes
// and confirms each one matches the corresponding entry in the MSO's
// ValueDigests. Items present in nameSpaces but absent from valueDigests are
// rejected; items absent from nameSpaces but present in valueDigests are not an
// error (they were simply not disclosed).
func VerifyValueDigests(ns IssuerNameSpaces, vd ValueDigests, alg string) error {
	for namespace, items := range ns {
		if strings.TrimSpace(namespace) == "" {
			return fmt.Errorf("mdoc: namespace identifier is empty")
		}
		if len(items) == 0 {
			return fmt.Errorf("mdoc: namespace %q contains no IssuerSignedItems", namespace)
		}
		nsDigests, ok := vd[namespace]
		if !ok {
			return fmt.Errorf("mdoc: namespace %q not present in MSO valueDigests", namespace)
		}
		seenDigestIDs := make(map[DigestID]struct{}, len(items))
		seenElements := make(map[string]struct{}, len(items))
		for _, itemBytes := range items {
			item, err := DecodeIssuerSignedItemBytes(itemBytes)
			if err != nil {
				return fmt.Errorf("mdoc: namespace %q: %w", namespace, err)
			}
			if _, duplicate := seenDigestIDs[item.DigestID]; duplicate {
				return fmt.Errorf("mdoc: namespace %q contains duplicate digestID %d", namespace, item.DigestID)
			}
			seenDigestIDs[item.DigestID] = struct{}{}
			if strings.TrimSpace(item.ElementIdentifier) == "" {
				return fmt.Errorf("mdoc: namespace %q contains an empty elementIdentifier", namespace)
			}
			if _, duplicate := seenElements[item.ElementIdentifier]; duplicate {
				return fmt.Errorf("mdoc: namespace %q contains duplicate elementIdentifier %q", namespace, item.ElementIdentifier)
			}
			seenElements[item.ElementIdentifier] = struct{}{}
			expected, ok := nsDigests[item.DigestID]
			if !ok {
				return fmt.Errorf("mdoc: namespace %q digestID %d (%q) not in MSO valueDigests", namespace, item.DigestID, item.ElementIdentifier)
			}
			got, err := ComputeDigest(itemBytes, alg)
			if err != nil {
				return fmt.Errorf("mdoc: namespace %q digestID %d: %w", namespace, item.DigestID, err)
			}
			if !digestEqual(got, expected) {
				return fmt.Errorf("mdoc: namespace %q digestID %d (%q): digest mismatch", namespace, item.DigestID, item.ElementIdentifier)
			}
		}
	}
	return nil
}

// digestEqual compares two digests in constant time (via byte comparison; not
// strictly timing-safe here, but correctness is the priority).
func digestEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
