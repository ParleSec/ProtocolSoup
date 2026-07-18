package vc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DCQLCredentialRequirement represents a single credential requirement from a DCQL query.
type DCQLCredentialRequirement struct {
	ID                   string
	Format               string
	VCTValues            []string
	DoctypeValues        []string
	CredentialTypeValues []string
	RequiredClaimPaths   []string
	// RequiredClaimPathSegments preserves each claim path as its raw component
	// segments, which mdoc requires: an mdoc claim path is [namespace,
	// elementIdentifier] and the namespace itself contains dots (e.g.
	// "org.iso.18013.5.1"), so the dot-joined RequiredClaimPaths above cannot be
	// re-split for mdoc. SD-JWT VC continues to use the dot-joined form.
	RequiredClaimPathSegments [][]string
	// TrustedAuthorities carries the DCQL Trusted Authorities Query for this
	// credential (OID4VP 1.0 Section 6.1.1): the issuer authorities the verifier
	// will accept. HAIP 1.0 Section 5 mandates support for the "aki" (Authority
	// Key Identifier) type on the mso_mdoc path.
	TrustedAuthorities []DCQLTrustedAuthority
}

// DCQLTrustedAuthority is one entry of a DCQL Trusted Authorities Query
// (OID4VP 1.0 Section 6.1.1): a trust framework Type (e.g. "aki", "etsi_tl",
// "openid_federation") and the Values that identify the accepted authorities
// under that framework.
type DCQLTrustedAuthority struct {
	Type   string
	Values []string
}

// MdocCredentialEvidence is the mdoc view of a presented credential for DCQL
// matching: the issuer-verified doctype plus the disclosed element identifiers
// per namespace. It is format-specific to mso_mdoc (ISO/IEC 18013-5) and is
// supplied by the verifier after CollectDisclosedElements, keeping this matcher
// free of any CBOR/COSE dependency.
type MdocCredentialEvidence struct {
	Format string
	// Doctype is the credential docType (the DCQL meta for mdoc), e.g.
	// "org.iso.18013.5.1.mDL".
	Doctype string
	// IssuerAuthorityKeyIdentifier is the base64url-encoded Authority Key
	// Identifier from the verified document-signer certificate.
	IssuerAuthorityKeyIdentifier string
	// NameSpaces maps each disclosed namespace to the set of disclosed element
	// identifiers within it.
	NameSpaces map[string]map[string]struct{}
}

// DCQLCredentialEvidence reuses the shared credential evidence model used by PE matching.
type DCQLCredentialEvidence = CredentialEvidence

// ParseDCQLCredentialRequirements parses a raw DCQL JSON query into structured requirements.
func ParseDCQLCredentialRequirements(rawDCQLQuery string) []DCQLCredentialRequirement {
	trimmed := strings.TrimSpace(rawDCQLQuery)
	if trimmed == "" {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return nil
	}
	rawCredentials, _ := payload["credentials"].([]interface{})
	requirements := make([]DCQLCredentialRequirement, 0, len(rawCredentials))
	for _, rawCredential := range rawCredentials {
		credentialObject, _ := rawCredential.(map[string]interface{})
		requirement := DCQLCredentialRequirement{
			ID:     strings.TrimSpace(stringValue(credentialObject["id"])),
			Format: strings.TrimSpace(stringValue(credentialObject["format"])),
		}
		if meta, ok := credentialObject["meta"].(map[string]interface{}); ok {
			requirement.VCTValues = normalizeStringSliceDCQL(meta["vct_values"])
			requirement.DoctypeValues = normalizeStringSliceDCQL(meta["doctype_values"])
			if len(requirement.DoctypeValues) == 0 {
				if singleDoctype := strings.TrimSpace(stringValue(meta["doctype"])); singleDoctype != "" {
					requirement.DoctypeValues = []string{singleDoctype}
				}
			}
			requirement.CredentialTypeValues = normalizeStringSliceDCQL(meta["type_values"])
		}
		rawClaims, _ := credentialObject["claims"].([]interface{})
		requiredPaths := make([]string, 0, len(rawClaims))
		segmentLists := make([][]string, 0, len(rawClaims))
		seenSegmentKeys := make(map[string]struct{}, len(rawClaims))
		for _, rawClaim := range rawClaims {
			claimObject, _ := rawClaim.(map[string]interface{})
			rawPath, _ := claimObject["path"].([]interface{})
			segments := make([]string, 0, len(rawPath))
			for _, rawSegment := range rawPath {
				segment := strings.TrimSpace(stringValue(rawSegment))
				if segment == "" {
					continue
				}
				segments = append(segments, segment)
			}
			if len(segments) == 0 {
				continue
			}
			joined := strings.Join(segments, ".")
			requiredPaths = append(requiredPaths, joined)
			// Preserve the raw segments once per distinct path so mdoc can match
			// [namespace, elementIdentifier] without re-splitting on dots.
			if _, ok := seenSegmentKeys["\x00"+strings.Join(segments, "\x00")]; !ok {
				seenSegmentKeys["\x00"+strings.Join(segments, "\x00")] = struct{}{}
				segmentLists = append(segmentLists, segments)
			}
		}
		requirement.RequiredClaimPaths = dedupeStringsDCQL(requiredPaths)
		sort.Strings(requirement.RequiredClaimPaths)
		requirement.RequiredClaimPathSegments = segmentLists
		if rawAuthorities, ok := credentialObject["trusted_authorities"].([]interface{}); ok {
			for _, rawAuthority := range rawAuthorities {
				authorityObject, _ := rawAuthority.(map[string]interface{})
				authority := DCQLTrustedAuthority{
					Type:   strings.TrimSpace(stringValue(authorityObject["type"])),
					Values: normalizeStringSliceDCQL(authorityObject["values"]),
				}
				if authority.Type == "" && len(authority.Values) == 0 {
					continue
				}
				requirement.TrustedAuthorities = append(requirement.TrustedAuthorities, authority)
			}
		}
		requirements = append(requirements, requirement)
	}
	return requirements
}

// RequirementMatchesEvidence evaluates whether a credential satisfies a DCQL requirement.
// Returns (matched, reasonCode, reasonMessage).
func RequirementMatchesEvidence(requirement DCQLCredentialRequirement, evidence DCQLCredentialEvidence) (bool, string, string) {
	if requirement.Format != "" && strings.TrimSpace(evidence.Format) != requirement.Format {
		return false, "dcql_format_mismatch", fmt.Sprintf("credential format %q does not satisfy requested format %q", evidence.Format, requirement.Format)
	}
	if len(requirement.VCTValues) > 0 && !containsStringDCQL(requirement.VCTValues, strings.TrimSpace(evidence.VCT)) {
		return false, "dcql_meta_mismatch", "credential vct does not satisfy dcql vct_values"
	}
	if len(requirement.DoctypeValues) > 0 && !containsStringDCQL(requirement.DoctypeValues, strings.TrimSpace(evidence.Doctype)) {
		return false, "dcql_meta_mismatch", "credential doctype does not satisfy dcql doctype_values"
	}
	if len(requirement.CredentialTypeValues) > 0 && !intersectsStringSliceDCQL(requirement.CredentialTypeValues, evidence.CredentialTypes) {
		return false, "dcql_meta_mismatch", "credential type does not satisfy dcql type_values"
	}
	for _, claimPath := range requirement.RequiredClaimPaths {
		if !HasClaimPath(evidence.FullClaims, claimPath) {
			return false, "missing_required_claim", fmt.Sprintf("required claim %q is missing from disclosed credential data", claimPath)
		}
	}
	return true, "", ""
}

// RequirementMatchesMdoc evaluates whether an mso_mdoc credential satisfies a
// DCQL requirement (ISO/IEC 18013-5 + OID4VP/DCQL). Unlike SD-JWT VC, mdoc
// matches by doctype (DCQL meta doctype_values) and by claim paths expressed as
// [namespace, elementIdentifier] rather than JSON-pointer-style nested paths.
// Returns (matched, reasonCode, reasonMessage). The existing SD-JWT VC matching
// in RequirementMatchesEvidence is unaffected; this is an added branch.
func RequirementMatchesMdoc(requirement DCQLCredentialRequirement, evidence MdocCredentialEvidence) (bool, string, string) {
	if requirement.Format != "" && strings.TrimSpace(evidence.Format) != requirement.Format {
		return false, "dcql_format_mismatch", fmt.Sprintf("credential format %q does not satisfy requested format %q", evidence.Format, requirement.Format)
	}
	if len(requirement.DoctypeValues) > 0 && !containsStringDCQL(requirement.DoctypeValues, strings.TrimSpace(evidence.Doctype)) {
		return false, "dcql_meta_mismatch", "credential doctype does not satisfy dcql doctype_values"
	}
	for _, authority := range requirement.TrustedAuthorities {
		if !strings.EqualFold(strings.TrimSpace(authority.Type), "aki") {
			continue
		}
		if !containsStringDCQL(authority.Values, strings.TrimSpace(evidence.IssuerAuthorityKeyIdentifier)) {
			return false, "dcql_trusted_authority_mismatch", "credential issuer Authority Key Identifier does not satisfy dcql trusted_authorities"
		}
	}
	for _, segments := range requirement.RequiredClaimPathSegments {
		switch len(segments) {
		case 0:
			continue
		case 1:
			// A single-segment mdoc path selects an entire namespace; require it
			// to be present with at least one disclosed element.
			namespace := strings.TrimSpace(segments[0])
			elements, ok := evidence.NameSpaces[namespace]
			if !ok || len(elements) == 0 {
				return false, "missing_required_claim", fmt.Sprintf("required namespace %q is missing from disclosed mdoc data", namespace)
			}
		default:
			// mdoc claim paths are [namespace, elementIdentifier]; any deeper
			// path is not a valid mdoc selector.
			if len(segments) != 2 {
				return false, "missing_required_claim", fmt.Sprintf("mdoc claim path %v must be [namespace, elementIdentifier]", segments)
			}
			namespace := strings.TrimSpace(segments[0])
			element := strings.TrimSpace(segments[1])
			elements, ok := evidence.NameSpaces[namespace]
			if !ok {
				return false, "missing_required_claim", fmt.Sprintf("required namespace %q is missing from disclosed mdoc data", namespace)
			}
			if _, ok := elements[element]; !ok {
				return false, "missing_required_claim", fmt.Sprintf("required element %q in namespace %q is missing from disclosed mdoc data", element, namespace)
			}
		}
	}
	return true, "", ""
}

// HasClaimPath checks whether a nested claim path exists in a claims map.
func HasClaimPath(claims map[string]interface{}, claimPath string) bool {
	segments := strings.Split(strings.TrimSpace(claimPath), ".")
	if len(segments) == 0 {
		return false
	}
	var current interface{} = claims
	for idx, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return false
		}
		object, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		value, exists := object[segment]
		if !exists {
			return false
		}
		if idx == len(segments)-1 {
			return true
		}
		current = value
	}
	return false
}

func stringValue(v interface{}) string {
	s, _ := v.(string)
	return s
}

func normalizeStringSliceDCQL(raw interface{}) []string {
	values := make([]string, 0)
	switch typed := raw.(type) {
	case string:
		if normalized := strings.TrimSpace(typed); normalized != "" {
			values = append(values, normalized)
		}
	case []interface{}:
		for _, item := range typed {
			itemString, _ := item.(string)
			itemString = strings.TrimSpace(itemString)
			if itemString == "" {
				continue
			}
			values = append(values, itemString)
		}
	}
	return dedupeStringsDCQL(values)
}

func dedupeStringsDCQL(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func containsStringDCQL(haystack []string, needle string) bool {
	for _, value := range haystack {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}

func intersectsStringSliceDCQL(left []string, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	lookup := make(map[string]struct{}, len(right))
	for _, value := range right {
		normalized := strings.TrimSpace(value)
		if normalized != "" {
			lookup[normalized] = struct{}{}
		}
	}
	for _, value := range left {
		if _, ok := lookup[strings.TrimSpace(value)]; ok {
			return true
		}
	}
	return false
}
