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
	// ClaimSets is the DCQL claim_sets array (OID4VP 1.0 Section 6.1/6.4.1):
	// each inner slice is a set of claim `id`s (Section 6.3) that must ALL be
	// present together for that alternative to satisfy the requirement.
	// Evaluated in order; the first fully-satisfied set wins. An empty
	// ClaimSets preserves today's behaviour exactly: every entry in
	// RequiredClaimPaths/RequiredClaimPathSegments is required, unconditionally.
	ClaimSets [][]string
	// claimsByID maps each claim `id` declared in this credential query's
	// `claims` array to its path, for resolving ClaimSets entries. It is kept
	// as an id-keyed map rather than a third slice index-aligned with
	// RequiredClaimPaths/RequiredClaimPathSegments: those two are already
	// independently deduplicated (and, for RequiredClaimPaths, sorted) for
	// the pre-claim_sets matching path below, and a map has no ordering for
	// that dedup/sort to disturb. This keeps the non-claim_sets matching path
	// byte-for-byte identical to before claim_sets support was added.
	claimsByID map[string]dcqlClaimPath
	// unclaimedRequiredPaths/unclaimedRequiredPathSegments are the claims from
	// this query's `claims` array that were not assigned a DCQL `id`. Per
	// OID4VP 1.0 Section 6.3, `id` is REQUIRED once claim_sets is present, so
	// conformant queries should never populate these; they exist purely to
	// fail safe (treat an id-less claim as unconditionally required rather
	// than silently unenforceable) if ClaimSets is non-empty anyway.
	unclaimedRequiredPaths        []string
	unclaimedRequiredPathSegments [][]string
}

// dcqlClaimPath is the resolved path (in both the dot-joined and raw-segment
// forms used by RequirementMatchesEvidence and RequirementMatchesMdoc
// respectively) for one claim `id` referenced by ClaimSets.
type dcqlClaimPath struct {
	path     string
	segments []string
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
// supplied by the verifier after CollectDisclosedElements.
//
// This keeps the DCQL *matcher* free of any CBOR/COSE dependency -- it
// consumes this already-decoded shape rather than raw IssuerSigned bytes --
// which is narrower than saying the vc package itself has no CBOR
// dependency. MSOMdocFormat in format.go imports internal/mdoc (and
// therefore internal/cose) to register mso_mdoc as a CredentialFormat, so
// that package-wide boundary no longer holds; what still holds is that this
// matcher's own logic never decodes CBOR itself.
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

// DCQLQuery is a full DCQL query object (OID4VP 1.0 Section 6): the per-
// credential Credential Queries plus the top-level Credential Set Queries
// (Section 6.2) that constrain which combinations of them are needed.
type DCQLQuery struct {
	Credentials    []DCQLCredentialRequirement
	CredentialSets []DCQLCredentialSet
}

// DCQLCredentialSet is one entry of the top-level `credential_sets` array
// (OID4VP 1.0 Section 6.2, "Credential Set Query").
type DCQLCredentialSet struct {
	// Options is the REQUIRED, ordered list of alternative combinations; each
	// inner slice is a set of Credential Query `id`s (matching
	// DCQLCredentialRequirement.ID) that must ALL be satisfied together for
	// that option to count. The Verifier's preference order runs from the
	// first (most preferred) to the last (least preferred) option; a Wallet
	// SHOULD return the first option it can satisfy. Evaluated here in the
	// same order; the first fully-satisfied option wins.
	Options [][]string
	// Required defaults to true per spec (OPTIONAL, default value true).
	// When false, this set being unsatisfied does not fail the overall query.
	Required bool
}

// ParseDCQLCredentialRequirements parses a raw DCQL JSON query into structured requirements.
func ParseDCQLCredentialRequirements(rawDCQLQuery string) []DCQLCredentialRequirement {
	return ParseDCQLQuery(rawDCQLQuery).Credentials
}

// ParseDCQLQuery parses a raw DCQL JSON query into both its per-credential
// Credential Queries (`credentials`) and its top-level Credential Set Queries
// (`credential_sets`, OID4VP 1.0 Section 6.2). Callers that only need
// per-credential requirements (unaffected by credential_sets) can keep using
// ParseDCQLCredentialRequirements, which is now a thin wrapper around this;
// callers that must enforce credential_sets semantics use this directly.
func ParseDCQLQuery(rawDCQLQuery string) DCQLQuery {
	trimmed := strings.TrimSpace(rawDCQLQuery)
	if trimmed == "" {
		return DCQLQuery{}
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return DCQLQuery{}
	}
	rawCredentials, _ := payload["credentials"].([]interface{})
	requirements := make([]DCQLCredentialRequirement, 0, len(rawCredentials))
	for _, rawCredential := range rawCredentials {
		credentialObject, _ := rawCredential.(map[string]interface{})
		requirements = append(requirements, parseDCQLCredentialRequirement(credentialObject))
	}

	var credentialSets []DCQLCredentialSet
	if rawSets, ok := payload["credential_sets"].([]interface{}); ok {
		for _, rawSet := range rawSets {
			setObject, _ := rawSet.(map[string]interface{})
			credentialSets = append(credentialSets, parseDCQLCredentialSet(setObject))
		}
	}

	return DCQLQuery{Credentials: requirements, CredentialSets: credentialSets}
}

// parseDCQLCredentialSet parses one entry of the top-level `credential_sets`
// array (OID4VP 1.0 Section 6.2). `required` defaults to true when omitted or
// not a boolean, per spec.
func parseDCQLCredentialSet(setObject map[string]interface{}) DCQLCredentialSet {
	set := DCQLCredentialSet{Required: true}
	if requiredValue, ok := setObject["required"].(bool); ok {
		set.Required = requiredValue
	}
	rawOptions, _ := setObject["options"].([]interface{})
	for _, rawOption := range rawOptions {
		rawIDs, _ := rawOption.([]interface{})
		ids := make([]string, 0, len(rawIDs))
		for _, rawID := range rawIDs {
			id := strings.TrimSpace(stringValue(rawID))
			if id == "" {
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			continue
		}
		set.Options = append(set.Options, ids)
	}
	return set
}

// EvaluateCredentialSets checks whether the overall DCQL query's
// credential_sets requirement (OID4VP 1.0 Section 6.2/6.4.2) is satisfied,
// given which Credential Query IDs (DCQLCredentialRequirement.ID) were
// actually matched by presented/held credentials. Returns (satisfied,
// unsatisfiedRequiredSetIndexes), the latter naming (by index into
// query.CredentialSets) every REQUIRED set for which no option was fully
// matched.
//
// A query with no CredentialSets is always satisfied by this function --
// callers must still separately confirm every entry in DCQLQuery.Credentials
// was matched, exactly as before credential_sets support existed.
//
// When CredentialSets is non-empty, Section 6.4.2 changes what "required"
// means for the Credential Queries it references: a Credential Query id
// that appears in any CredentialSets option is only required as part of
// satisfying that option (adjudicated here), not unconditionally on its
// own -- only Credential Queries NOT referenced by any CredentialSets
// option remain unconditionally required. Callers should use
// CredentialIDsReferencedByCredentialSets to tell the two apart before
// hard-failing on an individual non-match.
func EvaluateCredentialSets(query DCQLQuery, matchedRequirementIDs map[string]bool) (bool, []int) {
	if len(query.CredentialSets) == 0 {
		return true, nil
	}
	var unsatisfiedRequired []int
	for index, set := range query.CredentialSets {
		satisfied := credentialSetOptionSatisfied(set, matchedRequirementIDs)
		if !satisfied && set.Required {
			unsatisfiedRequired = append(unsatisfiedRequired, index)
		}
	}
	return len(unsatisfiedRequired) == 0, unsatisfiedRequired
}

// credentialSetOptionSatisfied reports whether at least one option in set is
// fully covered by matchedRequirementIDs.
func credentialSetOptionSatisfied(set DCQLCredentialSet, matchedRequirementIDs map[string]bool) bool {
	for _, option := range set.Options {
		allMatched := true
		for _, id := range option {
			if !matchedRequirementIDs[id] {
				allMatched = false
				break
			}
		}
		if allMatched {
			return true
		}
	}
	return false
}

// CredentialIDsReferencedByCredentialSets returns the set of Credential Query
// `id`s referenced by any option of any entry in query.CredentialSets. It
// lets a verifier-side matcher tell a Credential Query that is unconditionally
// required (not referenced by credential_sets at all, so it must always be
// matched, exactly as before credential_sets support existed) apart from one
// that is only required via a credential_sets alternative (so an individual
// match failure should not fail the whole query by itself -- only
// EvaluateCredentialSets' verdict, computed over every attempted match,
// decides that).
func CredentialIDsReferencedByCredentialSets(query DCQLQuery) map[string]bool {
	if len(query.CredentialSets) == 0 {
		return nil
	}
	referenced := make(map[string]bool)
	for _, set := range query.CredentialSets {
		for _, option := range set.Options {
			for _, id := range option {
				referenced[id] = true
			}
		}
	}
	return referenced
}

// parseDCQLCredentialRequirement parses one entry of the DCQL `credentials`
// array (OID4VP 1.0 Section 6.1, "Credential Query") into a
// DCQLCredentialRequirement. Shared by ParseDCQLQuery (and, through it,
// ParseDCQLCredentialRequirements) so the per-credential parsing logic is
// never duplicated between the two entry points.
func parseDCQLCredentialRequirement(credentialObject map[string]interface{}) DCQLCredentialRequirement {
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
	claimsByID := make(map[string]dcqlClaimPath, len(rawClaims))
	var unclaimedPaths []string
	var unclaimedSegments [][]string
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
		// DCQL claims[].id (OID4VP 1.0 Section 6.3): REQUIRED once
		// claim_sets is present, OPTIONAL otherwise. Recorded unconditionally
		// (independent of whether this query happens to use claim_sets) so
		// claim_sets resolution never depends on parsing order.
		claimID := strings.TrimSpace(stringValue(claimObject["id"]))
		if claimID != "" {
			if _, exists := claimsByID[claimID]; !exists {
				claimsByID[claimID] = dcqlClaimPath{path: joined, segments: segments}
			}
		} else {
			unclaimedPaths = append(unclaimedPaths, joined)
			unclaimedSegments = append(unclaimedSegments, segments)
		}
	}
	requirement.RequiredClaimPaths = dedupeStringsDCQL(requiredPaths)
	sort.Strings(requirement.RequiredClaimPaths)
	requirement.RequiredClaimPathSegments = segmentLists
	if len(claimsByID) > 0 {
		requirement.claimsByID = claimsByID
	}
	requirement.unclaimedRequiredPaths = dedupeStringsDCQL(unclaimedPaths)
	requirement.unclaimedRequiredPathSegments = unclaimedSegments
	if rawClaimSets, ok := credentialObject["claim_sets"].([]interface{}); ok {
		for _, rawSet := range rawClaimSets {
			rawIDs, _ := rawSet.([]interface{})
			ids := make([]string, 0, len(rawIDs))
			for _, rawID := range rawIDs {
				id := strings.TrimSpace(stringValue(rawID))
				if id == "" {
					continue
				}
				ids = append(ids, id)
			}
			if len(ids) == 0 {
				continue
			}
			requirement.ClaimSets = append(requirement.ClaimSets, ids)
		}
	}
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
	return requirement
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
	if len(requirement.ClaimSets) == 0 {
		for _, claimPath := range requirement.RequiredClaimPaths {
			if !HasClaimPath(evidence.FullClaims, claimPath) {
				return false, "missing_required_claim", fmt.Sprintf("required claim %q is missing from disclosed credential data", claimPath)
			}
		}
		return true, "", ""
	}
	// claim_sets present (OID4VP 1.0 Section 6.4.1): claims without an id
	// cannot be referenced by any alternative and remain unconditionally
	// required; the id-referenced claims are satisfied if any one full
	// claim_sets alternative, evaluated in order, is fully disclosed.
	for _, claimPath := range requirement.unclaimedRequiredPaths {
		if !HasClaimPath(evidence.FullClaims, claimPath) {
			return false, "missing_required_claim", fmt.Sprintf("required claim %q is missing from disclosed credential data", claimPath)
		}
	}
	for _, claimSet := range requirement.ClaimSets {
		if claimSetSatisfiesEvidence(requirement.claimsByID, evidence, claimSet) {
			return true, "", ""
		}
	}
	return false, "missing_required_claim_set", fmt.Sprintf("no claim_sets alternative is fully disclosed (attempted %v)", requirement.ClaimSets)
}

// claimSetSatisfiesEvidence reports whether every claim id in claimSet
// resolves (via claimsByID) to a path present in the disclosed credential
// data. An id that does not resolve at all fails the whole alternative.
func claimSetSatisfiesEvidence(claimsByID map[string]dcqlClaimPath, evidence DCQLCredentialEvidence, claimSet []string) bool {
	for _, id := range claimSet {
		resolved, ok := claimsByID[id]
		if !ok || !HasClaimPath(evidence.FullClaims, resolved.path) {
			return false
		}
	}
	return true
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
	if len(requirement.ClaimSets) == 0 {
		for _, segments := range requirement.RequiredClaimPathSegments {
			if ok, reasonCode, reasonMessage := mdocSegmentDisclosed(evidence, segments); !ok {
				return false, reasonCode, reasonMessage
			}
		}
		return true, "", ""
	}
	// claim_sets present (OID4VP 1.0 Section 6.4.1): mirrors the SD-JWT VC
	// branch in RequirementMatchesEvidence above, resolving ids via
	// RequiredClaimPathSegments/claimsByID alignment instead of the
	// dot-joined form mdoc cannot use.
	for _, segments := range requirement.unclaimedRequiredPathSegments {
		if ok, reasonCode, reasonMessage := mdocSegmentDisclosed(evidence, segments); !ok {
			return false, reasonCode, reasonMessage
		}
	}
	for _, claimSet := range requirement.ClaimSets {
		if claimSetSatisfiesMdoc(requirement.claimsByID, evidence, claimSet) {
			return true, "", ""
		}
	}
	return false, "missing_required_claim_set", fmt.Sprintf("no claim_sets alternative is fully disclosed (attempted %v)", requirement.ClaimSets)
}

// mdocSegmentDisclosed reports whether a single mdoc claim path
// ([namespace] or [namespace, elementIdentifier]) is present in the
// disclosed mdoc evidence. Returns (matched, reasonCode, reasonMessage),
// mirroring the per-requirement return shape so callers can propagate it
// directly.
func mdocSegmentDisclosed(evidence MdocCredentialEvidence, segments []string) (bool, string, string) {
	switch len(segments) {
	case 0:
		return true, "", ""
	case 1:
		// A single-segment mdoc path selects an entire namespace; require it
		// to be present with at least one disclosed element.
		namespace := strings.TrimSpace(segments[0])
		elements, ok := evidence.NameSpaces[namespace]
		if !ok || len(elements) == 0 {
			return false, "missing_required_claim", fmt.Sprintf("required namespace %q is missing from disclosed mdoc data", namespace)
		}
		return true, "", ""
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
		return true, "", ""
	}
}

// claimSetSatisfiesMdoc reports whether every claim id in claimSet resolves
// (via claimsByID) to an mdoc segment path present in the disclosed
// evidence. An id that does not resolve at all fails the whole alternative.
func claimSetSatisfiesMdoc(claimsByID map[string]dcqlClaimPath, evidence MdocCredentialEvidence, claimSet []string) bool {
	for _, id := range claimSet {
		resolved, ok := claimsByID[id]
		if !ok {
			return false
		}
		if ok, _, _ := mdocSegmentDisclosed(evidence, resolved.segments); !ok {
			return false
		}
	}
	return true
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
