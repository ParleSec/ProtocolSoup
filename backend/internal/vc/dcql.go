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
			requiredPaths = append(requiredPaths, strings.Join(segments, "."))
		}
		requirement.RequiredClaimPaths = dedupeStringsDCQL(requiredPaths)
		sort.Strings(requirement.RequiredClaimPaths)
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
