package vc

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
)

// CredentialEvidence is a shared, format-agnostic credential view for query engines.
type CredentialEvidence struct {
	Format          string
	VCT             string
	Doctype         string
	CredentialTypes []string
	FullClaims      map[string]interface{}
	DisclosedClaims map[string]interface{}
	// SelectiveDisclosure is nil for formats with no selective-disclosure
	// mechanism (jwt_vc_json, jwt_vc_json-ld, ldp_vc always reveal every
	// claim the credential carries) and populated for the two formats that
	// have one (mso_mdoc, dc+sd-jwt), each with a different exactness
	// property. See SelectiveDisclosureSummary.
	SelectiveDisclosure *SelectiveDisclosureSummary
	// IssuedAt and ExpiresAt mirror ParsedCredential's own fields verbatim
	// (mso_mdoc: MSO ValidityInfo.Signed/ValidUntil; ldp_vc:
	// issuanceDate/validFrom and expirationDate/validUntil; JWT-based
	// formats: the exp claim only, since parseJWTCredential does not read
	// iat). Each is the zero time.Time when the source credential does not
	// carry that claim -- callers must check IsZero rather than assume
	// presence, and this must never be back-filled with wall-clock time or
	// any other value the credential itself did not assert.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// CredentialLifecycleStage records whether a CredentialEvidence was captured
// at issuance or at presentation. It is a required parameter on
// BuildCredentialEvidence rather than a value the function infers, because it
// cannot be inferred from the artifact: an mDL presented with all 11 elements
// is byte-identical, in the respect that matters here, to the same mDL as
// issued. Only the caller knows which lifecycle point it is looking at.
type CredentialLifecycleStage string

const (
	LifecycleStageIssued    CredentialLifecycleStage = "issued"
	LifecycleStagePresented CredentialLifecycleStage = "presented"
)

// NamespaceDisclosureCounts carries mdoc per-namespace committed/present
// counts. mdoc only; SD-JWT has no namespace concept.
type NamespaceDisclosureCounts struct {
	CommittedCount int
	PresentCount   int
}

// SelectiveDisclosureSummary replaces the old
// ParsedCredential.HasKeyBindingJWT/DisclosureCount pair for evidence
// purposes -- those assumed SD-JWT tilde-counting semantics unconditionally,
// which is what let an mdoc render "disclosureCount: 0", a claim not sourced
// from the artifact and wrong about the format's actual mechanism (mdoc has
// no tildes; its selective disclosure lives in valueDigests). This shape is
// numeric for every format that has selective disclosure, and forces the
// caller to say which one it is rather than assume.
//
// CommittedCount cannot be read as "the true number of claims/elements this
// credential contains" for every format, which is the second thing the old
// single-number shape got wrong: it collapses two different epistemic
// statuses into one type. CommittedCountIsExact and Mechanism exist so the
// two never render identically.
type SelectiveDisclosureSummary struct {
	// Mechanism names what CommittedCount actually counts:
	// "mso_valuedigests" for mdoc, "sd_jwt_disclosures" for SD-JWT.
	Mechanism string
	// CommittedCount is the element/digest count the mechanism commits to.
	// For mdoc this is len(mso.ValueDigests[ns]) summed across namespaces --
	// a genuine count, since ISO/IEC 18013-5 has no decoy-digest mechanism.
	// For SD-JWT this is the count of digest strings found in "_sd" arrays
	// in the issuer-signed JWT payload (at any nesting level reachable
	// without decoding a disclosure) -- an upper bound, since SD-JWT
	// deliberately permits decoy digests so a verifier cannot infer the true
	// claim count from it.
	CommittedCount int
	// CommittedCountIsExact is true only for mso_valuedigests. False for
	// sd_jwt_disclosures unconditionally, even when this particular
	// credential happens to carry no decoys: the point is that the format
	// permits them, so no SD-JWT's count can be asserted as exact from the
	// digest count alone.
	CommittedCountIsExact bool
	// PresentCount is the element/disclosure count actually carried by this
	// artifact: len(issuerSigned.NameSpaces[ns]) summed for mdoc, or the
	// number of "~"-delimited Disclosures actually attached for SD-JWT.
	PresentCount int
	// LifecycleStage is carried verbatim from BuildCredentialEvidence's
	// required parameter. At LifecycleStageIssued, PresentCount is a
	// property of the format (an issuer sends every element/disclosure), not
	// a holder decision, and must never be worded as a disclosure ratio.
	// Only LifecycleStagePresented may use "N of M disclosed" phrasing.
	LifecycleStage CredentialLifecycleStage
	// DigestAlgorithm is mso.DigestAlgorithm ("SHA-256") for mdoc, or the
	// SD-JWT "_sd_alg" claim (defaulting to "sha-256" per the SD-JWT spec
	// when the claim is absent).
	DigestAlgorithm string
	// PerNamespace carries mdoc per-namespace committed/present counts. Nil
	// for SD-JWT, which has no namespace concept.
	PerNamespace map[string]NamespaceDisclosureCounts
	// HasUnrepresentedDisclosureForms is true when an SD-JWT structure
	// contains a disclosure form CommittedCount's flat "_sd" walk does not
	// represent: an array-element redaction marker ({"...": "<digest>"}), or
	// a disclosed claim whose own value contains a further "_sd" array
	// (structured/nested disclosure, only visible once that claim is
	// decoded). Always false for mdoc. When true, the UI must say the
	// structure contains more disclosure forms than the count shows, rather
	// than let the number stand as if it were complete.
	HasUnrepresentedDisclosureForms bool
}

// PresentationDefinition is the parsed Presentation Exchange definition used by the wallet.
type PresentationDefinition struct {
	ID               string
	InputDescriptors []PresentationInputDescriptor
}

// PresentationInputDescriptor captures the fields the wallet needs for matching and submission building.
type PresentationInputDescriptor struct {
	ID                string
	FormatConstraints map[string]map[string]interface{}
	Constraints       PresentationConstraints
}

// PresentationConstraints captures a descriptor's field constraints.
type PresentationConstraints struct {
	LimitDisclosure string
	Fields          []PresentationField
}

// PresentationField is one field constraint entry from a descriptor.
type PresentationField struct {
	Paths    []string
	Filter   map[string]interface{}
	Optional bool
}

// PresentationCandidate represents one credential found inside the submitted vp_token.
type PresentationCandidate struct {
	RootFormat        string
	RootPath          string
	CredentialPath    string
	CredentialFormats []string
	Evidence          CredentialEvidence
}

// DescriptorMatch captures a successful mapping between an input descriptor and a presented credential.
type DescriptorMatch struct {
	DescriptorID     string
	RootFormat       string
	RootPath         string
	CredentialPath   string
	CredentialFormat string
}

// ParsePresentationDefinition converts the raw request object presentation_definition into typed fields.
func ParsePresentationDefinition(raw map[string]interface{}) (*PresentationDefinition, error) {
	if raw == nil {
		return nil, fmt.Errorf("presentation definition is required")
	}

	definition := &PresentationDefinition{
		ID: strings.TrimSpace(formatStringPE(raw["id"])),
	}
	rawDescriptors, _ := raw["input_descriptors"].([]interface{})
	for _, rawDescriptor := range rawDescriptors {
		descriptorObject, _ := rawDescriptor.(map[string]interface{})
		if len(descriptorObject) == 0 {
			continue
		}

		descriptor := PresentationInputDescriptor{
			ID:                strings.TrimSpace(formatStringPE(descriptorObject["id"])),
			FormatConstraints: parseDescriptorFormats(descriptorObject["format"]),
			Constraints:       parseDescriptorConstraints(descriptorObject["constraints"]),
		}
		if descriptor.ID == "" {
			continue
		}
		definition.InputDescriptors = append(definition.InputDescriptors, descriptor)
	}
	return definition, nil
}

// BuildCredentialEvidence parses a raw credential into the shared evidence
// model used by DCQL and PE. lifecycleStage is required (LifecycleStageIssued
// or LifecycleStagePresented) and rejected on any other value, including the
// zero value: it names a fact about the caller's context that cannot be
// recovered from the credential bytes themselves, and Go's empty string
// would otherwise compile fine at a new call site and silently default into
// the wrong wording downstream. See CredentialLifecycleStage.
func BuildCredentialEvidence(rawCredential string, lifecycleStage CredentialLifecycleStage) (*CredentialEvidence, error) {
	if lifecycleStage != LifecycleStageIssued && lifecycleStage != LifecycleStagePresented {
		return nil, fmt.Errorf("vc: lifecycle stage must be %q or %q, got %q", LifecycleStageIssued, LifecycleStagePresented, lifecycleStage)
	}
	parsed, err := DefaultCredentialFormatRegistry().ParseAnyCredential(strings.TrimSpace(rawCredential))
	if err != nil {
		return nil, err
	}

	fullClaims := deepCopyMapPE(parsed.Claims)
	disclosedClaims := map[string]interface{}{}
	aliasVerifiableCredentialClaimsPE(fullClaims, parsed.VCClaims)
	aliasMSOMDocClaimsPE(fullClaims)
	var selectiveDisclosure *SelectiveDisclosureSummary
	if parsed.IsSDJWT {
		envelope, err := ParseSDJWTEnvelope(parsed.Original)
		if err != nil {
			return nil, err
		}
		committedCount, hasUnrepresentedForms := countSDJWTCommittedDigestsPE(parsed.Claims)
		for _, disclosure := range envelope.Disclosures {
			decodedDisclosure, err := DecodeSDJWTDisclosure(disclosure)
			if err != nil {
				return nil, err
			}
			claimName := strings.TrimSpace(decodedDisclosure.ClaimName)
			if claimName == "" {
				continue
			}
			disclosedClaims[claimName] = deepCopyJSONValuePE(decodedDisclosure.ClaimValue)
			// A disclosed claim's own value can carry a further "_sd" array
			// (SD-JWT's structured/nested disclosure), which is invisible to
			// countSDJWTCommittedDigestsPE above because it only walks the
			// issuer-signed payload, not what decoding a disclosure reveals.
			if claimValueMap, ok := decodedDisclosure.ClaimValue.(map[string]interface{}); ok {
				if _, hasNestedSD := claimValueMap["_sd"]; hasNestedSD {
					hasUnrepresentedForms = true
				}
			}
		}
		mergeDisclosedClaimsPE(fullClaims, disclosedClaims)
		selectiveDisclosure = &SelectiveDisclosureSummary{
			Mechanism:                       "sd_jwt_disclosures",
			CommittedCount:                  committedCount,
			CommittedCountIsExact:           false,
			PresentCount:                    len(envelope.Disclosures),
			LifecycleStage:                  lifecycleStage,
			DigestAlgorithm:                 sdJWTDigestAlgorithmPE(parsed.Claims),
			HasUnrepresentedDisclosureForms: hasUnrepresentedForms,
		}
	} else if strings.EqualFold(parsed.Format, "mso_mdoc") {
		selectiveDisclosure, err = mdocSelectiveDisclosureSummaryPE(parsed.Original, lifecycleStage)
		if err != nil {
			return nil, err
		}
	}
	flattenCredentialSubjectClaimsPE(fullClaims)

	return &CredentialEvidence{
		Format:              parsed.Format,
		VCT:                 parsed.VCT,
		Doctype:             parsed.Doctype,
		CredentialTypes:     append([]string{}, parsed.CredentialTypes...),
		FullClaims:          fullClaims,
		DisclosedClaims:     disclosedClaims,
		SelectiveDisclosure: selectiveDisclosure,
		IssuedAt:            parsed.IssuedAt,
		ExpiresAt:           parsed.ExpiresAt,
	}, nil
}

// sdJWTDigestAlgorithmPE reads the SD-JWT "_sd_alg" claim from the
// issuer-signed payload, defaulting to "sha-256" per SD-JWT (draft-ietf-oauth
// -selective-disclosure-jwt) Section 5.1.1's rule that a verifier MUST assume
// sha-256 when the claim is absent.
func sdJWTDigestAlgorithmPE(payload map[string]interface{}) string {
	if alg, ok := payload["_sd_alg"].(string); ok {
		if trimmed := strings.TrimSpace(alg); trimmed != "" {
			return trimmed
		}
	}
	return "sha-256"
}

// countSDJWTCommittedDigestsPE walks an SD-JWT issuer-signed payload (or a
// value nested within it) and returns the total digest count across every
// "_sd" array reachable without decoding a disclosure, plus whether an
// array-element redaction marker ({"...": "<digest>"}) was found. Per
// SelectiveDisclosureSummary.CommittedCount, this is an upper bound on the
// claim count, not the count itself: SD-JWT permits decoy digests inside
// "_sd" specifically so a verifier cannot infer how many claims exist, and
// this function counts every entry in "_sd" without attempting to tell a
// decoy from a real one, which is not possible from the payload alone.
func countSDJWTCommittedDigestsPE(value interface{}) (count int, hasArrayElementMarker bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, val := range typed {
			if key == "_sd" {
				if sdArray, ok := val.([]interface{}); ok {
					count += len(sdArray)
				}
				continue
			}
			nestedCount, nestedMarker := countSDJWTCommittedDigestsPE(val)
			count += nestedCount
			hasArrayElementMarker = hasArrayElementMarker || nestedMarker
		}
	case []interface{}:
		for _, element := range typed {
			if elementMap, ok := element.(map[string]interface{}); ok && len(elementMap) == 1 {
				if _, ok := elementMap["..."]; ok {
					hasArrayElementMarker = true
					continue
				}
			}
			nestedCount, nestedMarker := countSDJWTCommittedDigestsPE(element)
			count += nestedCount
			hasArrayElementMarker = hasArrayElementMarker || nestedMarker
		}
	}
	return count, hasArrayElementMarker
}

// mdocSelectiveDisclosureSummaryPE recomputes the mdoc selective-disclosure
// summary from the raw credential rather than from ParsedCredential, which is
// deliberately format-agnostic and does not carry the MSO's ValueDigests --
// the same reason the SD-JWT branch above re-parses the envelope rather than
// reading it from ParsedCredential.
func mdocSelectiveDisclosureSummaryPE(rawCredential string, lifecycleStage CredentialLifecycleStage) (*SelectiveDisclosureSummary, error) {
	issuerSigned, err := decodeMdocIssuerSignedGated(rawCredential)
	if err != nil {
		return nil, err
	}
	msoBytes, _, err := mdoc.ParseIssuerAuth(issuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("mdoc: parse IssuerAuth: %w", err)
	}
	mso, err := mdoc.DecodeMSOBytes(msoBytes)
	if err != nil {
		return nil, fmt.Errorf("mdoc: decode MobileSecurityObject: %w", err)
	}

	perNamespace := make(map[string]NamespaceDisclosureCounts, len(mso.ValueDigests))
	committedTotal := 0
	for ns, digests := range mso.ValueDigests {
		committedTotal += len(digests)
		counts := perNamespace[ns]
		counts.CommittedCount = len(digests)
		perNamespace[ns] = counts
	}
	presentTotal := 0
	for ns, items := range issuerSigned.NameSpaces {
		presentTotal += len(items)
		counts := perNamespace[ns]
		counts.PresentCount = len(items)
		perNamespace[ns] = counts
	}

	return &SelectiveDisclosureSummary{
		Mechanism:             "mso_valuedigests",
		CommittedCount:        committedTotal,
		CommittedCountIsExact: true,
		PresentCount:          presentTotal,
		LifecycleStage:        lifecycleStage,
		DigestAlgorithm:       mso.DigestAlgorithm,
		PerNamespace:          perNamespace,
	}, nil
}

// MatchCredentialToDescriptor evaluates whether a presented credential satisfies one input descriptor.
func MatchCredentialToDescriptor(descriptor PresentationInputDescriptor, candidate PresentationCandidate) (*DescriptorMatch, error) {
	selectedFormat, ok := selectDescriptorCredentialFormat(descriptor, candidate.CredentialFormats)
	if !ok {
		return nil, fmt.Errorf("descriptor %q does not allow the presented credential format", descriptor.ID)
	}
	for _, field := range descriptor.Constraints.Fields {
		if fieldMatchesPE(candidate.Evidence.FullClaims, field) {
			continue
		}
		if field.Optional {
			continue
		}
		return nil, fmt.Errorf("descriptor %q constraint paths %v did not match the presented credential", descriptor.ID, field.Paths)
	}
	return &DescriptorMatch{
		DescriptorID:     descriptor.ID,
		RootFormat:       candidate.RootFormat,
		RootPath:         candidate.RootPath,
		CredentialPath:   candidate.CredentialPath,
		CredentialFormat: selectedFormat,
	}, nil
}

// BuildPresentationSubmission creates the PE presentation_submission JSON for the submitted vp_token.
func BuildPresentationSubmission(rawDefinition map[string]interface{}, vpToken string) (string, error) {
	definition, err := ParsePresentationDefinition(rawDefinition)
	if err != nil {
		return "", err
	}
	if len(definition.InputDescriptors) == 0 {
		return "", fmt.Errorf("presentation definition has no input_descriptors")
	}

	candidates, err := ExtractPresentationCandidates(vpToken)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("vp_token does not contain any presentable credentials")
	}

	descriptorMap := make([]map[string]interface{}, 0, len(definition.InputDescriptors))
	for _, descriptor := range definition.InputDescriptors {
		var (
			match   *DescriptorMatch
			lastErr error
		)
		for _, candidate := range candidates {
			match, err = MatchCredentialToDescriptor(descriptor, candidate)
			if err == nil {
				break
			}
			lastErr = err
		}
		if match == nil {
			if lastErr == nil {
				lastErr = fmt.Errorf("descriptor %q did not match any presented credential", descriptor.ID)
			}
			return "", lastErr
		}

		entry := map[string]interface{}{
			"id":     match.DescriptorID,
			"path":   match.RootPath,
			"format": match.RootFormat,
		}
		if match.CredentialPath != "" && match.CredentialPath != match.RootPath {
			entry["path_nested"] = map[string]interface{}{
				"format": match.CredentialFormat,
				"path":   match.CredentialPath,
			}
		}
		descriptorMap = append(descriptorMap, entry)
	}

	definitionID := definition.ID
	if definitionID == "" {
		definitionID = "unknown"
	}
	submission := map[string]interface{}{
		"id":             randomFormatValue(16),
		"definition_id":  definitionID,
		"descriptor_map": descriptorMap,
	}
	encoded, err := json.Marshal(submission)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// ExtractPresentationCandidates parses the wallet's vp_token into candidate credentials for descriptor matching.
func ExtractPresentationCandidates(vpToken string) ([]PresentationCandidate, error) {
	normalized := strings.TrimSpace(vpToken)
	if normalized == "" {
		return nil, fmt.Errorf("vp_token is required")
	}

	if envelope, err := ParseSDJWTEnvelope(normalized); err == nil {
		_ = envelope
		// ExtractPresentationCandidates operates on a vp_token by definition,
		// so every candidate it produces is LifecycleStagePresented.
		evidence, err := BuildCredentialEvidence(normalized, LifecycleStagePresented)
		if err != nil {
			return nil, err
		}
		return []PresentationCandidate{
			{
				RootFormat:        "vc+sd-jwt",
				RootPath:          "$",
				CredentialPath:    "$",
				CredentialFormats: []string{"vc+sd-jwt"},
				Evidence:          *evidence,
			},
		}, nil
	}

	if decodedVPToken, err := intcrypto.DecodeTokenWithoutValidation(normalized); err == nil {
		if vpObject, ok := decodedVPToken.Payload["vp"].(map[string]interface{}); ok {
			rawCredentials, _ := vpObject["verifiableCredential"].([]interface{})
			candidates := make([]PresentationCandidate, 0, len(rawCredentials))
			for idx, rawCredential := range rawCredentials {
				credentialString, err := normalizeCredentialValuePE(rawCredential)
				if err != nil {
					return nil, err
				}
				evidence, err := BuildCredentialEvidence(credentialString, LifecycleStagePresented)
				if err != nil {
					return nil, err
				}
				parsed, err := DefaultCredentialFormatRegistry().ParseAnyCredential(credentialString)
				if err != nil {
					return nil, err
				}
				candidates = append(candidates, PresentationCandidate{
					RootFormat:        "jwt_vp_json",
					RootPath:          "$",
					CredentialPath:    fmt.Sprintf("$.vp.verifiableCredential[%d]", idx),
					CredentialFormats: nestedPresentationFormatsPE(parsed),
					Evidence:          *evidence,
				})
			}
			if len(candidates) > 0 {
				return candidates, nil
			}
		}
	}

	if strings.HasPrefix(normalized, "{") {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(normalized), &payload); err == nil {
			rawCredentials, _ := payload["verifiableCredential"].([]interface{})
			candidates := make([]PresentationCandidate, 0, len(rawCredentials))
			for idx, rawCredential := range rawCredentials {
				credentialString, err := normalizeCredentialValuePE(rawCredential)
				if err != nil {
					return nil, err
				}
				evidence, err := BuildCredentialEvidence(credentialString, LifecycleStagePresented)
				if err != nil {
					return nil, err
				}
				parsed, err := DefaultCredentialFormatRegistry().ParseAnyCredential(credentialString)
				if err != nil {
					return nil, err
				}
				candidates = append(candidates, PresentationCandidate{
					RootFormat:        "ldp_vp",
					RootPath:          "$",
					CredentialPath:    fmt.Sprintf("$.verifiableCredential[%d]", idx),
					CredentialFormats: nestedPresentationFormatsPE(parsed),
					Evidence:          *evidence,
				})
			}
			if len(candidates) > 0 {
				return candidates, nil
			}
		}
	}

	return nil, fmt.Errorf("unsupported vp_token format for presentation exchange")
}

// EvaluateJSONPath evaluates a minimal, safe subset of JSONPath against a JSON-like value.
func EvaluateJSONPath(root interface{}, expression string) ([]interface{}, error) {
	segments, err := parseJSONPathPE(expression)
	if err != nil {
		return nil, err
	}
	values := []interface{}{root}
	for _, segment := range segments {
		next := make([]interface{}, 0)
		for _, value := range values {
			next = append(next, applyJSONPathSegmentPE(value, segment)...)
		}
		values = next
		if len(values) == 0 {
			break
		}
	}
	return values, nil
}

func parseDescriptorFormats(raw interface{}) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{})
	formatObject, _ := raw.(map[string]interface{})
	for formatID, rawConfig := range formatObject {
		config, _ := rawConfig.(map[string]interface{})
		result[strings.TrimSpace(formatID)] = config
	}
	return result
}

func parseDescriptorConstraints(raw interface{}) PresentationConstraints {
	result := PresentationConstraints{}
	constraintsObject, _ := raw.(map[string]interface{})
	result.LimitDisclosure = strings.TrimSpace(formatStringPE(constraintsObject["limit_disclosure"]))
	rawFields, _ := constraintsObject["fields"].([]interface{})
	for _, rawField := range rawFields {
		fieldObject, _ := rawField.(map[string]interface{})
		if len(fieldObject) == 0 {
			continue
		}
		field := PresentationField{
			Paths:    normalizePathListPE(fieldObject["path"]),
			Optional: boolValuePE(fieldObject["optional"]),
		}
		if filterObject, ok := fieldObject["filter"].(map[string]interface{}); ok {
			field.Filter = filterObject
		}
		result.Fields = append(result.Fields, field)
	}
	return result
}

func normalizePathListPE(raw interface{}) []string {
	values := make([]string, 0)
	switch typed := raw.(type) {
	case []interface{}:
		for _, value := range typed {
			normalized := strings.TrimSpace(formatStringPE(value))
			if normalized != "" {
				values = append(values, normalized)
			}
		}
	case []string:
		for _, value := range typed {
			normalized := strings.TrimSpace(value)
			if normalized != "" {
				values = append(values, normalized)
			}
		}
	case string:
		if normalized := strings.TrimSpace(typed); normalized != "" {
			values = append(values, normalized)
		}
	}
	return dedupeStringsFormat(values)
}

func selectDescriptorCredentialFormat(descriptor PresentationInputDescriptor, candidateFormats []string) (string, bool) {
	if len(candidateFormats) == 0 {
		return "", false
	}
	if len(descriptor.FormatConstraints) == 0 {
		return candidateFormats[0], true
	}
	for _, candidateFormat := range candidateFormats {
		if _, ok := descriptor.FormatConstraints[candidateFormat]; ok {
			return candidateFormat, true
		}
	}
	return "", false
}

func fieldMatchesPE(claims map[string]interface{}, field PresentationField) bool {
	if len(field.Paths) == 0 {
		return field.Optional
	}
	for _, path := range field.Paths {
		values, err := EvaluateJSONPath(claims, path)
		if err != nil || len(values) == 0 {
			continue
		}
		if len(field.Filter) == 0 {
			return true
		}
		for _, value := range values {
			if valueMatchesFilterPE(value, field.Filter) {
				return true
			}
		}
	}
	return field.Optional
}

func valueMatchesFilterPE(value interface{}, filter map[string]interface{}) bool {
	if len(filter) == 0 {
		return true
	}
	if typeName := strings.TrimSpace(formatStringPE(filter["type"])); typeName != "" && !valueMatchesTypePE(value, typeName) {
		return false
	}
	if constValue, ok := filter["const"]; ok && !valuesEqualPE(value, constValue) {
		return false
	}
	if rawEnum, ok := filter["enum"].([]interface{}); ok && len(rawEnum) > 0 {
		matched := false
		for _, enumValue := range rawEnum {
			if valuesEqualPE(value, enumValue) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if rawContains, ok := filter["contains"]; ok {
		matchesContains := false
		switch typed := value.(type) {
		case []interface{}:
			for _, item := range typed {
				if nestedFilter, ok := rawContains.(map[string]interface{}); ok {
					if valueMatchesFilterPE(item, nestedFilter) {
						matchesContains = true
						break
					}
				} else if valuesEqualPE(item, rawContains) {
					matchesContains = true
					break
				}
			}
		case []string:
			for _, item := range typed {
				if nestedFilter, ok := rawContains.(map[string]interface{}); ok {
					if valueMatchesFilterPE(item, nestedFilter) {
						matchesContains = true
						break
					}
				} else if valuesEqualPE(item, rawContains) {
					matchesContains = true
					break
				}
			}
		default:
			return false
		}
		if !matchesContains {
			return false
		}
	}
	if rawAllOf, ok := filter["allOf"].([]interface{}); ok {
		for _, rawNestedFilter := range rawAllOf {
			nestedFilter, _ := rawNestedFilter.(map[string]interface{})
			if len(nestedFilter) == 0 {
				continue
			}
			if !valueMatchesFilterPE(value, nestedFilter) {
				return false
			}
		}
	}
	return true
}

func valueMatchesTypePE(value interface{}, expected string) bool {
	switch expected {
	case "string":
		_, ok := value.(string)
		return ok
	case "array":
		switch value.(type) {
		case []interface{}, []string:
			return true
		default:
			return false
		}
	case "object":
		_, ok := value.(map[string]interface{})
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		switch value.(type) {
		case float64, float32, int, int32, int64, json.Number:
			return true
		default:
			return false
		}
	case "integer":
		switch typed := value.(type) {
		case int, int32, int64:
			return true
		case float64:
			return typed == float64(int64(typed))
		case json.Number:
			_, err := typed.Int64()
			return err == nil
		default:
			return false
		}
	default:
		return true
	}
}

func valuesEqualPE(left interface{}, right interface{}) bool {
	return reflect.DeepEqual(normalizeComparableJSONValuePE(left), normalizeComparableJSONValuePE(right))
}

func normalizeComparableJSONValuePE(value interface{}) interface{} {
	switch typed := value.(type) {
	case []string:
		result := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			result = append(result, normalizeComparableJSONValuePE(item))
		}
		return result
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			result = append(result, normalizeComparableJSONValuePE(item))
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			result[key] = normalizeComparableJSONValuePE(item)
		}
		return result
	case int:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case float32:
		return float64(typed)
	default:
		return typed
	}
}

type jsonPathSegmentPE struct {
	property string
	index    *int
	wildcard bool
}

func parseJSONPathPE(expression string) ([]jsonPathSegmentPE, error) {
	normalized := strings.TrimSpace(expression)
	if normalized == "" {
		return nil, fmt.Errorf("jsonpath is required")
	}
	if normalized == "$" {
		return nil, nil
	}
	if !strings.HasPrefix(normalized, "$") {
		return nil, fmt.Errorf("jsonpath %q must start with $", expression)
	}

	segments := make([]jsonPathSegmentPE, 0)
	for idx := 1; idx < len(normalized); {
		switch normalized[idx] {
		case '.':
			idx++
			start := idx
			for idx < len(normalized) && normalized[idx] != '.' && normalized[idx] != '[' {
				idx++
			}
			if start == idx {
				return nil, fmt.Errorf("jsonpath %q contains an empty property segment", expression)
			}
			segments = append(segments, jsonPathSegmentPE{property: normalized[start:idx]})
		case '[':
			idx++
			if idx >= len(normalized) {
				return nil, fmt.Errorf("jsonpath %q has an unterminated bracket", expression)
			}
			if normalized[idx] == '\'' || normalized[idx] == '"' {
				quote := normalized[idx]
				idx++
				start := idx
				for idx < len(normalized) && normalized[idx] != quote {
					idx++
				}
				if idx >= len(normalized) {
					return nil, fmt.Errorf("jsonpath %q has an unterminated quoted property", expression)
				}
				property := normalized[start:idx]
				idx++
				if idx >= len(normalized) || normalized[idx] != ']' {
					return nil, fmt.Errorf("jsonpath %q has an invalid quoted property segment", expression)
				}
				idx++
				segments = append(segments, jsonPathSegmentPE{property: property})
				continue
			}
			if normalized[idx] == '*' {
				idx++
				if idx >= len(normalized) || normalized[idx] != ']' {
					return nil, fmt.Errorf("jsonpath %q has an invalid wildcard segment", expression)
				}
				idx++
				segments = append(segments, jsonPathSegmentPE{wildcard: true})
				continue
			}
			start := idx
			for idx < len(normalized) && normalized[idx] != ']' {
				idx++
			}
			if idx >= len(normalized) {
				return nil, fmt.Errorf("jsonpath %q has an unterminated index segment", expression)
			}
			indexValue, err := strconv.Atoi(normalized[start:idx])
			if err != nil {
				return nil, fmt.Errorf("jsonpath %q has an invalid array index", expression)
			}
			idx++
			segments = append(segments, jsonPathSegmentPE{index: &indexValue})
		default:
			return nil, fmt.Errorf("jsonpath %q contains unsupported syntax", expression)
		}
	}
	return segments, nil
}

func applyJSONPathSegmentPE(value interface{}, segment jsonPathSegmentPE) []interface{} {
	switch {
	case segment.property != "":
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		child, exists := object[segment.property]
		if !exists {
			return nil
		}
		return []interface{}{child}
	case segment.index != nil:
		switch typed := value.(type) {
		case []interface{}:
			if *segment.index < 0 || *segment.index >= len(typed) {
				return nil
			}
			return []interface{}{typed[*segment.index]}
		case []string:
			if *segment.index < 0 || *segment.index >= len(typed) {
				return nil
			}
			return []interface{}{typed[*segment.index]}
		default:
			return nil
		}
	case segment.wildcard:
		switch typed := value.(type) {
		case []interface{}:
			return append([]interface{}{}, typed...)
		case []string:
			result := make([]interface{}, 0, len(typed))
			for _, item := range typed {
				result = append(result, item)
			}
			return result
		case map[string]interface{}:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			result := make([]interface{}, 0, len(keys))
			for _, key := range keys {
				result = append(result, typed[key])
			}
			return result
		default:
			return nil
		}
	default:
		return nil
	}
}

func normalizeCredentialValuePE(raw interface{}) (string, error) {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed), nil
	case map[string]interface{}:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	default:
		return "", fmt.Errorf("unsupported credential value type %T", raw)
	}
}

func nestedPresentationFormatsPE(parsed *ParsedCredential) []string {
	if parsed == nil {
		return nil
	}
	switch parsed.Format {
	case "jwt_vc_json":
		return []string{"jwt_vc_json", "jwt_vc"}
	case "jwt_vc_json-ld":
		return []string{"jwt_vc_json-ld", "jwt_vc_json", "jwt_vc"}
	case "ldp_vc":
		return []string{"ldp_vc"}
	case "dc+sd-jwt":
		formats := []string{"vc+sd-jwt"}
		if len(parsed.VCClaims) > 0 {
			if _, hasContext := parsed.VCClaims["@context"]; hasContext {
				formats = append(formats, "jwt_vc_json-ld")
			}
			formats = append(formats, "jwt_vc_json", "jwt_vc")
		}
		return dedupeStringsFormat(formats)
	default:
		if normalized := strings.TrimSpace(parsed.Format); normalized != "" {
			return []string{normalized}
		}
		return nil
	}
}

func mergeDisclosedClaimsPE(fullClaims map[string]interface{}, disclosedClaims map[string]interface{}) {
	if len(fullClaims) == 0 {
		return
	}
	for claimName, claimValue := range disclosedClaims {
		if _, exists := fullClaims[claimName]; !exists {
			fullClaims[claimName] = deepCopyJSONValuePE(claimValue)
		}
	}
	if vcObject, ok := fullClaims["vc"].(map[string]interface{}); ok {
		credentialSubject := map[string]interface{}{}
		if existingSubject, ok := vcObject["credentialSubject"].(map[string]interface{}); ok {
			credentialSubject = deepCopyMapPE(existingSubject)
		}
		for claimName, claimValue := range disclosedClaims {
			if _, exists := credentialSubject[claimName]; !exists {
				credentialSubject[claimName] = deepCopyJSONValuePE(claimValue)
			}
		}
		vcObject["credentialSubject"] = credentialSubject
		fullClaims["vc"] = vcObject
	}
	if credentialSubject, ok := fullClaims["credentialSubject"].(map[string]interface{}); ok {
		copiedSubject := deepCopyMapPE(credentialSubject)
		for claimName, claimValue := range disclosedClaims {
			if _, exists := copiedSubject[claimName]; !exists {
				copiedSubject[claimName] = deepCopyJSONValuePE(claimValue)
			}
		}
		fullClaims["credentialSubject"] = copiedSubject
	}
}

func aliasVerifiableCredentialClaimsPE(fullClaims map[string]interface{}, vcClaims map[string]interface{}) {
	if len(fullClaims) == 0 || len(vcClaims) == 0 {
		return
	}
	if credentialSubject, ok := vcClaims["credentialSubject"]; ok {
		if _, exists := fullClaims["credentialSubject"]; !exists {
			fullClaims["credentialSubject"] = deepCopyJSONValuePE(credentialSubject)
		}
	}
	if credentialTypes, ok := vcClaims["type"]; ok {
		if _, exists := fullClaims["type"]; !exists {
			fullClaims["type"] = deepCopyJSONValuePE(credentialTypes)
		}
	}
	if contexts, ok := vcClaims["@context"]; ok {
		if _, exists := fullClaims["@context"]; !exists {
			fullClaims["@context"] = deepCopyJSONValuePE(contexts)
		}
	}
}

func aliasMSOMDocClaimsPE(fullClaims map[string]interface{}) {
	if len(fullClaims) == 0 {
		return
	}
	mdocObject, ok := fullClaims["mdoc"].(map[string]interface{})
	if !ok || len(mdocObject) == 0 {
		return
	}
	rawNamespaces, ok := mdocObject["namespaces"].(map[string]interface{})
	if !ok || len(rawNamespaces) == 0 {
		return
	}
	credentialSubject := map[string]interface{}{}
	if existingSubject, ok := fullClaims["credentialSubject"].(map[string]interface{}); ok {
		credentialSubject = deepCopyMapPE(existingSubject)
	}
	mergeMSOMDocNamespaceClaimsPE(credentialSubject, rawNamespaces)
	if len(credentialSubject) == 0 {
		return
	}
	fullClaims["credentialSubject"] = credentialSubject
}

func mergeMSOMDocNamespaceClaimsPE(target map[string]interface{}, source map[string]interface{}) {
	if len(target) == 0 && len(source) == 0 {
		return
	}
	for claimName, claimValue := range source {
		normalizedClaimName := strings.TrimSpace(claimName)
		if normalizedClaimName == "" {
			continue
		}
		if nestedClaims, ok := claimValue.(map[string]interface{}); ok && looksLikeMSOMDocNamespaceBucketPE(normalizedClaimName) {
			mergeMSOMDocNamespaceClaimsPE(target, nestedClaims)
			continue
		}
		if _, exists := target[normalizedClaimName]; exists {
			continue
		}
		target[normalizedClaimName] = deepCopyJSONValuePE(claimValue)
	}
}

func looksLikeMSOMDocNamespaceBucketPE(name string) bool {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return false
	}
	return strings.Contains(normalized, ".") || strings.Contains(normalized, ":") || strings.Contains(normalized, "/")
}

func flattenCredentialSubjectClaimsPE(fullClaims map[string]interface{}) {
	if len(fullClaims) == 0 {
		return
	}
	var credentialSubject map[string]interface{}
	if vcObject, ok := fullClaims["vc"].(map[string]interface{}); ok {
		if nestedSubject, ok := vcObject["credentialSubject"].(map[string]interface{}); ok {
			credentialSubject = nestedSubject
		}
	}
	if credentialSubject == nil {
		if nestedSubject, ok := fullClaims["credentialSubject"].(map[string]interface{}); ok {
			credentialSubject = nestedSubject
		}
	}
	for claimName, claimValue := range credentialSubject {
		if claimName == "_sd" || claimName == "_sd_alg" {
			continue
		}
		if _, exists := fullClaims[claimName]; exists {
			continue
		}
		fullClaims[claimName] = deepCopyJSONValuePE(claimValue)
	}
}

func deepCopyMapPE(source map[string]interface{}) map[string]interface{} {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = deepCopyJSONValuePE(value)
	}
	return result
}

func deepCopyJSONValuePE(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return deepCopyMapPE(typed)
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			result = append(result, deepCopyJSONValuePE(item))
		}
		return result
	case []string:
		result := make([]string, len(typed))
		copy(result, typed)
		return result
	default:
		return typed
	}
}

func boolValuePE(value interface{}) bool {
	booleanValue, _ := value.(bool)
	return booleanValue
}

func formatStringPE(value interface{}) string {
	stringValue, _ := value.(string)
	return stringValue
}
