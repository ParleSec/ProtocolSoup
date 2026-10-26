package vc

import (
	"fmt"
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

// BuildCredentialEvidence parses a raw credential into the shared evidence
// model used by DCQL. lifecycleStage is required (LifecycleStageIssued
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
	var selectiveDisclosure *SelectiveDisclosureSummary
	if parsed.IsSDJWT {
		envelope, err := ParseSDJWTEnvelope(parsed.Original)
		if err != nil {
			return nil, err
		}
		decodedIssuer, err := intcrypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
		if err != nil {
			return nil, fmt.Errorf("decode sd-jwt issuer-signed jwt: %w", err)
		}
		issuerPayload := map[string]interface{}(decodedIssuer.Payload)
		committedCount, hasUnrepresentedForms := countSDJWTCommittedDigestsPE(issuerPayload)
		processedPayload, decodedDisclosures, err := ProcessSDJWTDisclosures(issuerPayload, envelope.Disclosures)
		if err != nil {
			return nil, err
		}
		fullClaims = deepCopyMapPE(processedPayload)
		disclosedClaims = DisclosedClaimMap(decodedDisclosures)
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
	vcClaims, _ := fullClaims["vc"].(map[string]interface{})
	aliasVerifiableCredentialClaimsPE(fullClaims, vcClaims)
	aliasMSOMDocClaimsPE(fullClaims)
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
					count++
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
