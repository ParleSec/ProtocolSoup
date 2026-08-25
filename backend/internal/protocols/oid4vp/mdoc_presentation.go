package oid4vp

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// credentialFormatMsoMdoc is the OID4VP/ISO-18013-5 mdoc credential format. An
// mso_mdoc vp_token is a base64url-encoded CBOR DeviceResponse, distinct from
// the SD-JWT (`~`), JSON-LD (`{`), and JWT VP token shapes.
const credentialFormatMsoMdoc = "mso_mdoc"

type verifiedMdocPresentation struct {
	DCQLID   string
	Document mdoc.VerifiedDocument
}

// initMdocTrustAnchors loads the ISO/IEC 18013-5 IACA root the verifier trusts
// for mso_mdoc presentations. The trust anchor is the IACA root (issuer
// PKI), never the document-signer certificate; the DS cert arrives in the
// IssuerAuth x5chain and chains to this root.
//
// Every configured source is additive: external ecosystem roots from the
// environment are combined with the issuer-persisted iaca_root.pem under
// SHOWCASE_MDOC_PKI_PATH or {DataDir}/mdoc. This lets a combined
// issuer/verifier deployment validate both external suite credentials and the
// real mdocs it issued itself. When no anchor is configured the pool stays nil
// and the mdoc branch reports a clear policy reason.
func (p *Plugin) initMdocTrustAnchors(dataDir string) error {
	pemBytes, source := mdocIACARootPEM(dataDir)
	if len(pemBytes) == 0 {
		return nil
	}
	pool, err := mdoc.TrustAnchorsFromPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	// Retain the parsed root(s) so the HAIP mso_mdoc Authority Key Identifier
	// Trusted Authorities Query can be derived from each root's
	// SubjectKeyIdentifier (HAIP 1.0 Section 5).
	certs, err := mdoc.TrustAnchorCertificatesFromPEM(pemBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	p.mdocTrustAnchors = pool
	p.mdocTrustAnchorCerts = certs
	return nil
}

// mdocIACARootPEM resolves the configured ISO/IEC 18013-5 IACA root PEM and the
// labels of the sources they came from (for error messages). Explicit
// ecosystem roots and the local issuer-persisted root are additive. It returns
// nil bytes when no anchor is configured, leaving the verifier to report a
// clear policy reason rather than trusting anything.
func mdocIACARootPEM(dataDir string) ([]byte, string) {
	var combined []byte
	var sources []string
	if pemEnv := strings.TrimSpace(os.Getenv("MDOC_IACA_ROOT_PEM")); pemEnv != "" {
		combined = appendPEM(combined, []byte(pemEnv))
		sources = append(sources, "MDOC_IACA_ROOT_PEM")
	}
	candidates := make([]string, 0, 3)
	if path := strings.TrimSpace(os.Getenv("MDOC_IACA_ROOT_PEM_FILE")); path != "" {
		candidates = append(candidates, path)
	}
	if pkiDir := strings.TrimSpace(os.Getenv("SHOWCASE_MDOC_PKI_PATH")); pkiDir != "" {
		candidates = append(candidates, filepath.Join(pkiDir, "iaca_root.pem"))
	}
	if dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, "mdoc", "iaca_root.pem"))
	}
	seenPaths := make(map[string]struct{}, len(candidates))
	for _, path := range candidates {
		cleanPath := filepath.Clean(path)
		if _, duplicate := seenPaths[cleanPath]; duplicate {
			continue
		}
		seenPaths[cleanPath] = struct{}{}
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		combined = appendPEM(combined, pemBytes)
		sources = append(sources, fmt.Sprintf("mso_mdoc IACA trust anchor %q", path))
	}
	return combined, strings.Join(sources, ", ")
}

func appendPEM(destination, pemBytes []byte) []byte {
	if len(destination) > 0 && destination[len(destination)-1] != '\n' {
		destination = append(destination, '\n')
	}
	return append(destination, pemBytes...)
}

// looksLikeMdocDeviceResponse reports whether a vp_token carries an mso_mdoc
// DeviceResponse, in either the OID4VP 1.0 DCQL-keyed object form
// ({"<id>": ["<base64url DeviceResponse>"]}) or a bare base64url DeviceResponse.
// It only returns true when a DeviceResponse actually decodes, so it is a safe
// dispatch discriminator that never misclassifies SD-JWT or JSON-LD VP tokens.
func looksLikeMdocDeviceResponse(vpToken string) bool {
	_, ok := extractMdocPresentations(vpToken)
	return ok
}

// evaluateMdocPresentation verifies an mso_mdoc DeviceResponse vp_token (ISO/IEC
// 18013-5 clauses 9.3.1 and 9.1.3.4), parallel to evaluateSDJWTPresentation:
//
//  1. Decode the base64url CBOR DeviceResponse.
//  2. Reconstruct the shared SessionTranscript from the handover bound to this
//     session (production uses OpenID4VPHandover; tests may supply a fixed
//     handover on the session). The verifier reconstructs the transcript
//     itself rather than trusting any transmitted value.
//  3. Verify each document: issuer signature + x5chain to the IACA root + digest
//     recompute + validityInfo (VerifyIssuerSigned), then the detached
//     deviceSignature over the reconstructed DeviceAuthenticationBytes against the
//     MSO-bound device key (VerifyDeviceResponse).
//  4. Evaluate the session DCQL query against the disclosed namespace/element
//     values.
func (p *Plugin) evaluateMdocPresentation(session *requestSession, vpToken string, result *models.OID4VPVerificationResult) *models.OID4VPVerificationResult {
	presentations, ok := extractMdocPresentations(vpToken)
	if !ok {
		addPolicyReason(result, "vp_token_invalid", "mso_mdoc vp_token did not contain a decodable DeviceResponse")
		finalizePolicyDecision(result)
		return result
	}
	if p.mdocTrustAnchors == nil {
		addPolicyReason(result, "mdoc_trust_anchor_unavailable", "no ISO/IEC 18013-5 IACA trust anchor is configured for mso_mdoc verification")
		finalizePolicyDecision(result)
		return result
	}

	// Reconstruct the shared SessionTranscript handover. The verifier rebuilds
	// the OID4VP 1.0 OpenID4VPHandover from this session's
	// client_id, nonce, response_uri, and response-encryption key thumbprint --
	// never trusting any transmitted value. Tests may pin an exact handover via
	// session.MdocHandover; production leaves it empty and reconstructs.
	handover := session.MdocHandover
	if len(handover) == 0 {
		reconstructed, herr := reconstructSessionHandover(session)
		if herr != nil {
			addPolicyReason(result, "mdoc_handover_unavailable", fmt.Sprintf("cannot reconstruct OpenID4VPHandover for this request: %v", herr))
			finalizePolicyDecision(result)
			return result
		}
		handover = reconstructed
	}
	transcript, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		addPolicyReason(result, "vp_token_invalid", fmt.Sprintf("build SessionTranscript: %v", err))
		finalizePolicyDecision(result)
		return result
	}
	transcriptBytes, err := transcript.Encode()
	if err != nil {
		addPolicyReason(result, "vp_token_invalid", fmt.Sprintf("encode SessionTranscript: %v", err))
		finalizePolicyDecision(result)
		return result
	}

	verified := make([]verifiedMdocPresentation, 0, len(presentations))
	for _, presentation := range presentations {
		docs, verr := mdoc.VerifyDeviceResponse(presentation.Response, transcriptBytes, p.mdocTrustAnchors, time.Now().UTC())
		if verr != nil {
			// A device-authentication failure is most often a SessionTranscript
			// mismatch; the error chain distinguishes issuer vs device failures.
			addPolicyReason(result, "device_auth_invalid", verr.Error())
			finalizePolicyDecision(result)
			return result
		}
		for _, document := range docs {
			verified = append(verified, verifiedMdocPresentation{
				DCQLID:   presentation.DCQLID,
				Document: document,
			})
		}
	}

	// Issuer verification (chain + digests + validityInfo) and device
	// authentication both passed for every document. The deviceSignature is over
	// the session-bound SessionTranscript, so holder binding, request binding
	// (nonce/audience via the handover), and validity are all established by the
	// mdoc proof itself rather than by JWT claims.
	result.HolderBindingVerified = true
	result.NonceValidated = true
	result.AudienceValidated = true
	result.ExpiryValidated = true

	evidenceSet, dcqlErr := p.matchMdocAgainstDCQL(session, verified)
	if dcqlErr != nil {
		addPresentedCredentialPolicyError(result, dcqlErr)
		result.HolderBindingVerified = false
	} else if len(evidenceSet) > 0 {
		result.CredentialEvidence = &evidenceSet[0]
		result.CredentialEvidenceSet = evidenceSet
	}

	result.Policy.Allowed = result.NonceValidated &&
		result.AudienceValidated &&
		result.ExpiryValidated &&
		result.HolderBindingVerified &&
		len(result.Policy.ReasonCodes) == 0
	if result.Policy.Allowed {
		result.Policy.Code = "allowed"
		result.Policy.Message = "Presentation accepted"
		result.Policy.Reasons = nil
		result.Policy.ReasonCodes = nil
		return result
	}
	finalizePolicyDecision(result)
	return result
}

// matchMdocAgainstDCQL builds the mdoc credential evidence from the verified
// documents (doctype + disclosed namespace/element values) and evaluates the
// session DCQL query against it using vc.RequirementMatchesMdoc. Each DCQL
// requirement must be satisfied by at least one presented document.
func (p *Plugin) matchMdocAgainstDCQL(session *requestSession, verified []verifiedMdocPresentation) ([]models.OID4VPCredentialEvidence, error) {
	evidenceSet := make([]models.OID4VPCredentialEvidence, 0, len(verified))
	mdocEvidence := make([]vc.MdocCredentialEvidence, 0, len(verified))
	dcqlIDs := make([]string, 0, len(verified))
	for _, presentation := range verified {
		doc := presentation.Document
		namespaces := make(map[string]map[string]struct{}, len(doc.DisclosedClaims))
		disclosed := make(map[string]interface{}, len(doc.DisclosedClaims))
		for ns, elements := range doc.DisclosedClaims {
			set := make(map[string]struct{}, len(elements))
			nsClaims := make(map[string]interface{}, len(elements))
			for element, value := range elements {
				set[element] = struct{}{}
				// CBOR decoders use map[interface{}]interface{} for nested
				// values. Convert it before storing verifier evidence because
				// completed OID4VP request sessions are persisted as JSON.
				nsClaims[element] = mdoc.JSONSafeValue(value)
			}
			namespaces[ns] = set
			disclosed[ns] = nsClaims
		}
		mdocEvidence = append(mdocEvidence, vc.MdocCredentialEvidence{
			Format:                       credentialFormatMsoMdoc,
			Doctype:                      doc.DocType,
			IssuerAuthorityKeyIdentifier: base64.RawURLEncoding.EncodeToString(doc.IssuerAuthorityKeyIdentifier),
			NameSpaces:                   namespaces,
		})
		evidenceSet = append(evidenceSet, models.OID4VPCredentialEvidence{
			Format:          credentialFormatMsoMdoc,
			Doctype:         doc.DocType,
			DisclosedClaims: disclosed,
			FullClaims:      disclosed,
		})
		dcqlIDs = append(dcqlIDs, strings.TrimSpace(presentation.DCQLID))
	}

	if session == nil {
		return evidenceSet, nil
	}
	dcqlQuery := vc.ParseDCQLQuery(session.DCQLQuery)
	requirements := dcqlQuery.Credentials
	requirementsByID := make(map[string]struct{}, len(requirements))
	for _, requirement := range requirements {
		requirementID := strings.TrimSpace(requirement.ID)
		if requirementID == "" {
			return nil, newVerifierPolicyError("dcql_query_invalid", "mso_mdoc DCQL credential query is missing id", nil)
		}
		requirementsByID[requirementID] = struct{}{}
	}
	if len(requirements) > 0 {
		for _, dcqlID := range dcqlIDs {
			if dcqlID == "" {
				return nil, newVerifierPolicyError("dcql_response_invalid", "mso_mdoc DCQL vp_token must be keyed by credential query id", nil)
			}
			if _, ok := requirementsByID[dcqlID]; !ok {
				return nil, newVerifierPolicyError("dcql_response_invalid", fmt.Sprintf("mso_mdoc vp_token contains unrequested credential query id %q", dcqlID), nil)
			}
		}
	}
	// referencedByCredentialSets is nil when the query has no credential_sets
	// (OID4VP 1.0 Section 6.2), so every requirement below is unconditionally
	// required exactly as it was before credential_sets support existed --
	// this is the backward-compatibility bar for this loop.
	referencedByCredentialSets := vc.CredentialIDsReferencedByCredentialSets(dcqlQuery)
	matchedRequirementIDs := make(map[string]bool, len(requirements))
	for _, requirement := range requirements {
		matched := false
		failureCode := "dcql_format_mismatch"
		failureMessage := "presented mso_mdoc credential does not satisfy requested dcql constraints"
		for idx := range mdocEvidence {
			if dcqlIDs[idx] != strings.TrimSpace(requirement.ID) {
				continue
			}
			ok, code, message := vc.RequirementMatchesMdoc(requirement, mdocEvidence[idx])
			if ok {
				evidenceSet[idx].RequiredClaimPaths = mergeMdocClaimPaths(evidenceSet[idx].RequiredClaimPaths, requirement.RequiredClaimPathSegments)
				matched = true
				break
			}
			if strings.TrimSpace(code) != "" {
				failureCode = code
			}
			if strings.TrimSpace(message) != "" {
				failureMessage = message
			}
		}
		if matched {
			matchedRequirementIDs[strings.TrimSpace(requirement.ID)] = true
			continue
		}
		// A requirement referenced by a credential_sets option is only
		// required as part of satisfying that option; its failure to match
		// is adjudicated below by vc.EvaluateCredentialSets, not here.
		if !referencedByCredentialSets[strings.TrimSpace(requirement.ID)] {
			return nil, newVerifierPolicyError(failureCode, failureMessage, nil)
		}
	}
	if satisfied, unsatisfiedSets := vc.EvaluateCredentialSets(dcqlQuery, matchedRequirementIDs); !satisfied {
		return nil, newVerifierPolicyError("dcql_credential_set_unsatisfied", fmt.Sprintf("presented mso_mdoc credentials do not satisfy required dcql credential_sets %v", unsatisfiedSets), nil)
	}
	return evidenceSet, nil
}

// mergeMdocClaimPaths records the satisfied mdoc claim paths (namespace/element)
// on the evidence using a "namespace/element" rendering distinct from SD-JWT's
// dot-joined JSON-pointer form (an mdoc namespace itself contains dots).
func mergeMdocClaimPaths(existing []string, segments [][]string) []string {
	seen := make(map[string]struct{}, len(existing))
	for _, path := range existing {
		seen[path] = struct{}{}
	}
	for _, seg := range segments {
		rendered := strings.Join(seg, "/")
		if rendered == "" {
			continue
		}
		if _, ok := seen[rendered]; ok {
			continue
		}
		seen[rendered] = struct{}{}
		existing = append(existing, rendered)
	}
	return existing
}
