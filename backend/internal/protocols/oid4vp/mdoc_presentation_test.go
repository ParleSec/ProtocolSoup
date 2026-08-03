package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
)

const mdocDCQLQuery = `{
	"credentials": [{
		"id": "mdl",
		"format": "mso_mdoc",
		"meta": {"doctype_values": ["org.iso.18013.5.1.mDL"]},
		"claims": [
			{"path": ["org.iso.18013.5.1", "family_name"]},
			{"path": ["org.iso.18013.5.1", "document_number"]}
		]
	}]
}`

// issueMdocForVerifier issues a real mDL IssuerSigned bound to deviceKey, signed
// by a fresh IACA document signer, returning the credential and the IssuerPKI
// whose IACA root is the verifier trust anchor.
func issueMdocForVerifier(t *testing.T, deviceKey *ecdsa.PrivateKey) (mdoc.IssuerSigned, *mdoc.IssuerPKI) {
	t.Helper()
	pki, err := mdoc.GenerateIssuerPKI(mdoc.DefaultPKIParams("https://issuer.example"))
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	family, err := mdoc.NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	docNumber, err := mdoc.NewIssuerSignedItem(1, "document_number", "D-9007-2026")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	ns, err := mdoc.BuildIssuerNameSpaces(map[mdoc.NameSpace][]mdoc.IssuerSignedItem{mdoc.NameSpaceMDL: {family, docNumber}})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := mdoc.BuildValueDigests(ns, mdoc.DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}
	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(&deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}
	now := time.Now().Truncate(time.Second).UTC()
	mso := mdoc.BuildMSO(vd, deviceCOSEKey, mdoc.DocTypeMDL, mdoc.ValidityInfo{
		Signed:     now,
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(48 * time.Hour),
	})
	msoBytes, err := mdoc.EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := mdoc.BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	return mdoc.IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}, pki
}

// realHandover builds the real OID4VP 1.0 OpenID4VPHandover (Appendix B.2.6.1)
// the wallet signs over. The verifier reconstructs the identical bytes from the
// same session fields via reconstructSessionHandover, so these tests exercise
// the production handover, not a placeholder. thumbprint is nil for an
// unencrypted presentation.
func realHandover(t *testing.T, clientID, nonce, responseURI string, thumbprint []byte) []byte {
	t.Helper()
	handover, err := mdoc.NewOpenID4VPHandover(clientID, nonce, thumbprint, responseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	return handover
}

func buildMdocVPToken(t *testing.T, deviceKey *ecdsa.PrivateKey, issuerSigned mdoc.IssuerSigned, handover []byte) string {
	t.Helper()
	st, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	requested := map[mdoc.NameSpace][]string{mdoc.NameSpaceMDL: {"family_name", "document_number"}}
	response, err := mdoc.BuildDeviceResponse(deviceKey, issuerSigned, mdoc.DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}
	wire, err := mdoc.EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse: %v", err)
	}
	vpToken, err := json.Marshal(map[string][]string{
		"mdl": {base64.RawURLEncoding.EncodeToString(wire)},
	})
	if err != nil {
		t.Fatalf("marshal DCQL-keyed vp_token: %v", err)
	}
	return string(vpToken)
}

// TestEvaluateMdocPresentationRoundTrip is the joint wallet-to-verifier gate at
// the service layer: the wallet builds a DeviceResponse over the shared
// SessionTranscript, and the verifier dispatches the base64url CBOR vp_token to
// the mdoc branch, verifies issuer + device authentication against the IACA
// trust anchor, satisfies the DCQL query, and allows the presentation.
func TestEvaluateMdocPresentationRoundTrip(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	// The wallet signs over the real OpenID4VPHandover; the verifier session
	// holds only the request fields and reconstructs the identical handover.
	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)

	session := &requestSession{
		ID:          "req-1",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery:   mdocDCQLQuery,
	}

	result := p.evaluateVPToken(session, vpToken)
	if !result.Policy.Allowed {
		t.Fatalf("expected mdoc presentation to be allowed, got code=%q reasons=%v", result.Policy.Code, result.Policy.Reasons)
	}
	if !result.HolderBindingVerified {
		t.Fatal("expected holder binding verified via deviceSignature")
	}
	if result.CredentialEvidence == nil {
		t.Fatal("expected credential evidence")
	}
	if result.CredentialEvidence.Format != "mso_mdoc" || result.CredentialEvidence.Doctype != mdoc.DocTypeMDL {
		t.Fatalf("unexpected evidence format/doctype: %q/%q", result.CredentialEvidence.Format, result.CredentialEvidence.Doctype)
	}
}

// TestEvaluateMdocPresentationRejectsSessionTranscriptMismatch proves the
// binding is genuine at the service layer: the verifier session carries a
// different handover (a different nonce) than the wallet signed over, so device
// authentication fails and the presentation is denied.
func TestEvaluateMdocPresentationRejectsSessionTranscriptMismatch(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	// Wallet signs over the handover for nonce-xyz; the verifier session carries
	// nonce-DIFFERENT, so its reconstructed handover differs and device auth fails.
	walletHandover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, walletHandover)

	session := &requestSession{
		ID:          "req-2",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-DIFFERENT",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery:   mdocDCQLQuery,
	}

	result := p.evaluateVPToken(session, vpToken)
	if result.Policy.Allowed {
		t.Fatal("expected denial on SessionTranscript mismatch")
	}
	if !containsPolicyCode(result, "device_auth_invalid") {
		t.Fatalf("expected device_auth_invalid reason, got %v", result.Policy.ReasonCodes)
	}
}

// TestEvaluateMdocPresentationRejectsUntrustedIssuer denies a DeviceResponse
// whose document-signer chains to an IACA root the verifier does not trust.
func TestEvaluateMdocPresentationRejectsUntrustedIssuer(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, _ := issueMdocForVerifier(t, deviceKey)

	// The verifier trusts a different (unrelated) IACA root.
	otherPKI, err := mdoc.GenerateIssuerPKI(mdoc.DefaultPKIParams("https://other-issuer.example"))
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	p := NewPlugin()
	p.mdocTrustAnchors = otherPKI.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)
	session := &requestSession{
		ID:          "req-3",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery:   mdocDCQLQuery,
	}

	result := p.evaluateVPToken(session, vpToken)
	if result.Policy.Allowed {
		t.Fatal("expected denial when the DS cert does not chain to a trusted IACA root")
	}
	if !containsPolicyCode(result, "device_auth_invalid") {
		t.Fatalf("expected device_auth_invalid reason, got %v", result.Policy.ReasonCodes)
	}
}

// TestEvaluateMdocPresentationRejectsDCQLMismatch denies when the disclosed mdoc
// elements do not satisfy the DCQL query (a requested element was not disclosed).
func TestEvaluateMdocPresentationRejectsDCQLMismatch(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)

	// DCQL requires birth_date, which was not disclosed.
	dcql := `{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_values":["org.iso.18013.5.1.mDL"]},"claims":[{"path":["org.iso.18013.5.1","birth_date"]}]}]}`
	session := &requestSession{
		ID:          "req-4",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery:   dcql,
	}

	result := p.evaluateVPToken(session, vpToken)
	if result.Policy.Allowed {
		t.Fatal("expected denial when a required DCQL element was not disclosed")
	}
	if !containsPolicyCode(result, "missing_required_claim") {
		t.Fatalf("expected missing_required_claim reason, got %v", result.Policy.ReasonCodes)
	}
}

// mdocCredentialSetsDCQLQuery builds an mso_mdoc DCQL query with two
// Credential Queries -- "mdl" (satisfiable by the mDL DeviceResponse these
// tests build via buildMdocVPToken) and "unused_pid" (a distinct doctype the
// tests never present) -- plus the given top-level credential_sets array
// (OID4VP 1.0 Section 6.2), for exercising vc.EvaluateCredentialSets on the
// mdoc verification path (matchMdocAgainstDCQL).
func mdocCredentialSetsDCQLQuery(t *testing.T, credentialSets []map[string]interface{}) string {
	t.Helper()
	query := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "mdl",
				"format": "mso_mdoc",
				"meta":   map[string]interface{}{"doctype_values": []string{"org.iso.18013.5.1.mDL"}},
				"claims": []map[string]interface{}{
					{"path": []string{"org.iso.18013.5.1", "family_name"}},
					{"path": []string{"org.iso.18013.5.1", "document_number"}},
				},
			},
			{
				"id":     "unused_pid",
				"format": "mso_mdoc",
				"meta":   map[string]interface{}{"doctype_values": []string{"eu.europa.ec.eudi.pid.1"}},
			},
		},
		"credential_sets": credentialSets,
	}
	raw, err := json.Marshal(query)
	if err != nil {
		t.Fatalf("marshal mdoc credential_sets dcql query: %v", err)
	}
	return string(raw)
}

// TestEvaluateMdocPresentationCredentialSetSatisfiedByOneAlternative proves a
// required credential_sets entry on the mdoc path succeeds when the presented
// DeviceResponse satisfies at least one of its options, even though
// "unused_pid" (a different Credential Query in the same `credentials` array)
// was never presented.
func TestEvaluateMdocPresentationCredentialSetSatisfiedByOneAlternative(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)
	session := &requestSession{
		ID:          "req-cs-1",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery: mdocCredentialSetsDCQLQuery(t, []map[string]interface{}{
			{"options": [][]string{{"unused_pid"}, {"mdl"}}, "required": true},
		}),
	}

	result := p.evaluateVPToken(session, vpToken)
	if !result.Policy.Allowed {
		t.Fatalf("expected credential_sets satisfied by mdl alone, got code=%q reasons=%v", result.Policy.Code, result.Policy.Reasons)
	}
}

// TestEvaluateMdocPresentationDeniesUnsatisfiedRequiredCredentialSet proves a
// required credential_sets entry whose only option references a Credential
// Query the wallet never presented is denied with the new
// dcql_credential_set_unsatisfied reason code, even though a different,
// independently-satisfied credential_sets entry exists for "mdl".
func TestEvaluateMdocPresentationDeniesUnsatisfiedRequiredCredentialSet(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)
	session := &requestSession{
		ID:          "req-cs-2",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery: mdocCredentialSetsDCQLQuery(t, []map[string]interface{}{
			{"options": [][]string{{"mdl"}}, "required": true},
			{"options": [][]string{{"unused_pid"}}, "required": true},
		}),
	}

	result := p.evaluateVPToken(session, vpToken)
	if result.Policy.Allowed {
		t.Fatal("expected denial when a required credential_sets entry has no satisfiable option")
	}
	if !containsPolicyCode(result, "dcql_credential_set_unsatisfied") {
		t.Fatalf("expected dcql_credential_set_unsatisfied reason, got %v", result.Policy.ReasonCodes)
	}
}

// TestEvaluateMdocPresentationAllowsUnsatisfiedOptionalCredentialSet proves a
// credential_sets entry marked required:false does not block the overall mdoc
// query from succeeding even when none of its options are satisfiable.
func TestEvaluateMdocPresentationAllowsUnsatisfiedOptionalCredentialSet(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)
	session := &requestSession{
		ID:          "req-cs-3",
		ClientID:    "verifier-client-1",
		Nonce:       "nonce-xyz",
		ResponseURI: "https://verifier.example/response",
		DCQLQuery: mdocCredentialSetsDCQLQuery(t, []map[string]interface{}{
			{"options": [][]string{{"mdl"}}, "required": true},
			{"options": [][]string{{"unused_pid"}}, "required": false},
		}),
	}

	result := p.evaluateVPToken(session, vpToken)
	if !result.Policy.Allowed {
		t.Fatalf("expected optional unsatisfied credential_sets entry to not block, got code=%q reasons=%v", result.Policy.Code, result.Policy.Reasons)
	}
}

// TestEvaluateMdocPresentationRequiresHandover confirms the verifier does not
// guess a handover: without one bound to the session it reports a clear reason
// (the OID4VP handover is fixed by the online profile).
func TestEvaluateMdocPresentationRequiresHandover(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)

	p := NewPlugin()
	p.mdocTrustAnchors = pki.TrustAnchors()

	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	vpToken := buildMdocVPToken(t, deviceKey, issuerSigned, handover)
	// No client_id/nonce/response_uri on the session: the verifier cannot
	// reconstruct a handover and must refuse rather than guess one.
	session := &requestSession{ID: "req-5", DCQLQuery: mdocDCQLQuery}

	result := p.evaluateVPToken(session, vpToken)
	if result.Policy.Allowed {
		t.Fatal("expected denial when no SessionTranscript handover is bound")
	}
	if !containsPolicyCode(result, "mdoc_handover_unavailable") {
		t.Fatalf("expected mdoc_handover_unavailable reason, got %v", result.Policy.ReasonCodes)
	}
}

// TestMdocDispatchDoesNotCaptureOtherFormats guards the dispatch: SD-JWT,
// JSON-LD, and JWT VP tokens must not be misrouted to the mdoc branch.
func TestMdocDispatchDoesNotCaptureOtherFormats(t *testing.T) {
	cases := map[string]string{
		"sd-jwt":  "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.sig~WyJzYWx0IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~",
		"jwt-vp":  "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ3YWxsZXQifQ.signature",
		"json-ld": `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"]}`,
	}
	for name, token := range cases {
		if looksLikeMdocDeviceResponse(token) {
			t.Fatalf("%s token must not be classified as an mdoc DeviceResponse", name)
		}
	}
}
