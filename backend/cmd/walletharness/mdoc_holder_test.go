package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// newMdocTestHarness builds a wallet harness server with a persistent device key
// for exercising the mso_mdoc holder wiring without a live issuer.
func newMdocTestHarness(t *testing.T) *walletHarnessServer {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "device_key.pem")
	deviceKey, err := intcrypto.LoadOrCreateDeviceKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceKey: %v", err)
	}
	return &walletHarnessServer{
		issuerBaseURL: "https://issuer.example",
		deviceKey:     deviceKey,
		deviceKeyID:   intcrypto.JWKFromECPublicKey(&deviceKey.PublicKey, "").Thumbprint(),
	}
}

// issueMdocBoundTo issues a real mso_mdoc IssuerSigned (base64url CBOR) bound to
// boundKey, signed by a freshly generated IACA document signer.
func issueMdocBoundTo(t *testing.T, s *walletHarnessServer, boundKey *ecdsa.PublicKey) string {
	t.Helper()
	pki, err := mdoc.GenerateIssuerPKI(mdoc.DefaultPKIParams("https://issuer.example/oid4vci"))
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	s.mdocIssuerRoots = pki.TrustAnchors()
	now := time.Now().Truncate(time.Second).UTC()
	family, err := mdoc.NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	age, err := mdoc.NewIssuerSignedItem(1, "age_over_18", true)
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	ns, err := mdoc.BuildIssuerNameSpaces(map[mdoc.NameSpace][]mdoc.IssuerSignedItem{mdoc.NameSpaceMDL: {family, age}})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := mdoc.BuildValueDigests(ns, mdoc.DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}
	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(boundKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}
	mso := mdoc.BuildMSO(vd, deviceCOSEKey, mdoc.DocTypeMDL, mdoc.ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(48 * time.Hour)})
	msoBytes, err := mdoc.EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := mdoc.BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	encoded, err := mdoc.EncodeIssuerSigned(mdoc.IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth})
	if err != nil {
		t.Fatalf("EncodeIssuerSigned: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func TestCredentialRefreshRequiredReadsMdocValidityInfo(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	server := &walletHarnessServer{deviceKey: deviceKey}
	credential := issueMdocBoundTo(t, server, &deviceKey.PublicKey)

	if refresh, err := credentialRefreshRequired(credential, time.Hour); err != nil || refresh {
		t.Fatalf("48-hour mdoc should not need refresh with one-hour threshold: refresh=%t err=%v", refresh, err)
	}
	if refresh, err := credentialRefreshRequired(credential, 72*time.Hour); err != nil || !refresh {
		t.Fatalf("48-hour mdoc should need refresh with 72-hour threshold: refresh=%t err=%v", refresh, err)
	}
}

func TestHarnessCreateMdocDeviceProof(t *testing.T) {
	s := newMdocTestHarness(t)
	proof, err := s.createMdocDeviceProofJWT("did:example:wallet:alice", "nonce-1", s.issuerBaseURL+"/oid4vci")
	if err != nil {
		t.Fatalf("createMdocDeviceProofJWT: %v", err)
	}
	// The proof must be signed by the device key and self-describe it in the JOSE jwk header.
	parsed, err := jwt.Parse(proof, func(token *jwt.Token) (interface{}, error) {
		return &s.deviceKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("device proof did not verify against the device key: %v", err)
	}
	if parsed.Header["typ"] != "openid4vci-proof+jwt" {
		t.Fatalf("unexpected proof typ header: %v", parsed.Header["typ"])
	}
	if _, ok := parsed.Header["jwk"].(map[string]interface{}); !ok {
		t.Fatal("proof JOSE header is missing jwk")
	}
	if _, ok := parsed.Claims.(jwt.MapClaims)["cnf"]; ok {
		t.Fatal("proof payload must not carry cnf")
	}
}

func TestHarnessBindMdocCredentialStoresAndChecksBinding(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}

	// A credential bound to the wallet device key is stored with doctype/format.
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential (mso_mdoc): %v", err)
	}
	if len(wallet.Credentials) != 1 {
		t.Fatalf("expected 1 stored credential, got %d", len(wallet.Credentials))
	}
	var stored walletCredentialMaterial
	for _, record := range wallet.Credentials {
		stored = record
	}
	if stored.Format != credentialFormatMsoMdoc {
		t.Fatalf("stored format = %q, want %q", stored.Format, credentialFormatMsoMdoc)
	}
	if stored.Doctype != mdoc.DocTypeMDL {
		t.Fatalf("stored doctype = %q, want %q", stored.Doctype, mdoc.DocTypeMDL)
	}

	// A credential bound to a DIFFERENT device key must be rejected: regenerating
	// or mismatching the device key breaks the binding.
	primaryRoots := s.mdocIssuerRoots
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreign := issueMdocBoundTo(t, s, &otherKey.PublicKey)
	if err := s.bindCredential(wallet, foreign, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err == nil {
		t.Fatal("expected rejection of an mso_mdoc credential bound to a foreign device key")
	}

	// Batch OID4VCI secondaries may be bound to ephemeral proof keys: store them
	// without requiring the wallet device key, and do not activate them.
	beforeActive := wallet.CredentialJWT
	if err := s.bindMdocCredentialWithPolicy(wallet, foreign, "MobileDrivingLicenceMsoMdoc", false); err != nil {
		t.Fatalf("relaxed batch bind of foreign-key mdoc: %v", err)
	}
	if len(wallet.Credentials) != 2 {
		t.Fatalf("expected 2 stored credentials after relaxed bind, got %d", len(wallet.Credentials))
	}
	if wallet.CredentialJWT != beforeActive {
		t.Fatalf("relaxed bind must not replace the active device-key credential")
	}
	if s.mdocCredentialMatchesWalletDeviceKey(foreign) {
		t.Fatal("foreign-key mdoc must not match wallet device key")
	}
	s.mdocIssuerRoots = primaryRoots
	if !s.mdocCredentialMatchesWalletDeviceKey(credential) {
		t.Fatal("expected primary mdoc to match wallet device key")
	}

	// The issuer-provided x5chain cannot bootstrap wallet trust.
	s.mdocIssuerRoots = nil
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err == nil {
		t.Fatal("expected rejection when the wallet has no independently configured IACA root")
	}
}

func TestHarnessBuildMdocDeviceResponse(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}
	var credentialID string
	for id := range wallet.Credentials {
		credentialID = id
	}

	handover, err := mdoc.EncodeHandover([]any{"test-handover", "verifier.example", "nonce-xyz"})
	if err != nil {
		t.Fatalf("EncodeHandover: %v", err)
	}
	requested := map[mdoc.NameSpace][]string{mdoc.NameSpaceMDL: {"family_name"}}
	responseBytes, err := s.buildMdocDeviceResponse(wallet, credentialID, requested, handover)
	if err != nil {
		t.Fatalf("buildMdocDeviceResponse: %v", err)
	}

	response, err := mdoc.DecodeDeviceResponse(responseBytes)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	if response.Version != "1.0" || response.Status != 0 || len(response.Documents) != 1 {
		t.Fatalf("unexpected DeviceResponse envelope: %+v", response)
	}

	// The deviceSignature verifies over DeviceAuthenticationBytes built from the
	// same SessionTranscript using the persistent device key.
	transcript, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcriptBytes, err := transcript.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	doc := response.Documents[0]
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, transcriptBytes, doc.DocType, &s.deviceKey.PublicKey); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}
}

const mdocMDLFamilyNameDCQL = `{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}`

func decodeMdocDCQLVPToken(t *testing.T, vpToken string) []byte {
	t.Helper()
	var keyed map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &keyed); err != nil {
		t.Fatalf("vp_token is not a DCQL-keyed JSON object: %v", err)
	}
	values := keyed["mdl"]
	if len(values) != 1 {
		t.Fatalf("vp_token mdl entry = %v, want exactly one DeviceResponse", values)
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil {
		t.Fatalf("vp_token mdl value is not base64url CBOR: %v", err)
	}
	return raw
}

// TestHarnessMatchWalletCredentialsToDCQLMdoc proves an stored mso_mdoc
// credential is matched against an mso_mdoc DCQL query via the mdoc evidence
// path (doctype + [namespace, elementIdentifier]). Before this wiring the
// harness parsed every stored credential as a JWT, so mso_mdoc credentials
// (base64url CBOR) failed with "invalid token format" and never matched.
func TestHarnessMatchWalletCredentialsToDCQLMdoc(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}

	matched, reasons := matchWalletCredentialsToDCQL(wallet.Credentials, mdocMDLFamilyNameDCQL)
	if len(matched) != 1 {
		t.Fatalf("expected 1 matched mso_mdoc credential, got %d (reasons: %v)", len(matched), reasons)
	}
	if matched[0].Format != credentialFormatMsoMdoc {
		t.Fatalf("matched credential format = %q, want %q", matched[0].Format, credentialFormatMsoMdoc)
	}

	// A DCQL whose doctype does not match the credential must not match.
	mismatchDCQL := `{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}`
	if matched, _ := matchWalletCredentialsToDCQL(wallet.Credentials, mismatchDCQL); len(matched) != 0 {
		t.Fatalf("expected no match for a mismatched doctype, got %d", len(matched))
	}

	// A DCQL requiring an element the credential does not carry must not match.
	missingElementDCQL := `{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","portrait"]}]}]}`
	if matched, _ := matchWalletCredentialsToDCQL(wallet.Credentials, missingElementDCQL); len(matched) != 0 {
		t.Fatalf("expected no match when a required element is absent, got %d", len(matched))
	}
}

// TestHarnessMatchWalletCredentialsToPresentationDefinitionRefusesMdoc pins
// the A3c PE format guard: before mso_mdoc registration, an mdoc credential
// failed at vc.BuildCredentialEvidence's parse step and was refused with a
// parse-error reason. After registration it parses successfully, so without
// the guard in matchWalletCredentialsToPresentationDefinition it would
// proceed into PE field-path matching against a claim shape (namespace-
// nested, not JWT/SD-JWT flat) that Presentation Exchange constraints were
// never meant to address. This asserts the refusal is the explicit format
// guard, not a parse failure wearing a different message.
func TestHarnessMatchWalletCredentialsToPresentationDefinitionRefusesMdoc(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}

	presentationDefinition := map[string]interface{}{
		"id": "pd-mdoc-guard",
		"input_descriptors": []interface{}{
			map[string]interface{}{
				"id": "descriptor-1",
				"constraints": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{"path": []interface{}{"$.vc.type"}},
					},
				},
			},
		},
	}

	matched, reasons := matchWalletCredentialsToPresentationDefinition(wallet.Credentials, presentationDefinition)
	if len(matched) != 0 {
		t.Fatalf("expected 0 matched credentials for mso_mdoc under presentation_exchange, got %d", len(matched))
	}

	foundGuardReason := false
	for _, reason := range reasons {
		if strings.Contains(reason, "matched via DCQL, not presentation_exchange") {
			foundGuardReason = true
		}
		// Before the guard existed, refusal came from
		// vc.BuildCredentialEvidence/ParseAnyCredential failing at parse.
		// A reason that still looks like a parse failure would mean the
		// guard regressed back to relying on the parse erroring out.
		if strings.Contains(reason, "unsupported credential format") || strings.Contains(reason, "decode base64url") {
			t.Fatalf("refusal reason %q looks like a parse failure, not the explicit format guard", reason)
		}
	}
	if !foundGuardReason {
		t.Fatalf("expected a refusal reason citing the DCQL-not-PE format guard, got reasons: %v", reasons)
	}
}

// TestHarnessCreateMdocVPToken proves createVPToken builds an mso_mdoc vp_token
// (base64url CBOR DeviceResponse) over the verifier-reconstructed OID4VP
// OpenID4VPHandover, discloses exactly the DCQL-requested elements, and that the
// device signature verifies against the same SessionTranscript. This is the
// holder side of the default Looking Glass OID4VP demo (mso_mdoc + direct_post).
func TestHarnessCreateMdocVPToken(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}

	requestContext := &resolvedRequestContext{
		ClientID:     "x509_san_dns:verifier.example",
		Nonce:        "nonce-mdoc-vp",
		ResponseURI:  "https://verifier.example/oid4vp/response",
		ResponseMode: "direct_post",
		DCQLQuery:    mdocMDLFamilyNameDCQL,
	}

	vpToken, format, err := s.createVPToken(wallet, requestContext, wallet.CredentialJWT)
	if err != nil {
		t.Fatalf("createVPToken (mso_mdoc): %v", err)
	}
	if format != credentialFormatMsoMdoc {
		t.Fatalf("vp_token format = %q, want %q", format, credentialFormatMsoMdoc)
	}

	rawResponse := decodeMdocDCQLVPToken(t, vpToken)
	response, err := mdoc.DecodeDeviceResponse(rawResponse)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(response.Documents))
	}
	doc := response.Documents[0]

	// The DeviceResponse must authenticate over the SAME handover the verifier
	// reconstructs: OpenID4VPHandover[client_id, nonce, nil, response_uri].
	handover, err := mdoc.NewOpenID4VPHandover(requestContext.ClientID, requestContext.Nonce, nil, requestContext.ResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	transcript, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcriptBytes, err := transcript.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, transcriptBytes, doc.DocType, &s.deviceKey.PublicKey); err != nil {
		t.Fatalf("VerifyDeviceSignature over OpenID4VPHandover: %v", err)
	}

	// Only the DCQL-requested element (family_name) is disclosed; age_over_18 is
	// withheld (selective disclosure, ISO/IEC 18013-5 clause 9.1.4).
	disclosed, err := mdoc.CollectDisclosedElements(doc.IssuerSigned)
	if err != nil {
		t.Fatalf("CollectDisclosedElements: %v", err)
	}
	elements := disclosed[mdoc.NameSpaceMDL]
	if _, ok := elements["family_name"]; !ok {
		t.Fatalf("expected family_name to be disclosed, got %v", elements)
	}
	if _, ok := elements["age_over_18"]; ok {
		t.Fatalf("age_over_18 must not be disclosed when only family_name is requested, got %v", elements)
	}
}

// TestHarnessCreateMdocVPTokenOmitsElementsWhenDCQLClaimsAbsent proves OID4VP
// §6.4.1: a matching mso_mdoc credential query without claims returns the
// credential (issuerAuth + DeviceSigned) with no selectively disclosable
// IssuerSignedItem elements.
func TestHarnessCreateMdocVPTokenOmitsElementsWhenDCQLClaimsAbsent(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}

	const noClaimsDCQL = `{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}`
	requestContext := &resolvedRequestContext{
		ClientID:     "x509_san_dns:verifier.example",
		Nonce:        "nonce-mdoc-no-claims",
		ResponseURI:  "https://verifier.example/oid4vp/response",
		ResponseMode: "direct_post",
		DCQLQuery:    noClaimsDCQL,
	}

	vpToken, format, err := s.createVPToken(wallet, requestContext, wallet.CredentialJWT)
	if err != nil {
		t.Fatalf("createVPToken (mso_mdoc, no claims): %v", err)
	}
	if format != credentialFormatMsoMdoc {
		t.Fatalf("vp_token format = %q, want %q", format, credentialFormatMsoMdoc)
	}

	rawResponse := decodeMdocDCQLVPToken(t, vpToken)
	response, err := mdoc.DecodeDeviceResponse(rawResponse)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(response.Documents))
	}
	doc := response.Documents[0]
	if len(doc.IssuerSigned.NameSpaces) != 0 {
		disclosed, _ := mdoc.CollectDisclosedElements(doc.IssuerSigned)
		t.Fatalf("OID4VP §6.4.1: empty DCQL claims must disclose no mdoc elements, got %v", disclosed)
	}
	if len(doc.IssuerSigned.IssuerAuth) == 0 {
		t.Fatal("issuerAuth remains mandatory and must still be present")
	}
}

// TestHarnessCreateMdocVPTokenRequiresResponseEncryptionKey proves the mso_mdoc
// direct_post.jwt path fails clearly when the verifier advertises no
// response-encryption key: without it the wallet cannot bind the verifier key
// thumbprint into the SessionTranscript handover, so it reports the error rather
// than producing a handover the verifier cannot reconstruct.
func TestHarnessCreateMdocVPTokenRequiresResponseEncryptionKey(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}
	requestContext := &resolvedRequestContext{
		ClientID:     "x509_san_dns:verifier.example",
		Nonce:        "nonce-mdoc-enc",
		ResponseURI:  "https://verifier.example/oid4vp/response",
		ResponseMode: "direct_post.jwt",
		DCQLQuery:    mdocMDLFamilyNameDCQL,
	}
	if _, _, err := s.createVPToken(wallet, requestContext, wallet.CredentialJWT); err == nil {
		t.Fatal("expected createVPToken to reject direct_post.jwt without a verifier response-encryption key")
	}
}

// newTestResponseEncryptionKey mints an EC P-256 ECDH-ES response-encryption key
// the way the verifier does (OID4VP 1.0 Section 8.3): it returns the private key
// (retained by the verifier to decrypt) and the public JWK advertised in
// client_metadata.jwks (use=enc, alg=ECDH-ES) that the wallet encrypts to.
func newTestResponseEncryptionKey(t *testing.T) (*ecdsa.PrivateKey, intcrypto.JWK) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	jwk := intcrypto.JWKFromECPublicKey(&priv.PublicKey, "verifier-enc-1")
	jwk.Use = "enc"
	jwk.Alg = mdocResponseEncAlg
	return priv, jwk
}

// TestHarnessCreateMdocVPTokenEncrypted proves the full mso_mdoc HAIP encrypted
// (direct_post.jwt) path: the DeviceResponse authenticates over the
// OpenID4VPHandover that binds the verifier response-encryption key thumbprint
// (OID4VP 1.0 Appendix B.2.6.1), and the encrypted response (ECDH-ES JWE)
// decrypts back to the same vp_token and state with the verifier's private key.
func TestHarnessCreateMdocVPTokenEncrypted(t *testing.T) {
	s := newMdocTestHarness(t)
	wallet := &walletMaterial{
		Subject:     "did:example:wallet:alice",
		Credentials: make(map[string]walletCredentialMaterial),
	}
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)
	if err := s.bindCredential(wallet, credential, "MobileDrivingLicenceMsoMdoc", credentialFormatMsoMdoc); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}

	encPriv, encJWK := newTestResponseEncryptionKey(t)
	requestContext := &resolvedRequestContext{
		ClientID:              "x509_san_dns:verifier.example",
		Nonce:                 "nonce-mdoc-haip",
		ResponseURI:           "https://verifier.example/oid4vp/response",
		ResponseMode:          "direct_post.jwt",
		State:                 "state-haip-123",
		DCQLQuery:             mdocMDLFamilyNameDCQL,
		ResponseEncryptionJWK: &encJWK,
		ResponseEncValues:     []string{"A128GCM", "A256GCM"},
	}

	vpToken, format, err := s.createVPToken(wallet, requestContext, wallet.CredentialJWT)
	if err != nil {
		t.Fatalf("createVPToken (encrypted mso_mdoc): %v", err)
	}
	if format != credentialFormatMsoMdoc {
		t.Fatalf("vp_token format = %q, want %q", format, credentialFormatMsoMdoc)
	}

	// The DeviceResponse must authenticate over the handover that binds the
	// verifier response-encryption key thumbprint (the encrypted variant).
	thumbprint, err := encJWK.ThumbprintBytes()
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}
	handover, err := mdoc.NewOpenID4VPHandover(requestContext.ClientID, requestContext.Nonce, thumbprint, requestContext.ResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	transcript, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcriptBytes, err := transcript.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	rawResponse := decodeMdocDCQLVPToken(t, vpToken)
	response, err := mdoc.DecodeDeviceResponse(rawResponse)
	if err != nil || len(response.Documents) != 1 {
		t.Fatalf("DecodeDeviceResponse: %v (docs=%d)", err, len(response.Documents))
	}
	doc := response.Documents[0]
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, transcriptBytes, doc.DocType, &s.deviceKey.PublicKey); err != nil {
		t.Fatalf("device signature must verify over the thumbprint-bound handover: %v", err)
	}

	// Encrypt the response (ECDH-ES) and decrypt it with the verifier private key.
	enc := selectMdocResponseEnc(requestContext.ResponseEncValues)
	if enc != jose.A256GCM {
		t.Fatalf("selectMdocResponseEnc preferred %v, want A256GCM when advertised", enc)
	}
	compactJWE, err := encryptMdocResponseForVerifier(encJWK, vpToken, requestContext.State, enc)
	if err != nil {
		t.Fatalf("encryptMdocResponseForVerifier: %v", err)
	}
	object, err := jose.ParseEncrypted(compactJWE, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM, jose.A256GCM})
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	plaintext, err := object.Decrypt(encPriv)
	if err != nil {
		t.Fatalf("verifier could not decrypt the mso_mdoc response: %v", err)
	}
	var decrypted struct {
		VPToken json.RawMessage `json:"vp_token"`
		State   string          `json:"state"`
	}
	if err := json.Unmarshal(plaintext, &decrypted); err != nil {
		t.Fatalf("decode decrypted response payload: %v", err)
	}
	if string(decrypted.VPToken) != vpToken {
		t.Fatal("decrypted vp_token does not match the submitted DeviceResponse")
	}
	if decrypted.State != requestContext.State {
		t.Fatalf("decrypted state = %q, want %q", decrypted.State, requestContext.State)
	}
}

// TestSelectMdocResponseEnc proves the content encryption selection prefers
// A256GCM (HAIP 1.0 Section 5) when advertised and falls back to A128GCM (the
// mdoc online-profile default) otherwise.
func TestSelectMdocResponseEnc(t *testing.T) {
	if got := selectMdocResponseEnc([]string{"A128GCM"}); got != jose.A128GCM {
		t.Fatalf("A128GCM-only advertised: got %v, want A128GCM", got)
	}
	if got := selectMdocResponseEnc([]string{"A128GCM", "A256GCM"}); got != jose.A256GCM {
		t.Fatalf("A256GCM advertised: got %v, want A256GCM", got)
	}
	if got := selectMdocResponseEnc(nil); got != jose.A128GCM {
		t.Fatalf("nothing advertised: got %v, want A128GCM default", got)
	}
}

// TestSummarizeCredentialMdoc proves summarizeCredential renders authentic mDL
// metadata for an mso_mdoc credential (base64url CBOR), rather than the blank
// summary the JWT/SD-JWT path produced. The wallet UI Credentials tab reads this
// summary, so without it the mDL showed empty format/doctype/claims.
func TestSummarizeCredentialMdoc(t *testing.T) {
	s := newMdocTestHarness(t)
	credential := issueMdocBoundTo(t, s, &s.deviceKey.PublicKey)

	summary := summarizeCredential(credential)
	if summary == nil {
		t.Fatal("summarizeCredential returned nil for an mso_mdoc credential")
		return
	}
	if summary.Format != credentialFormatMsoMdoc {
		t.Fatalf("summary.Format = %q, want %q", summary.Format, credentialFormatMsoMdoc)
	}
	if summary.Doctype != mdoc.DocTypeMDL {
		t.Fatalf("summary.Doctype = %q, want %q", summary.Doctype, mdoc.DocTypeMDL)
	}
	if summary.IsSDJWT {
		t.Fatal("mso_mdoc summary must not be flagged as SD-JWT")
	}
	if summary.ExpiresAt == "" {
		t.Fatal("summary.ExpiresAt should reflect the MSO validityInfo.validUntil")
	}
	nsClaims, ok := summary.Claims[string(mdoc.NameSpaceMDL)].(map[string]interface{})
	if !ok {
		t.Fatalf("summary.Claims missing namespace %q: %#v", mdoc.NameSpaceMDL, summary.Claims)
	}
	if _, ok := nsClaims["family_name"]; !ok {
		t.Fatalf("expected disclosed family_name element in summary claims, got %v", nsClaims)
	}
	if _, ok := nsClaims["age_over_18"]; !ok {
		t.Fatalf("expected disclosed age_over_18 element in summary claims, got %v", nsClaims)
	}
}
