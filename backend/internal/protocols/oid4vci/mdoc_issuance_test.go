package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const mdocConfigurationID = "MobileDrivingLicenceMsoMdoc"

// newMdocTestEnv builds an OID4VCI server alongside the live plugin and mock IdP
// so a test can drive the HTTP flow and still reach the issuer trust anchor.
func newMdocTestEnv(t *testing.T) (*httptest.Server, *Plugin, *mockidp.MockIdP) {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	idp := mockidp.NewMockIdP(keySet)
	testPlugin := NewPlugin()
	if err := testPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize plugin: %v", err)
	}
	router := chi.NewRouter()
	router.Route("/oid4vci", func(r chi.Router) {
		testPlugin.RegisterRoutes(r)
	})
	return httptest.NewServer(router), testPlugin, idp
}

// createECDeviceProof builds an OID4VCI proof JWT signed by an EC P-256 device
// key, carrying the public key in the JOSE jwk header. This is the holder device key the
// mso_mdoc issuer binds into the MSO.
func createECDeviceProof(t *testing.T, deviceKey *ecdsa.PrivateKey, nonce, subject, audience string) string {
	t.Helper()
	publicJWK := crypto.JWKFromECPublicKey(&deviceKey.PublicKey, "device-key-1")
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   "proof-" + subject,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = publicJWK
	signed, err := token.SignedString(deviceKey)
	if err != nil {
		t.Fatalf("sign device proof: %v", err)
	}
	return signed
}

// decodeAndVerifyMdoc decodes the base64url mso_mdoc credential, verifies it
// against the issuer IACA trust anchor, and returns the MSO and IssuerSigned.
func decodeAndVerifyMdoc(t *testing.T, p *Plugin, credential string) (*mdoc.MobileSecurityObject, mdoc.IssuerSigned) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		t.Fatalf("base64url decode credential: %v", err)
	}
	issuerSigned, err := mdoc.DecodeIssuerSigned(raw)
	if err != nil {
		t.Fatalf("decode IssuerSigned: %v", err)
	}
	mso, err := mdoc.VerifyIssuerSigned(issuerSigned, p.mdocPKI.TrustAnchors(), time.Now().UTC())
	if err != nil {
		t.Fatalf("verify issued mDL against IACA trust anchor: %v", err)
	}
	return mso, issuerSigned
}

// TestMsoMdocPreAuthorizedIssuance issues a real mDL over the pre-authorized
// code flow, binds the device key from the proof, and verifies the issued
// credential structurally and cryptographically.
func TestMsoMdocPreAuthorizedIssuance(t *testing.T) {
	server, testPlugin, _ := newMdocTestEnv(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{mdocConfigurationID},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	proofJWT := createECDeviceProof(t, deviceKey, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"format":                      "mso_mdoc",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	credential := asString(t, firstCredential(t, credentialPayload))
	if credential == "" {
		t.Fatal("expected non-empty mso_mdoc credential")
	}

	mso, issuerSigned := decodeAndVerifyMdoc(t, testPlugin, credential)

	if mso.DocType != mdoc.DocTypeMDL {
		t.Fatalf("expected docType %q, got %q", mdoc.DocTypeMDL, mso.DocType)
	}

	// The MSO must bind the exact device key supplied in the proof.
	boundKey, err := intcose.COSEKeyToECPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		t.Fatalf("decode bound device key: %v", err)
	}
	if !boundKey.Equal(&deviceKey.PublicKey) {
		t.Fatal("MSO deviceKey does not match the proof device key")
	}

	// The mDL namespace must carry the expected data elements.
	items := issuerSigned.NameSpaces[mdoc.NameSpaceMDL]
	if len(items) == 0 {
		t.Fatal("expected issuer-signed items in the mDL namespace")
	}
	found := map[string]bool{}
	values := map[string]interface{}{}
	for _, raw := range items {
		item, decErr := mdoc.DecodeIssuerSignedItemBytes(raw)
		if decErr != nil {
			t.Fatalf("decode issuer signed item: %v", decErr)
		}
		found[item.ElementIdentifier] = true
		values[item.ElementIdentifier] = item.ElementValue
	}
	for _, required := range []string{"family_name", "given_name", "birth_date", "issuing_country", "document_number"} {
		if !found[required] {
			t.Fatalf("expected mDL element %q to be present", required)
		}
	}
	if got := fmt.Sprint(values["family_name"]); got != "Johnson" {
		t.Fatalf("family_name = %q, want identity-record value Johnson", got)
	}
	if got := fmt.Sprint(values["given_name"]); got != "Alice" {
		t.Fatalf("given_name = %q, want identity-record value Alice", got)
	}
	if got := fmt.Sprint(values["document_number"]); got != "D-ALICE-001" {
		t.Fatalf("document_number = %q, want identity-record value D-ALICE-001", got)
	}
	if got := fmt.Sprint(values["birth_date"]); !strings.Contains(got, "1990-03-12") {
		t.Fatalf("birth_date = %q, want identity-record date 1990-03-12", got)
	}
}

// TestMsoMdocAuthorizationCodeIssuance issues an mDL over the authorization code
// flow, confirming the format driver works for both grant types.
func TestMsoMdocAuthorizationCodeIssuance(t *testing.T) {
	server, testPlugin, idp := newMdocTestEnv(t)
	defer server.Close()

	// Generate the client identifier and use the IdP's designated identity.
	clientID := "mdoc-client-" + testPlugin.randomValue(8)
	userID := idp.DefaultUserID()
	const redirectURI = "https://wallet.example/cb"
	idp.RegisterClient(&models.Client{
		ID:           clientID,
		Name:         "mDL Test Wallet",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "vc:mdl"},
		Public:       true,
	})

	authCode, err := idp.CreateAuthorizationCode(
		clientID, userID, redirectURI, "openid vc:mdl", "state-1", "",
		"", "", "", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	assertTokenResponseHasNoCredentialNonce(t, tokenPayload)
	if accessToken == "" {
		t.Fatal("expected access token from authorization code grant")
	}
	cNonce := fetchCNonce(t, server.URL, accessToken)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	// The proof subject must equal the grant subject, which the issuer derives as
	// the wallet DID from the (normalized) user id. Use the same normalization so
	// the proof binding matches.
	proofSubject := "did:example:wallet:" + normalizeSubjectComponent(userID)
	proofJWT := createECDeviceProof(t, deviceKey, cNonce, proofSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	credential := asString(t, firstCredential(t, credentialPayload))
	if credential == "" {
		t.Fatal("expected non-empty mso_mdoc credential from authorization code flow")
	}
	mso, _ := decodeAndVerifyMdoc(t, testPlugin, credential)
	boundKey, err := intcose.COSEKeyToECPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		t.Fatalf("decode bound device key: %v", err)
	}
	if !boundKey.Equal(&deviceKey.PublicKey) {
		t.Fatal("MSO deviceKey does not match the proof device key (authorization code flow)")
	}
}

// TestMsoMdocIssuedCredentialNestingDepthWithinHardenedCeiling measures the
// actual CBOR nesting depth of a real, production-shaped issued mDL --
// including driving_privileges, the one element with array-of-maps-of-
// tagged-full-dates structure, which is the deepest path in
// buildMDLIssuerSignedItems -- against mdoc.CheckUntrustedCBOR's hardened
// gate. This exists because a prior revision of the MaxNestedLevels=16
// derivation stated a depth (~8) that did not match the gate's own
// cumulative tag-24 accounting once that accounting was corrected; this
// test replaces "asserted in a comment" with "measured against a real
// issued credential", and fails if a future change to the mDL element set
// or its encoding pushes the real depth close enough to 16 that the margin
// this ceiling assumes no longer holds.
func TestMsoMdocIssuedCredentialNestingDepthWithinHardenedCeiling(t *testing.T) {
	server, _, _ := newMdocTestEnv(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{mdocConfigurationID},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	proofJWT := createECDeviceProof(t, deviceKey, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"format":                      "mso_mdoc",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	credential := asString(t, firstCredential(t, credentialPayload))
	if credential == "" {
		t.Fatal("expected non-empty mso_mdoc credential")
	}

	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		t.Fatalf("base64url decode credential: %v", err)
	}

	depth, err := mdoc.CheckUntrustedCBOR(raw)
	if err != nil {
		t.Fatalf("mdoc.CheckUntrustedCBOR rejected a real production-shaped issued mDL: %v", err)
	}
	t.Logf("measured nesting depth of a real issued mDL (11 elements incl. driving_privileges): %d", depth)

	// 16 mirrors mdoc.maxUntrustedNestedLevels (internal/mdoc/issuersigned.go),
	// which is unexported; duplicated here as a literal rather than exported
	// solely for this test's convenience.
	const maxUntrustedNestedLevels = 16
	if depth <= 0 {
		t.Fatalf("measured depth %d is non-positive; a real IssuerSigned structure must nest at least a few levels deep", depth)
	}
	if depth >= maxUntrustedNestedLevels {
		t.Fatalf("measured depth %d of a real issued mDL leaves no margin under MaxNestedLevels=%d", depth, maxUntrustedNestedLevels)
	}
	if margin := maxUntrustedNestedLevels - depth; margin < 4 {
		t.Fatalf("measured depth %d leaves only %d levels of margin under MaxNestedLevels=%d, tighter than the intended headroom", depth, margin, maxUntrustedNestedLevels)
	}
}

// TestMsoMdocIssuedCredentialValidateIssuerSignatureTriState exercises
// vc.MSOMdocFormat.ValidateIssuerSignature's tri-state result against a real,
// production-issued mDL (through the full HTTP issuance pipeline, not a
// hand-assembled fixture), confirming the same trust outcomes the internal/vc
// unit tests pin also hold end-to-end: verified against the issuing plugin's
// own IACA root, failed against an unrelated one, and not evaluated when no
// trust anchor is supplied at all.
func TestMsoMdocIssuedCredentialValidateIssuerSignatureTriState(t *testing.T) {
	server, testPlugin, _ := newMdocTestEnv(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{mdocConfigurationID},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	proofJWT := createECDeviceProof(t, deviceKey, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"format":                      "mso_mdoc",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	credential := asString(t, firstCredential(t, credentialPayload))
	if credential == "" {
		t.Fatal("expected non-empty mso_mdoc credential")
	}

	registry := vc.DefaultCredentialFormatRegistry()
	formatHandler, ok := registry.Lookup("mso_mdoc")
	if !ok {
		t.Fatalf("mso_mdoc format handler not found in registry")
	}

	t.Run("verified_against_issuing_plugin_trust_anchor", func(t *testing.T) {
		trustStatus, err := formatHandler.ValidateIssuerSignature(vc.CredentialValidationInput{
			Credential:         credential,
			IssuerTrustAnchors: testPlugin.mdocPKI.TrustAnchors(),
		})
		if err != nil {
			t.Fatalf("ValidateIssuerSignature(issuing plugin's own IACA root): %v", err)
		}
		if trustStatus != vc.IssuerTrustVerified {
			t.Fatalf("trust status = %v, want IssuerTrustVerified", trustStatus)
		}
	})

	t.Run("failed_against_unrelated_trust_anchor", func(t *testing.T) {
		unrelatedPKI, err := mdoc.GenerateIssuerPKI(mdoc.DefaultPKIParams("https://unrelated-issuer.example/oid4vci"))
		if err != nil {
			t.Fatalf("GenerateIssuerPKI(unrelated): %v", err)
		}
		trustStatus, err := formatHandler.ValidateIssuerSignature(vc.CredentialValidationInput{
			Credential:         credential,
			IssuerTrustAnchors: unrelatedPKI.TrustAnchors(),
		})
		if err == nil {
			t.Fatalf("ValidateIssuerSignature(unrelated IACA root) unexpectedly succeeded")
		}
		if trustStatus != vc.IssuerTrustFailed {
			t.Fatalf("trust status = %v, want IssuerTrustFailed", trustStatus)
		}
	})

	t.Run("not_evaluated_without_trust_anchor", func(t *testing.T) {
		trustStatus, err := formatHandler.ValidateIssuerSignature(vc.CredentialValidationInput{
			Credential: credential,
		})
		if err == nil {
			t.Fatalf("ValidateIssuerSignature(no trust anchor) unexpectedly succeeded")
		}
		if trustStatus != vc.IssuerTrustNotEvaluated {
			t.Fatalf("trust status = %v, want IssuerTrustNotEvaluated", trustStatus)
		}
	})
}

// TestMsoMdocRejectsNonECDeviceKey confirms an RSA proof key is rejected, since
// mdoc device keys must be EC2/P-256.
func TestMsoMdocRejectsNonECDeviceKey(t *testing.T) {
	server, _, _ := newMdocTestEnv(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{mdocConfigurationID},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

	// An RSA-backed proof carries an RSA cnf.jwk, which is invalid for mdoc.
	rsaProof := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)
	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"proofs": map[string]interface{}{
				"jwt": []string{rsaProof},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	// The driver rejects the non-EC device key, surfaced as a server error.
	if credentialResp.StatusCode == http.StatusOK {
		t.Fatal("expected mso_mdoc issuance to reject an RSA device key")
	}
}
