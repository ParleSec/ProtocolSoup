package oid4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type combinedServer struct {
	Server *httptest.Server
	KeySet *crypto.KeySet
}

type combinedServerOptions struct {
	DataDir string
	KeySet  *crypto.KeySet
}

type walletFixture struct {
	Subject       string
	KeySet        *crypto.KeySet
	CredentialJWT string
}

const testIssuerAudience = "http://localhost:8080/oid4vci"
const testCredentialVCT = "https://protocolsoup.com/credentials/university_degree"

func TestDirectPostFlowEndToEnd(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostJWTFlowEndToEnd(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post.jwt")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestCreateAuthorizationRequestRejectsDCQLAndScopeTogether(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createResp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", map[string]interface{}{
		"response_mode": "direct_post",
		"response_uri":  env.Server.URL + "/oid4vp/response",
		"scope":         "openid",
		"dcql_query": map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id": "credential_query",
				},
			},
		},
	})
	assertVPStatus(t, createResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, createResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestDirectPostPolicyDenialForNonceMismatch(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "invalid-nonce")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	resultObj := resultPayload["result"].(map[string]interface{})
	policyObj := resultObj["policy"].(map[string]interface{})
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasons, _ := policyObj["reasons"].([]interface{})
	if !containsVPReason(reasons, "nonce mismatch") {
		t.Fatalf("expected nonce mismatch reason, got %v", reasons)
	}
}

func TestDirectPostPolicyDenialForNonceFromDifferentRequest(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	requestA := createVPRequest(t, env.Server.URL, "direct_post")
	requestB := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, requestA, wallet, asVPString(requestB["nonce"]))

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(requestA["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "nonce_mismatch") {
		t.Fatalf("expected nonce_mismatch reason code, got %v", reasonCodes)
	}
}

func TestDirectPostPolicyDenialForExpiredVPToken(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	expiredVPToken := createVPTokenWithExpiry(t, createPayload, wallet, time.Now().UTC().Add(-1*time.Minute))

	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"vp_token": {expiredVPToken},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "vp_token_expired") {
		t.Fatalf("expected vp_token_expired reason code, got %v", reasonCodes)
	}
}

func TestWalletResponseRejectsReplayAfterCompletion(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	replayToken := createVPToken(t, createPayload, wallet, "")
	replayResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"vp_token": {replayToken},
	})
	if err != nil {
		t.Fatalf("post replay wallet response failed: %v", err)
	}
	assertVPStatus(t, replayResp, http.StatusBadRequest)
	replayPayload := decodeVPJSONMap(t, replayResp)
	if asVPString(replayPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request, got %v", replayPayload["error"])
	}
	if !strings.Contains(strings.ToLower(asVPString(replayPayload["error_description"])), "already completed") {
		t.Fatalf("expected replay error_description to mention completion, got %v", replayPayload["error_description"])
	}
}

func TestDirectPostPolicyAllowsSelectiveDisclosureSubsetForMatchingDCQL(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	degreeOnlyCredential := filterCredentialDisclosures(t, wallet.CredentialJWT, []string{"degree"})
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id": "degree_only",
				"meta": map[string]interface{}{
					"vct_values": []string{testCredentialVCT},
				},
				"claims": []map[string]interface{}{
					{
						"path": []string{"degree"},
					},
				},
			},
		},
	})

	wallet.CredentialJWT = degreeOnlyCredential
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)

	resultObj := extractVPResult(t, resultPayload)
	credentialEvidence, ok := resultObj["credential_evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential evidence in verification result")
	}
	disclosedClaims, _ := credentialEvidence["disclosed_claims"].(map[string]interface{})
	if _, exists := disclosedClaims["degree"]; !exists {
		t.Fatalf("expected degree in disclosed_claims, got %v", disclosedClaims)
	}
	if _, exists := disclosedClaims["graduation_year"]; exists {
		t.Fatalf("expected graduation_year to remain undisclosed, got %v", disclosedClaims)
	}
}

func TestDirectPostPolicyDeniesMissingRequiredDisclosureClaim(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	wallet.CredentialJWT = filterCredentialDisclosures(t, wallet.CredentialJWT, []string{"degree"})
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "missing_required_claim") {
		t.Fatalf("expected missing_required_claim reason code, got %v", reasonCodes)
	}
}

func TestDirectPostPolicyDeniesMissingLineageWithExplicitCode(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	wallet.CredentialJWT = createUntrackedCredentialJWT(t, wallet)
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "missing_lineage") {
		t.Fatalf("expected missing_lineage reason code, got %v", reasonCodes)
	}
}

func TestDirectPostFlowSurvivesVerifierRestartWithPersistentState(t *testing.T) {
	dataDir := t.TempDir()
	env1 := newCombinedVCServerWithOptions(t, combinedServerOptions{
		DataDir: dataDir,
	})
	wallet := issueCredentialForWallet(t, env1.Server.URL, "alice")
	createPayload := createVPRequest(t, env1.Server.URL, "direct_post")
	env1.Server.Close()

	env2 := newCombinedVCServerWithOptions(t, combinedServerOptions{
		DataDir: dataDir,
	})
	defer env2.Server.Close()

	postWalletResponse(t, env2.Server.URL, env2.KeySet, createPayload, wallet, "")
	resultPayload := fetchVerificationResult(t, env2.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostJWTRejectsInvalidEncryptedResponse(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post.jwt")
	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"response": {"invalid-jwe-response"},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, formResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestWalletResponseRejectsUnknownState(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {"unknown-state"},
		"vp_token": {"placeholder-token"},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, formResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestExternalInteropConformance(t *testing.T) {
	if strings.TrimSpace(os.Getenv("RUN_EXTERNAL_INTEROP_CONFORMANCE")) != "1" {
		t.Skip("set RUN_EXTERNAL_INTEROP_CONFORMANCE=1 to execute external interop conformance")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("CONFORMANCE_BASE_URL")), "/")
	walletSubmitURL := strings.TrimSpace(os.Getenv("CONFORMANCE_EXTERNAL_WALLET_SUBMIT_URL"))
	if baseURL == "" || walletSubmitURL == "" {
		t.Skip("external interop requires CONFORMANCE_BASE_URL and CONFORMANCE_EXTERNAL_WALLET_SUBMIT_URL")
	}

	walletUserID := strings.TrimSpace(os.Getenv("CONFORMANCE_WALLET_USER_ID"))
	if walletUserID == "" {
		walletUserID = "alice"
	}

	wallet := issueCredentialForExternalWallet(t, baseURL, walletUserID)
	runExternalWalletFlow(t, baseURL, walletSubmitURL, wallet, "direct_post")
	runExternalWalletFlow(t, baseURL, walletSubmitURL, wallet, "direct_post.jwt")
}

func createVPRequest(t *testing.T, serverURL string, responseMode string) map[string]interface{} {
	t.Helper()
	return createVPRequestPayload(t, serverURL, map[string]interface{}{
		"response_mode": responseMode,
		"response_uri":  serverURL + "/oid4vp/response",
	})
}

func createVPRequestWithDCQL(
	t *testing.T,
	serverURL string,
	responseMode string,
	dcqlQuery map[string]interface{},
) map[string]interface{} {
	t.Helper()
	return createVPRequestPayload(t, serverURL, map[string]interface{}{
		"response_mode": responseMode,
		"response_uri":  serverURL + "/oid4vp/response",
		"dcql_query":    dcqlQuery,
	})
}

func createVPRequestPayload(t *testing.T, serverURL string, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	createResp := postVPJSON(t, serverURL+"/oid4vp/request/create", payload)
	assertVPStatus(t, createResp, http.StatusCreated)
	createPayload := decodeVPJSONMap(t, createResp)
	if asVPString(createPayload["request_id"]) == "" {
		t.Fatalf("expected request_id")
	}
	return createPayload
}

func issueCredentialForExternalWallet(t *testing.T, baseURL string, walletUserID string) *walletFixture {
	t.Helper()

	metadataResp, err := http.Get(baseURL + "/.well-known/openid-credential-issuer/oid4vci")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertVPStatus(t, metadataResp, http.StatusOK)
	metadataPayload := decodeVPJSONMap(t, metadataResp)
	issuerID := asVPString(metadataPayload["credential_issuer"])
	if issuerID == "" {
		t.Fatalf("metadata missing credential_issuer")
	}

	offerResp := postVPJSON(t, baseURL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id": walletUserID,
	})
	assertVPStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeVPJSONMap(t, offerResp)
	walletSubject := asVPString(offerPayload["wallet_subject"])
	if walletSubject == "" {
		t.Fatalf("offer response missing wallet_subject")
	}

	tokenResp, err := http.PostForm(baseURL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asVPString(offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertVPStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeVPJSONMap(t, tokenResp)

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, asVPString(tokenPayload["c_nonce"]), issuerID)

	credentialResp := postVPJSONWithHeaders(
		t,
		baseURL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{
					"proof_type": "jwt",
					"jwt":        proofJWT,
				},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + asVPString(tokenPayload["access_token"]),
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := asVPString(credentialPayload["credential"])
	if credentialJWT == "" {
		t.Fatalf("credential response missing credential")
	}

	return &walletFixture{
		Subject:       walletSubject,
		KeySet:        walletKeySet,
		CredentialJWT: credentialJWT,
	}
}

func issueCredentialForWallet(t *testing.T, serverURL string, walletUserID string) *walletFixture {
	t.Helper()

	offerResp := postVPJSON(t, serverURL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id": walletUserID,
	})
	assertVPStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeVPJSONMap(t, offerResp)
	walletSubject := asVPString(offerPayload["wallet_subject"])
	if walletSubject == "" {
		t.Fatalf("offer response missing wallet_subject")
	}

	tokenResp, err := http.PostForm(serverURL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asVPString(offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertVPStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeVPJSONMap(t, tokenResp)

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, asVPString(tokenPayload["c_nonce"]), testIssuerAudience)

	credentialResp := postVPJSONWithHeaders(
		t,
		serverURL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{
					"proof_type": "jwt",
					"jwt":        proofJWT,
				},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + asVPString(tokenPayload["access_token"]),
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := asVPString(credentialPayload["credential"])
	if credentialJWT == "" {
		t.Fatalf("credential response missing credential")
	}

	return &walletFixture{
		Subject:       walletSubject,
		KeySet:        walletKeySet,
		CredentialJWT: credentialJWT,
	}
}

func runExternalWalletFlow(
	t *testing.T,
	baseURL string,
	externalWalletSubmitURL string,
	wallet *walletFixture,
	responseMode string,
) {
	t.Helper()

	createPayload := createVPRequest(t, baseURL, responseMode)
	requestID := asVPString(createPayload["request_id"])
	if requestID == "" {
		t.Fatalf("request response missing request_id")
	}

	submitResp := postVPJSON(t, externalWalletSubmitURL, map[string]interface{}{
		"request_id":     requestID,
		"request_uri":    asVPString(createPayload["request_uri"]),
		"request":        asVPString(createPayload["request"]),
		"response_mode":  responseMode,
		"response_uri":   asVPString(createPayload["response_uri"]),
		"state":          asVPString(createPayload["state"]),
		"nonce":          asVPString(createPayload["nonce"]),
		"client_id":      asVPString(createPayload["client_id"]),
		"wallet_subject": wallet.Subject,
		"credential_jwt": wallet.CredentialJWT,
	})
	if submitResp.StatusCode < http.StatusOK || submitResp.StatusCode >= http.StatusMultipleChoices {
		payload := decodeVPJSONMap(t, submitResp)
		t.Fatalf("external wallet submit expected 2xx, got %d with payload %v", submitResp.StatusCode, payload)
	}
	_ = submitResp.Body.Close()

	resultPayload := fetchVerificationResultWithTimeout(t, baseURL, requestID, 45*time.Second)
	assertPolicyAllowed(t, resultPayload)
}

func createProofJWT(t *testing.T, keySet *crypto.KeySet, subject string, nonce string, audience string) string {
	t.Helper()
	pubJWK, found := keySet.GetJWKByID(keySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet rsa jwk is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   "proof-" + subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["kid"] = keySet.RSAKeyID()
	signed, err := token.SignedString(keySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign proof jwt: %v", err)
	}
	return signed
}

func postWalletResponse(
	t *testing.T,
	serverURL string,
	verifierKeySet *crypto.KeySet,
	createPayload map[string]interface{},
	wallet *walletFixture,
	nonceOverride string,
) {
	t.Helper()
	vpToken := createVPToken(t, createPayload, wallet, nonceOverride)
	state := asVPString(createPayload["state"])
	responseMode := asVPString(createPayload["response_mode"])

	form := url.Values{}
	form.Set("state", state)
	if responseMode == "direct_post.jwt" {
		encryptedResponse := createEncryptedResponseJWT(t, verifierKeySet, createPayload, wallet, vpToken)
		form.Set("response", encryptedResponse)
	} else {
		form.Set("vp_token", vpToken)
	}
	formResp, err := http.PostForm(serverURL+"/oid4vp/response", form)
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)
}

func createVPToken(t *testing.T, createPayload map[string]interface{}, wallet *walletFixture, nonceOverride string) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	nonce := asVPString(createPayload["nonce"])
	if strings.TrimSpace(nonceOverride) != "" {
		nonce = strings.TrimSpace(nonceOverride)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   asVPString(createPayload["client_id"]),
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"jti":   "vp-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
		"vp": map[string]interface{}{
			"credential_jwt": wallet.CredentialJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign vp token: %v", err)
	}
	return signed
}

func createVPTokenWithExpiry(
	t *testing.T,
	createPayload map[string]interface{},
	wallet *walletFixture,
	expiry time.Time,
) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   asVPString(createPayload["client_id"]),
		"nonce": asVPString(createPayload["nonce"]),
		"iat":   now.Add(-2 * time.Minute).Unix(),
		"exp":   expiry.Unix(),
		"jti":   "vp-expired-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
		"vp": map[string]interface{}{
			"credential_jwt": wallet.CredentialJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign vp token: %v", err)
	}
	return signed
}

func createEncryptedResponseJWT(
	t *testing.T,
	verifierKeySet *crypto.KeySet,
	createPayload map[string]interface{},
	wallet *walletFixture,
	vpToken string,
) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	now := time.Now().UTC()
	innerClaims := jwt.MapClaims{
		"iss":      wallet.Subject,
		"sub":      wallet.Subject,
		"aud":      asVPString(createPayload["response_uri"]),
		"state":    asVPString(createPayload["state"]),
		"vp_token": vpToken,
		"iat":      now.Unix(),
		"exp":      now.Add(3 * time.Minute).Unix(),
		"jti":      "resp-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
	}
	innerToken := jwt.NewWithClaims(jwt.SigningMethodRS256, innerClaims)
	innerToken.Header["typ"] = "oauth-authz-resp+jwt"
	innerToken.Header["kid"] = wallet.KeySet.RSAKeyID()
	signedInner, err := innerToken.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign response jwt: %v", err)
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       verifierKeySet.RSAPublicKey(),
		},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatalf("create encrypter: %v", err)
	}
	object, err := encrypter.Encrypt([]byte(signedInner))
	if err != nil {
		t.Fatalf("encrypt response jwt: %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize jwe: %v", err)
	}
	return serialized
}

func filterCredentialDisclosures(t *testing.T, credentialJWT string, requestedClaims []string) string {
	t.Helper()
	envelope, err := vc.ParseSDJWTEnvelope(credentialJWT)
	if err != nil {
		t.Fatalf("parse sd-jwt envelope: %v", err)
	}
	if len(envelope.Disclosures) == 0 {
		t.Fatalf("expected sd-jwt disclosures in issued credential")
	}
	allow := make(map[string]struct{}, len(requestedClaims))
	for _, claim := range requestedClaims {
		normalized := strings.TrimSpace(claim)
		if normalized == "" {
			continue
		}
		allow[normalized] = struct{}{}
	}
	selected := make([]string, 0, len(envelope.Disclosures))
	for _, encodedDisclosure := range envelope.Disclosures {
		disclosure, err := vc.DecodeSDJWTDisclosure(encodedDisclosure)
		if err != nil {
			t.Fatalf("decode disclosure: %v", err)
		}
		if len(allow) == 0 {
			selected = append(selected, disclosure.Encoded)
			continue
		}
		if _, ok := allow[strings.TrimSpace(disclosure.ClaimName)]; ok {
			selected = append(selected, disclosure.Encoded)
		}
	}
	return vc.BuildSDJWTSerialization(envelope.IssuerSignedJWT, selected, envelope.KeyBindingJWT)
}

func createUntrackedCredentialJWT(t *testing.T, wallet *walletFixture) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": "https://example.org/untracked-issuer",
		"sub": wallet.Subject,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": "untracked-" + wallet.Subject,
		"vct": "https://protocolsoup.com/credentials/untracked",
		"vc": map[string]interface{}{
			"credentialSubject": map[string]interface{}{
				"id":     wallet.Subject,
				"degree": "Untracked Credential",
			},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vc+sd-jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign untracked credential: %v", err)
	}
	return vc.BuildSDJWTSerialization(signed, nil, "")
}

func fetchVerificationResult(t *testing.T, serverURL string, requestID string) map[string]interface{} {
	t.Helper()
	resultResp, err := http.Get(serverURL + "/oid4vp/result/" + requestID)
	if err != nil {
		t.Fatalf("result request failed: %v", err)
	}
	assertVPStatus(t, resultResp, http.StatusOK)
	resultPayload := decodeVPJSONMap(t, resultResp)
	if asVPString(resultPayload["status"]) != "completed" {
		t.Fatalf("expected completed status, got %v", resultPayload["status"])
	}
	return resultPayload
}

func fetchVerificationResultWithTimeout(t *testing.T, baseURL string, requestID string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for completed verification result for request %s", requestID)
		}

		resultResp, err := http.Get(baseURL + "/oid4vp/result/" + requestID)
		if err != nil {
			t.Fatalf("result request failed: %v", err)
		}
		assertVPStatus(t, resultResp, http.StatusOK)
		resultPayload := decodeVPJSONMap(t, resultResp)
		if asVPString(resultPayload["status"]) == "completed" {
			return resultPayload
		}
		time.Sleep(1 * time.Second)
	}
}

func assertPolicyAllowed(t *testing.T, resultPayload map[string]interface{}) {
	t.Helper()
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || !allowed {
		t.Fatalf("expected allowed policy decision")
	}
}

func extractVPResult(t *testing.T, resultPayload map[string]interface{}) map[string]interface{} {
	t.Helper()
	resultObj, ok := resultPayload["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result object")
	}
	return resultObj
}

func extractVPPolicy(t *testing.T, resultPayload map[string]interface{}) map[string]interface{} {
	t.Helper()
	resultObj := extractVPResult(t, resultPayload)
	policyObj, ok := resultObj["policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected policy object")
	}
	return policyObj
}

func newCombinedVCServer(t *testing.T) *combinedServer {
	t.Helper()
	return newCombinedVCServerWithOptions(t, combinedServerOptions{})
}

func newCombinedVCServerWithOptions(t *testing.T, options combinedServerOptions) *combinedServer {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()

	keySet := options.KeySet
	if keySet == nil {
		var err error
		keySet, err = crypto.NewKeySet()
		if err != nil {
			t.Fatalf("new key set: %v", err)
		}
	}
	idp := mockidp.NewMockIdP(keySet)

	vciPlugin := oid4vci.NewPlugin()
	if err := vciPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		DataDir: strings.TrimSpace(options.DataDir),
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize oid4vci plugin: %v", err)
	}

	vpPlugin := NewPlugin()
	if err := vpPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		DataDir: strings.TrimSpace(options.DataDir),
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize oid4vp plugin: %v", err)
	}

	router := chi.NewRouter()
	router.Route("/oid4vci", func(r chi.Router) {
		vciPlugin.RegisterRoutes(r)
	})
	router.Route("/oid4vp", func(r chi.Router) {
		vpPlugin.RegisterRoutes(r)
	})
	return &combinedServer{
		Server: httptest.NewServer(router),
		KeySet: keySet,
	}
}

func postVPJSON(t *testing.T, endpoint string, payload map[string]interface{}) *http.Response {
	t.Helper()
	return postVPJSONWithHeaders(t, endpoint, payload, nil)
}

func postVPJSONWithHeaders(t *testing.T, endpoint string, payload map[string]interface{}, headers map[string]string) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	return resp
}

func assertVPStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
	}
}

func decodeVPJSONMap(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return payload
}

func asVPString(value interface{}) string {
	str, _ := value.(string)
	return str
}

func containsVPReason(reasons []interface{}, expected string) bool {
	for _, reason := range reasons {
		if strings.EqualFold(strings.TrimSpace(asVPString(reason)), expected) {
			return true
		}
	}
	return false
}

func containsVPReasonCode(codes []interface{}, expected string) bool {
	for _, code := range codes {
		if strings.EqualFold(strings.TrimSpace(asVPString(code)), expected) {
			return true
		}
	}
	return false
}
