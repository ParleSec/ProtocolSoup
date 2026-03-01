package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuerAudience = "http://localhost:8080/oid4vci"

func TestPreAuthorizedFlowWithTxCodeAndProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	preAuthCode := asString(t, offerPayload["pre_authorized_code"])
	offerURI := asString(t, offerPayload["credential_offer_uri"])
	walletSubject := asString(t, offerPayload["wallet_subject"])

	offerURL, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parse offer URI: %v", err)
	}
	offerGetResp, err := http.Get(server.URL + offerURL.Path)
	if err != nil {
		t.Fatalf("get credential offer: %v", err)
	}
	assertStatus(t, offerGetResp, http.StatusOK)
	_ = offerGetResp.Body.Close()

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, credentialPayload["credential"]) == "" {
		t.Fatalf("expected credential in response")
	}
}

func TestCredentialIssuerMetadataWellKnown(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	if asString(t, payload["credential_issuer"]) == "" {
		t.Fatalf("expected credential_issuer in metadata")
	}
	if asString(t, payload["credential_endpoint"]) == "" {
		t.Fatalf("expected credential_endpoint in metadata")
	}
	if asString(t, payload["nonce_endpoint"]) == "" {
		t.Fatalf("expected nonce_endpoint in metadata")
	}
}

func TestCredentialIssuerMetadataRejectsUnexpectedPathSuffix(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/openid-credential-issuer/unexpected")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDeferredIssuanceFlow(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized/deferred", map[string]interface{}{})
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
	cNonce := asString(t, tokenPayload["c_nonce"])
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	transactionID := asString(t, credentialPayload["transaction_id"])
	if transactionID == "" {
		t.Fatalf("expected deferred transaction_id")
	}

	time.Sleep(deferredReadyDelay + 200*time.Millisecond)

	deferredResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/deferred_credential",
		map[string]interface{}{
			"transaction_id": transactionID,
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, deferredResp, http.StatusOK)
	deferredPayload := decodeJSONMap(t, deferredResp)
	if asString(t, deferredPayload["credential"]) == "" {
		t.Fatalf("expected deferred credential")
	}
}

func TestCredentialRequestRejectsNonceMismatchProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{})
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

	proofJWT := createWalletProofJWT(t, "wrong-nonce", walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, credentialPayload["error"]) != "invalid_nonce" {
		t.Fatalf("expected invalid_nonce error, got %v", credentialPayload["error"])
	}
}

func TestCredentialRequestRejectsReplayOfPreviousProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{})
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
	cNonce := asString(t, tokenPayload["c_nonce"])

	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	firstCredentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, firstCredentialResp, http.StatusOK)
	_ = firstCredentialResp.Body.Close()

	replayCredentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, replayCredentialResp, http.StatusBadRequest)
	replayPayload := decodeJSONMap(t, replayCredentialResp)
	if asString(t, replayPayload["error"]) != "invalid_nonce" {
		t.Fatalf("expected invalid_nonce on replay, got %v", replayPayload["error"])
	}
}

func TestCredentialRequestRejectsMissingProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)

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

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof error, got %v", payload["error"])
	}
}

func TestCredentialRequestRejectsProofSignedByDifferentWallet(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	aliceOfferResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id": "alice",
	})
	assertStatus(t, aliceOfferResp, http.StatusCreated)
	aliceOffer := decodeJSONMap(t, aliceOfferResp)

	bobOfferResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id": "bob",
	})
	assertStatus(t, bobOfferResp, http.StatusCreated)
	bobOffer := decodeJSONMap(t, bobOfferResp)

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, aliceOffer["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)

	proofJWT := createWalletProofJWT(
		t,
		asString(t, tokenPayload["c_nonce"]),
		asString(t, bobOffer["wallet_subject"]),
		testIssuerAudience,
	)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
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
			"Authorization": "Bearer " + asString(t, tokenPayload["access_token"]),
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof error, got %v", payload["error"])
	}
}

func createWalletProofJWT(t *testing.T, nonce string, subject string, audience string) string {
	t.Helper()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("create wallet key set: %v", err)
	}
	publicJWK, found := keySet.GetJWKByID(keySet.RSAKeyID())
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
			"jwk": publicJWK,
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

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	vc.DefaultWalletCredentialStore().Reset()
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
	return httptest.NewServer(router)
}

func postJSON(t *testing.T, endpoint string, payload map[string]interface{}) *http.Response {
	t.Helper()
	return postJSONWithHeaders(t, endpoint, payload, nil)
}

func postJSONWithHeaders(t *testing.T, endpoint string, payload map[string]interface{}, headers map[string]string) *http.Response {
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

func assertStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
	}
}

func decodeJSONMap(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return payload
}

func asString(t *testing.T, value interface{}) string {
	t.Helper()
	str, _ := value.(string)
	return str
}
