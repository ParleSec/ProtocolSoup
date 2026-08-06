package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// dpopOID4VCITestServer bundles the running httptest server with a handle to
// the plugin instance, needed for tests that inject a failing replay store.
// newTestServer (plugin_test.go) intentionally does not expose the plugin,
// so this is a separate, minimal constructor rather than a signature change
// to a helper every other test in this package already depends on.
type dpopOID4VCITestServer struct {
	server *httptest.Server
	plugin *Plugin
}

func newDPoPOID4VCITestServer(t *testing.T) *dpopOID4VCITestServer {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()
	keySet, err := internalcrypto.NewKeySet()
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
	httpServer := httptest.NewServer(router)
	t.Cleanup(httpServer.Close)
	// The plugin computes htu comparison targets (tokenEndpointURL) from its
	// configured baseURL, which must match the actual httptest listener
	// address issuing the requests, not the placeholder passed to
	// Initialize above.
	testPlugin.baseURL = httpServer.URL
	idp.SetIssuer(httpServer.URL)
	return &dpopOID4VCITestServer{server: httpServer, plugin: testPlugin}
}

type dpopOID4VCITestKey struct {
	privateKey *ecdsa.PrivateKey
	jwk        internalcrypto.JWK
}

func newDPoPOID4VCITestKey(t *testing.T) dpopOID4VCITestKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return dpopOID4VCITestKey{
		privateKey: privateKey,
		jwk:        internalcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "oid4vci-dpop-test-key"),
	}
}

func (k dpopOID4VCITestKey) proof(t *testing.T, htm, htu string, overrides jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"jti": "oid4vci-dpop-jti-" + randomTestSuffix(t),
		"htm": htm,
		"htu": htu,
		"iat": time.Now().UTC().Unix(),
	}
	for key, value := range overrides {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = dpop.ProofTyp
	token.Header["jwk"] = map[string]interface{}{
		"kty": k.jwk.Kty,
		"crv": k.jwk.Crv,
		"x":   k.jwk.X,
		"y":   k.jwk.Y,
	}
	signed, err := token.SignedString(k.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// computeTestATH mirrors the unexported dpop.computeATH (RFC 9449 Section
// 4.2): base64url(SHA-256(access token)). Resource-endpoint proofs must
// carry this so ValidateProof's mandatory ath check succeeds.
func computeTestATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func randomTestSuffix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, c := range raw {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}

func accessTokenCnfJKT(t *testing.T, accessToken string) string {
	t.Helper()
	decoded, err := internalcrypto.DecodeTokenWithoutValidation(accessToken)
	if err != nil {
		t.Fatalf("decode access token: %v", err)
	}
	cnf, ok := decoded.Payload["cnf"].(map[string]interface{})
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func requestPreAuthorizedOffer(t *testing.T, server *dpopOID4VCITestServer) (preAuthCode, walletSubject string) {
	t.Helper()
	offerResp := postJSON(t, server.server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	return asString(t, offerPayload["pre_authorized_code"]), asString(t, offerPayload["wallet_subject"])
}

func postTokenRequestForm(t *testing.T, serverURL string, form url.Values, dpopProof string) (int, map[string]interface{}) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oid4vci/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		request.Header.Set(dpop.HeaderName, dpopProof)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode, decodeJSONMap(t, response)
}

// postTokenRequestFormCapturingHeaders mirrors postTokenRequestForm but
// also returns the response headers, needed for asserting on the
// DPoP-Nonce response header (RFC 9449 Section 8).
func postTokenRequestFormCapturingHeaders(t *testing.T, serverURL string, form url.Values, dpopProof string) (int, map[string]interface{}, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oid4vci/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		request.Header.Set(dpop.HeaderName, dpopProof)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode, decodeJSONMap(t, response), response.Header
}

func TestPreAuthorizedTokenGrantBindsDPoPAccessToken(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	accessToken := asString(t, body["access_token"])
	if jkt := accessTokenCnfJKT(t, accessToken); jkt != key.jwk.Thumbprint() {
		t.Fatalf("cnf.jkt = %q, want %q", jkt, key.jwk.Thumbprint())
	}
}

func TestPreAuthorizedTokenGrantWithoutDPoPStaysBearer(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
	accessToken := asString(t, body["access_token"])
	if jkt := accessTokenCnfJKT(t, accessToken); jkt != "" {
		t.Fatalf("unbound token carries cnf.jkt = %q", jkt)
	}
}

func TestTokenEndpointRejectsInvalidDPoPProofOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, "not-a-valid-proof")
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorInvalidDPoPProof)
	}
}

// TestTokenEndpointRejectsMultipleDPoPHeadersOID4VCI covers RFC 9449
// Section 4.3 check 1 at this plugin's own token endpoint: a request
// carrying more than one DPoP header field must be rejected outright, not
// silently resolved to the first value.
func TestTokenEndpointRejectsMultipleDPoPHeadersOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	request, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add(dpop.HeaderName, proof)
	request.Header.Add(dpop.HeaderName, proof)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body := decodeJSONMap(t, response)
	if response.StatusCode != http.StatusBadRequest || body["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("status = %d, body = %#v, want 400 %s", response.StatusCode, body, dpop.ErrorInvalidDPoPProof)
	}
}

func TestTokenEndpointDPoPReplayStoreOutageFailsClosedOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopReplay = failingOID4VCIDPoPReplayStore{}
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, proof)
	if status != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("status = %d, body = %#v, want 500 server_error (fail closed)", status, body)
	}
}

type failingOID4VCIDPoPReplayStore struct{}

func (failingOID4VCIDPoPReplayStore) Reserve(context.Context, string, string, time.Time, time.Time) (bool, error) {
	return false, errDPoPProofReplayed
}
func (failingOID4VCIDPoPReplayStore) Close() error { return nil }

// issueDPoPBoundCredentialGrant runs the pre-authorized token grant bound to
// key and returns the resulting access token, for resource-endpoint tests.
func issueDPoPBoundCredentialGrant(t *testing.T, server *dpopOID4VCITestServer, key dpopOID4VCITestKey) (accessToken, walletSubject string) {
	t.Helper()
	preAuthCode, subject := requestPreAuthorizedOffer(t, server)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("token issuance status = %d, body = %#v", status, body)
	}
	return asString(t, body["access_token"]), subject
}

func TestNonceEndpointAcceptsBoundTokenWithMatchingProof(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	proof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})

	request, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	request.Header.Set(dpop.HeaderName, proof)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

// TestNonceEndpointRejectsMultipleDPoPHeaders covers RFC 9449 Section 4.3
// check 1 at a resource endpoint: a request carrying more than one DPoP
// header field must be rejected outright.
func TestNonceEndpointRejectsMultipleDPoPHeaders(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	proof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})

	request, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	request.Header.Add(dpop.HeaderName, proof)
	request.Header.Add(dpop.HeaderName, proof)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
}

func TestNonceEndpointRejectsBoundTokenPresentedAsBearer(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)

	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oid4vci/nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Presented as a bare bearer token, no DPoP proof at all -- this is the
	// entire security property DPoP exists to enforce.
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
	wwwAuthenticate := response.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuthenticate, dpop.HeaderName) {
		t.Fatalf("WWW-Authenticate = %q, want DPoP scheme", wwwAuthenticate)
	}
}

func TestNonceEndpointRejectsBoundTokenWithNoProofAtAllUnderDPoPScheme(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)

	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oid4vci/nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	// No DPoP proof header at all.
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
}

func TestNonceEndpointRejectsProofFromDifferentKey(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	originalKey := newDPoPOID4VCITestKey(t)
	attackerKey := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, originalKey)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	wrongKeyProof := attackerKey.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})

	request, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	request.Header.Set(dpop.HeaderName, wrongKeyProof)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (proof key does not match bound key)", response.StatusCode)
	}
}

func TestNonceEndpointRejectsReplayedProof(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	sharedProof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{
		"jti": "fixed-nonce-endpoint-jti",
		"ath": computeTestATH(accessToken),
	})

	makeRequest := func() *http.Response {
		request, err := http.NewRequest(http.MethodPost, nonceURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
		request.Header.Set(dpop.HeaderName, sharedProof)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	first := makeRequest()
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.StatusCode)
	}

	second := makeRequest()
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed proof status = %d, want 401", second.StatusCode)
	}
}

func TestNonceEndpointUnboundTokenStaysUnchangedWithoutProof(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	tokenResp, err := http.PostForm(server.server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])

	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oid4vci/nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unbound token unaffected by DPoP)", response.StatusCode)
	}
}

func TestCredentialEndpointEnforcesDPoPBinding(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)
	accessToken, walletSubject := issueDPoPBoundCredentialGrant(t, server, key)

	// Fetch a fresh c_nonce: the pre-authorized token response already
	// carried one from issuance; re-derive it from a DPoP-authorized nonce
	// call so the credential request's proof-of-possession JWT can bind it.
	nonceURL := server.server.URL + "/oid4vci/nonce"
	nonceProof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})
	nonceRequest, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	nonceRequest.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	nonceRequest.Header.Set(dpop.HeaderName, nonceProof)
	nonceResponse, err := http.DefaultClient.Do(nonceRequest)
	if err != nil {
		t.Fatal(err)
	}
	noncePayload := decodeJSONMap(t, nonceResponse)
	cNonce := asString(t, noncePayload["c_nonce"])

	walletProofJWT := createWalletProofJWT(t, cNonce, walletSubject, server.plugin.issuerID())
	credentialURL := server.server.URL + "/oid4vci/credential"

	// Without a DPoP proof at all: the bound token must be rejected outright.
	bearerOnlyResp := postJSONWithHeaders(
		t,
		credentialURL,
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": walletProofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, bearerOnlyResp, http.StatusUnauthorized)

	// With a valid, matching DPoP proof: success.
	credentialProof := key.proof(t, http.MethodPost, credentialURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})
	credentialResp := postJSONWithHeaders(
		t,
		credentialURL,
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": walletProofJWT},
			},
		},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: credentialProof,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
}

func TestDeferredCredentialEndpointEnforcesDPoPBinding(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	key := newDPoPOID4VCITestKey(t)

	preAuthCode, walletSubject := requestDeferredOffer(t, server)
	tokenURL := server.server.URL + "/oid4vci/token"
	tokenProof := key.proof(t, http.MethodPost, tokenURL, nil)
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, tokenBody := postTokenRequestForm(t, server.server.URL, form, tokenProof)
	if status != http.StatusOK {
		t.Fatalf("token issuance status = %d, body = %#v", status, tokenBody)
	}
	accessToken := asString(t, tokenBody["access_token"])
	cNonce := asString(t, tokenBody["c_nonce"])
	walletProofJWT := createWalletProofJWT(t, cNonce, walletSubject, server.plugin.issuerID())

	credentialURL := server.server.URL + "/oid4vci/credential"
	credentialProof := key.proof(t, http.MethodPost, credentialURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})
	credentialResp := postJSONWithHeaders(
		t,
		credentialURL,
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": walletProofJWT},
			},
		},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: credentialProof,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	transactionID := asString(t, credentialPayload["transaction_id"])
	if transactionID == "" {
		t.Fatalf("expected deferred transaction_id")
	}

	time.Sleep(deferredReadyDelay + 200*time.Millisecond)
	deferredURL := server.server.URL + "/oid4vci/deferred_credential"

	// Bound token presented as bearer, no proof: rejected outright.
	bearerOnlyResp := postJSONWithHeaders(
		t,
		deferredURL,
		map[string]interface{}{"transaction_id": transactionID},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, bearerOnlyResp, http.StatusUnauthorized)

	// Bound token with a valid, matching DPoP proof: success.
	deferredProof := key.proof(t, http.MethodPost, deferredURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})
	deferredResp := postJSONWithHeaders(
		t,
		deferredURL,
		map[string]interface{}{"transaction_id": transactionID},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: deferredProof,
		},
	)
	assertStatus(t, deferredResp, http.StatusOK)
	deferredPayload := decodeJSONMap(t, deferredResp)
	if asString(t, deferredPayload["credential"]) == "" {
		t.Fatalf("expected deferred credential")
	}
}

// --- Phase 5: DPoP-Nonce (RFC 9449 Section 8) ---
//
// dpopASNonceIssuer/dpopRSNonceIssuer are nil by default (nonces are
// opt-in per PluginConfig, off unless SHOWCASE_DPOP_NONCE_REQUIRED /
// SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED are set), so these tests turn them
// on directly on the test server's plugin, mirroring how
// TestTokenEndpointDPoPReplayStoreOutageFailsClosedOID4VCI substitutes
// server.plugin.dpopReplay. The two issuers are exercised separately to
// prove the AS-role and RS-role nonce spaces are independent (Section
// 8.2) even though both live on this one plugin instance.

func TestTokenEndpointNonceDisabledByDefaultOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	if server.plugin.dpopASNonceIssuer != nil || server.plugin.dpopRSNonceIssuer != nil {
		t.Fatal("nonce issuers must be nil by default -- nonces are opt-in hardening")
	}
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body := postTokenRequestForm(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v, want 200 (nonces disabled by default)", status, body)
	}
}

func TestTokenEndpointChallengesMissingNonceOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopASNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body, headers := postTokenRequestFormCapturingHeaders(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	if headers.Get(dpop.NonceHeaderName) == "" {
		t.Fatal("expected a DPoP-Nonce response header on the challenge")
	}
}

func TestTokenEndpointRetryWithChallengedNonceSucceedsOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopASNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"

	firstCode, _ := requestPreAuthorizedOffer(t, server)
	firstProof := key.proof(t, http.MethodPost, tokenURL, nil)
	firstForm := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {firstCode},
	}
	status, body, headers := postTokenRequestFormCapturingHeaders(t, server.server.URL, firstForm, firstProof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("first request status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	nonce := headers.Get(dpop.NonceHeaderName)
	if nonce == "" {
		t.Fatal("expected a DPoP-Nonce response header")
	}

	retryCode, _ := requestPreAuthorizedOffer(t, server)
	retryProof := key.proof(t, http.MethodPost, tokenURL, jwt.MapClaims{"nonce": nonce})
	retryForm := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {retryCode},
	}
	retryStatus, retryBody := postTokenRequestForm(t, server.server.URL, retryForm, retryProof)
	if retryStatus != http.StatusOK {
		t.Fatalf("retry status = %d, body = %#v", retryStatus, retryBody)
	}
	if retryBody["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", retryBody["token_type"])
	}
}

func TestTokenEndpointForeignNonceRejectedAsFreshChallengeOID4VCI(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopASNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	preAuthCode, _ := requestPreAuthorizedOffer(t, server)
	key := newDPoPOID4VCITestKey(t)
	tokenURL := server.server.URL + "/oid4vci/token"
	proof := key.proof(t, http.MethodPost, tokenURL, jwt.MapClaims{"nonce": "a-nonce-this-issuer-never-issued"})

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	}
	status, body, headers := postTokenRequestFormCapturingHeaders(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	if headers.Get(dpop.NonceHeaderName) == "" {
		t.Fatal("expected a fresh DPoP-Nonce even for a foreign nonce")
	}
}

func TestNonceEndpointChallengesMissingResourceNonce(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopRSNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	proof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})

	request, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	request.Header.Set(dpop.HeaderName, proof)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
	body := decodeJSONMap(t, response)
	if body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("error = %v, want %s", body["error"], dpop.ErrorUseDPoPNonce)
	}
	if response.Header.Get(dpop.NonceHeaderName) == "" {
		t.Fatal("expected a DPoP-Nonce response header on the challenge")
	}
	wwwAuthenticate := response.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuthenticate, dpop.ErrorUseDPoPNonce) {
		t.Fatalf("WWW-Authenticate = %q, want it to carry error=%q", wwwAuthenticate, dpop.ErrorUseDPoPNonce)
	}
}

func TestNonceEndpointRetryWithChallengedResourceNonceSucceeds(t *testing.T) {
	server := newDPoPOID4VCITestServer(t)
	server.plugin.dpopRSNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	key := newDPoPOID4VCITestKey(t)
	accessToken, _ := issueDPoPBoundCredentialGrant(t, server, key)
	nonceURL := server.server.URL + "/oid4vci/nonce"
	firstProof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{"ath": computeTestATH(accessToken)})

	firstRequest, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	firstRequest.Header.Set(dpop.HeaderName, firstProof)
	firstResponse, err := http.DefaultClient.Do(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer firstResponse.Body.Close()
	if firstResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first request status = %d, want 401", firstResponse.StatusCode)
	}
	serverNonce := firstResponse.Header.Get(dpop.NonceHeaderName)
	if serverNonce == "" {
		t.Fatal("expected a DPoP-Nonce response header")
	}

	retryProof := key.proof(t, http.MethodPost, nonceURL, jwt.MapClaims{
		"ath":   computeTestATH(accessToken),
		"nonce": serverNonce,
	})
	retryRequest, err := http.NewRequest(http.MethodPost, nonceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	retryRequest.Header.Set("Authorization", dpop.HeaderName+" "+accessToken)
	retryRequest.Header.Set(dpop.HeaderName, retryProof)
	retryResponse, err := http.DefaultClient.Do(retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer retryResponse.Body.Close()
	if retryResponse.StatusCode != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", retryResponse.StatusCode)
	}
}

func requestDeferredOffer(t *testing.T, server *dpopOID4VCITestServer) (preAuthCode, walletSubject string) {
	t.Helper()
	offerResp := postJSON(t, server.server.URL+"/oid4vci/offers/pre-authorized/deferred", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	return asString(t, offerPayload["pre_authorized_code"]), asString(t, offerPayload["wallet_subject"])
}
