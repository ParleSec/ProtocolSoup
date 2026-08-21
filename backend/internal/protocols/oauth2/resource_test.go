package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/golang-jwt/jwt/v5"
)

// computeTestATH mirrors the unexported dpop.computeATH (RFC 9449 Section
// 4.2): base64url(SHA-256(access token)). Resource-endpoint proofs must
// carry this so ValidateProof's mandatory ath check succeeds.
func computeTestATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func getResourceRequest(t *testing.T, server *oauthAssertionTestServer, authorizationHeader, dpopProof string) (int, map[string]interface{}, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, server.server.URL+"/oauth2/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorizationHeader != "" {
		request.Header.Set("Authorization", authorizationHeader)
	}
	if dpopProof != "" {
		request.Header.Set(dpop.HeaderName, dpopProof)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body, response.Header
}

// TestProtectedResourceAcceptsBearerForUnboundToken covers the baseline RS
// leg: a plain access token presented as Bearer succeeds exactly as it did
// before DPoP existed.
func TestProtectedResourceAcceptsBearerForUnboundToken(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "bearer-resource-client", "bearer-resource-secret")

	tokenRequest, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"bearer-resource-client"},
		"scope":      {"api:read"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.SetBasicAuth("bearer-resource-client", "bearer-resource-secret")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("token response missing access_token: %#v", tokenBody)
	}

	status, body, _ := getResourceRequest(t, server, "Bearer "+accessToken, "")
	if status != http.StatusOK {
		t.Fatalf("resource status = %d, body = %#v", status, body)
	}
	if body["dpop_bound"] != false {
		t.Fatalf("dpop_bound = %v, want false", body["dpop_bound"])
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
}

// TestProtectedResourceAcceptsDPoPProofWithAthForBoundToken covers RFC 9449
// Section 7: a DPoP-bound token is presented as `Authorization: DPoP
// <token>` alongside a fresh proof over this endpoint's own URL, carrying
// ath for that exact access token.
func TestProtectedResourceAcceptsDPoPProofWithAthForBoundToken(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "dpop-resource-client", "dpop-resource-secret")
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	tokenProof := key.proof(t, http.MethodPost, tokenURL, nil)

	tokenRequest, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"dpop-resource-client"},
		"scope":      {"api:read"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set(dpop.HeaderName, tokenProof)
	tokenRequest.SetBasicAuth("dpop-resource-client", "dpop-resource-secret")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("token response missing access_token: %#v", tokenBody)
	}
	if tokenBody["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", tokenBody["token_type"])
	}

	resourceURL := server.server.URL + "/oauth2/resource"
	resourceProof := key.proof(t, http.MethodGet, resourceURL, map[string]interface{}{
		"ath": computeTestATH(accessToken),
	})

	status, body, _ := getResourceRequest(t, server, "DPoP "+accessToken, resourceProof)
	if status != http.StatusOK {
		t.Fatalf("resource status = %d, body = %#v", status, body)
	}
	if body["dpop_bound"] != true {
		t.Fatalf("dpop_bound = %v, want true", body["dpop_bound"])
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
}

// TestProtectedResourceRejectsBoundTokenPresentedAsBearer guards RFC 9449
// Section 7.1's "never silently downgrade" rule.
func TestProtectedResourceRejectsBoundTokenPresentedAsBearer(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "downgrade-client", "downgrade-secret")
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	tokenProof := key.proof(t, http.MethodPost, tokenURL, nil)

	tokenRequest, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"downgrade-client"},
		"scope":      {"api:read"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set(dpop.HeaderName, tokenProof)
	tokenRequest.SetBasicAuth("downgrade-client", "downgrade-secret")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)

	status, body, headers := getResourceRequest(t, server, "Bearer "+accessToken, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("resource status = %d, body = %#v, want 401", status, body)
	}
	if !strings.HasPrefix(headers.Get("WWW-Authenticate"), dpop.HeaderName) {
		t.Fatalf("WWW-Authenticate = %q, want it to start with %q", headers.Get("WWW-Authenticate"), dpop.HeaderName)
	}
}

// TestProtectedResourceRejectsWrongKeyProof guards the cnf.jkt binding
// check: a proof from a different key than the one the token was bound to
// must not be accepted just because it is otherwise well-formed.
func TestProtectedResourceRejectsWrongKeyProof(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "wrongkey-client", "wrongkey-secret")
	boundKey := newDPoPTestKey(t)
	otherKey := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	tokenProof := boundKey.proof(t, http.MethodPost, tokenURL, nil)

	tokenRequest, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"wrongkey-client"},
		"scope":      {"api:read"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set(dpop.HeaderName, tokenProof)
	tokenRequest.SetBasicAuth("wrongkey-client", "wrongkey-secret")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)

	resourceURL := server.server.URL + "/oauth2/resource"
	wrongProof := otherKey.proof(t, http.MethodGet, resourceURL, map[string]interface{}{
		"ath": computeTestATH(accessToken),
	})

	status, body, _ := getResourceRequest(t, server, "DPoP "+accessToken, wrongProof)
	if status != http.StatusUnauthorized {
		t.Fatalf("resource status = %d, body = %#v, want 401", status, body)
	}
}

// TestProtectedResourceRejectsReplayedProof guards RFC 9449 Section 11.1 at
// the resource-server leg specifically (the token-endpoint replay tests
// elsewhere cover the AS leg).
func TestProtectedResourceRejectsReplayedProof(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "replay-resource-client", "replay-resource-secret")
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	tokenProof := key.proof(t, http.MethodPost, tokenURL, nil)

	tokenRequest, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"replay-resource-client"},
		"scope":      {"api:read"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set(dpop.HeaderName, tokenProof)
	tokenRequest.SetBasicAuth("replay-resource-client", "replay-resource-secret")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)

	resourceURL := server.server.URL + "/oauth2/resource"
	resourceProof := key.proof(t, http.MethodGet, resourceURL, map[string]interface{}{
		"ath": computeTestATH(accessToken),
	})

	firstStatus, firstBody, _ := getResourceRequest(t, server, "DPoP "+accessToken, resourceProof)
	if firstStatus != http.StatusOK {
		t.Fatalf("first resource status = %d, body = %#v", firstStatus, firstBody)
	}

	secondStatus, secondBody, _ := getResourceRequest(t, server, "DPoP "+accessToken, resourceProof)
	if secondStatus != http.StatusUnauthorized {
		t.Fatalf("replayed resource status = %d, body = %#v, want 401", secondStatus, secondBody)
	}
}

// TestProtectedResourceRejectsMissingAuthorization covers the bare
// unauthenticated request path.
func TestProtectedResourceRejectsMissingAuthorization(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	status, body, headers := getResourceRequest(t, server, "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("resource status = %d, body = %#v, want 401", status, body)
	}
	if headers.Get("WWW-Authenticate") == "" {
		t.Fatal("expected a WWW-Authenticate challenge header")
	}
}

func TestSSFClientCredentialsIssuesShortLivedResourceAudience(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	client, exists := server.idp.GetClient(mockidp.SSFStreamClientID)
	if !exists || client == nil || client.Secret == "" {
		t.Fatal("seeded ssf-stream-client is required for Stream Management tokens")
	}

	tokenRequest, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/token", strings.NewReader(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {mockidp.SSFStreamClientID},
		"client_secret": {client.Secret},
		"scope":         {"ssf.manage"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := http.DefaultClient.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		t.Fatal(err)
	}
	if tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d body %#v", tokenResponse.StatusCode, tokenBody)
	}
	if expires, _ := tokenBody["expires_in"].(float64); expires != 900 {
		t.Fatalf("expires_in = %v, want 900 [CAEPINTEROP short-lived]", tokenBody["expires_in"])
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatal("missing access_token")
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	if got, _ := claims["aud"].(string); got != server.plugin.baseURL {
		t.Fatalf("aud %v want %s", claims["aud"], server.plugin.baseURL)
	}
	if claims["scope"] != "ssf.manage" {
		t.Fatalf("scope %v", claims["scope"])
	}
}
