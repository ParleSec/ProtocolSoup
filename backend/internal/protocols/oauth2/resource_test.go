package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
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

// TestProtectedResourceRejectsWrongKeyProof guards the second half of RFC
// 9449 Section 4.3 check 12, "confirm that the public key to which the
// access token is bound matches the public key from the DPoP proof": a
// proof from a different key than the one the token was bound to must not
// be accepted just because it is otherwise well-formed.
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

	status, body, headers := getResourceRequest(t, server, "DPoP "+accessToken, wrongProof)
	if status != http.StatusUnauthorized {
		t.Fatalf("resource status = %d, body = %#v, want 401", status, body)
	}
	// The proof's ath, htm, htu, iat and signature are all valid, so only
	// the key comparison can have refused it.
	if body["error"] != "invalid_token" || body["error_description"] != "DPoP proof key does not match the token's bound key" {
		t.Fatalf("body = %#v, want invalid_token for the key binding", body)
	}
	if challenge := headers.Get("WWW-Authenticate"); !strings.HasPrefix(challenge, dpop.HeaderName+" ") {
		t.Fatalf("WWW-Authenticate = %q, want a DPoP challenge", challenge)
	}

	// The same token with a proof from the key it is bound to is accepted.
	boundProof := boundKey.proof(t, http.MethodGet, resourceURL, map[string]interface{}{
		"ath": computeTestATH(accessToken),
	})
	if status, body, _ := getResourceRequest(t, server, "DPoP "+accessToken, boundProof); status != http.StatusOK {
		t.Fatalf("resource status with the bound key = %d, body = %#v, want 200", status, body)
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

// clientCredentialsToken requests a client_credentials access token over
// HTTP and returns it with the token response.
func clientCredentialsToken(t *testing.T, server *oauthAssertionTestServer, clientID, secret, scope string) (string, map[string]interface{}) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, secret)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, body = %#v", response.StatusCode, body)
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("token response missing access_token: %#v", body)
	}
	return accessToken, body
}

// TestClientCredentialsTokenNamesTheResourceAndTheClient covers RFC 7519
// Section 4.1.3, "Each principal intended to process the JWT MUST identify
// itself with a value in the audience claim": the access token's aud is the
// protected resource that processes it, and the client that requested it is
// carried in client_id (RFC 8693 Section 4.3). Introspection reports the two
// separately (RFC 7662 Section 2.2).
func TestClientCredentialsTokenNamesTheResourceAndTheClient(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "audience-client", "audience-secret")
	accessToken, _ := clientCredentialsToken(t, server, "audience-client", "audience-secret", "api:read")

	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	if got, _ := claims["aud"].(string); got != server.plugin.resourceURL() {
		t.Fatalf("aud = %v, want the protected resource %s", claims["aud"], server.plugin.resourceURL())
	}
	if got, _ := claims["client_id"].(string); got != "audience-client" {
		t.Fatalf("client_id = %v, want audience-client", claims["client_id"])
	}

	introspectRequest, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {accessToken}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	introspectRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectRequest.SetBasicAuth("audience-client", "audience-secret")
	introspectResponse, err := http.DefaultClient.Do(introspectRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer introspectResponse.Body.Close()
	var introspection map[string]interface{}
	if err := json.NewDecoder(introspectResponse.Body).Decode(&introspection); err != nil {
		t.Fatal(err)
	}
	if introspection["active"] != true {
		t.Fatalf("active = %v, want true: %#v", introspection["active"], introspection)
	}
	if introspection["client_id"] != "audience-client" {
		t.Fatalf("introspection client_id = %v, want audience-client", introspection["client_id"])
	}
	if introspection["aud"] != server.plugin.resourceURL() {
		t.Fatalf("introspection aud = %v, want %s", introspection["aud"], server.plugin.resourceURL())
	}
}

// TestProtectedResourceRejectsTokenForAnotherAudience covers the second
// sentence of RFC 7519 Section 4.1.3: "If the principal processing the claim
// does not identify itself with a value in the "aud" claim when this claim
// is present, then the JWT MUST be rejected." An SSF-scoped token is issued
// for the SSF resource, so this resource refuses it.
func TestProtectedResourceRejectsTokenForAnotherAudience(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	client, ok := server.idp.GetClient(mockidp.SSFStreamClientID)
	if !ok || client == nil {
		t.Fatal("ssf client missing")
	}
	accessToken, _ := clientCredentialsToken(t, server, mockidp.SSFStreamClientID, client.Secret, "ssf.manage")

	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if aud, _ := parsed.Claims.(jwt.MapClaims)["aud"].(string); aud == server.plugin.resourceURL() {
		t.Fatalf("the SSF token's aud %q already names /oauth2/resource, so it cannot show a refusal", aud)
	}

	status, body, header := getResourceRequest(t, server, "Bearer "+accessToken, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("resource status = %d, want 401; body = %#v", status, body)
	}
	if body["error"] != "invalid_token" {
		t.Fatalf("error = %v, want invalid_token", body["error"])
	}
	if got := header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

// accessTokenParts decodes a JWT access token's header and claims without
// verifying it, for assertions on what the token endpoint issued.
func accessTokenParts(t *testing.T, accessToken string) (map[string]interface{}, jwt.MapClaims) {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Header, parsed.Claims.(jwt.MapClaims)
}

// introspect posts token to /oauth2/introspect authenticated as clientID.
func introspect(t *testing.T, server *oauthAssertionTestServer, clientID, secret, token string) (int, map[string]interface{}) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		request.SetBasicAuth(clientID, secret)
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
	return response.StatusCode, body
}

// TestAuthorizationCodeAccessTokenFollowsRFC9068 covers RFC 9068 Section 2:
// the "typ" header is at+jwt (Section 2.1), and iss, aud, sub and client_id
// are present (Section 2.2), with iss the issuer this authorization server's
// metadata publishes and aud the default resource indicator (Section 3). The
// resource the token names accepts it.
func TestAuthorizationCodeAccessTokenFollowsRFC9068(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	header, claims := accessTokenParts(t, accessToken)
	if header["typ"] != "at+jwt" {
		t.Errorf("typ = %v, want at+jwt", header["typ"])
	}
	if claims["iss"] != server.plugin.issuer() {
		t.Errorf("iss = %v, want the authorization server issuer %s", claims["iss"], server.plugin.issuer())
	}
	if claims["aud"] != server.plugin.resourceURL() {
		t.Errorf("aud = %v, want the protected resource %s", claims["aud"], server.plugin.resourceURL())
	}
	if claims["client_id"] != "public-app" {
		t.Errorf("client_id = %v, want public-app", claims["client_id"])
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", claims["sub"])
	}
	for _, required := range []string{"exp", "iat", "jti"} {
		if _, present := claims[required]; !present {
			t.Errorf("%s is REQUIRED by RFC 9068 Section 2.2 and is missing", required)
		}
	}

	if status, body, _ := getResourceRequest(t, server, "Bearer "+accessToken, ""); status != http.StatusOK {
		t.Fatalf("resource status = %d, want 200; body = %#v", status, body)
	}
}

// TestProtectedResourceRejectsJWTsThatAreNotItsAccessTokens covers the RFC
// 9068 Section 4 checks one at a time. Each token is signed by the server's
// own key and unexpired, so only the named check can refuse it. RFC 6750
// Section 3.1: the error code is invalid_token.
func TestProtectedResourceRejectsJWTsThatAreNotItsAccessTokens(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	jwtService := server.idp.JWTService()
	base := internalcrypto.AccessToken{
		Issuer:   server.plugin.issuer(),
		Subject:  "alice",
		Audience: server.plugin.resourceURL(),
		ClientID: "public-app",
		Scope:    "profile",
		Lifetime: time.Hour,
	}

	refreshToken, err := jwtService.CreateRefreshToken("alice", "public-app", "profile", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := jwtService.CreateIDToken("alice", "public-app", "", time.Now(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	untyped, err := jwtService.CreateUnprofiledAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer := base
	otherIssuer.Issuer = server.plugin.baseURL
	fromOtherIssuer, err := jwtService.CreateAccessToken(otherIssuer)
	if err != nil {
		t.Fatal(err)
	}
	otherResource := base
	otherResource.Audience = server.plugin.baseURL + "/oidc/userinfo"
	forOtherResource, err := jwtService.CreateAccessToken(otherResource)
	if err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]string{
		"a refresh token has no at+jwt typ and no aud":     refreshToken,
		"an ID Token has no at+jwt typ":                    idToken,
		"an access token typed JWT":                        untyped,
		"an access token from another issuer":              fromOtherIssuer,
		"an access token whose aud names another resource": forOtherResource,
	} {
		t.Run(name, func(t *testing.T) {
			status, body, header := getResourceRequest(t, server, "Bearer "+token, "")
			if status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body = %#v", status, body)
			}
			if body["error"] != "invalid_token" {
				t.Fatalf("error = %v, want invalid_token", body["error"])
			}
			if got := header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
		})
	}

	accepted, err := jwtService.CreateAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}
	if status, body, _ := getResourceRequest(t, server, "Bearer "+accepted, ""); status != http.StatusOK {
		t.Fatalf("a token that names this resource: status = %d, want 200; body = %#v", status, body)
	}
}

// TestTokenEndpointResourceParameter covers RFC 8707 Section 2 and RFC 9068
// Section 3: a "resource" value that names the resource the scope belongs to
// becomes "aud"; a value that is not an absolute URI, carries a fragment,
// names an unknown resource or does not fit the scope is refused with
// invalid_target.
func TestTokenEndpointResourceParameter(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "resource-client", "resource-secret")
	request := func(resources ...string) (int, map[string]interface{}) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"resource-client"},
			"client_secret": {"resource-secret"},
			"scope":         {"api:read"},
		}
		for _, resource := range resources {
			form.Add("resource", resource)
		}
		return postTokenRequest(t, server.server.URL, form, "")
	}

	status, body := request(server.plugin.resourceURL())
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	if _, claims := accessTokenParts(t, accessToken); claims["aud"] != server.plugin.resourceURL() {
		t.Fatalf("aud = %v, want the resource parameter %s", claims["aud"], server.plugin.resourceURL())
	}

	for name, resources := range map[string][]string{
		"an unknown resource":                {"https://rs.example/api"},
		"a relative reference":               {"oauth2/resource"},
		"a URI with a fragment":              {server.plugin.resourceURL() + "#section"},
		"a resource the scope has no use at": {server.plugin.ssfResourceAudience()},
		"two resources":                      {server.plugin.resourceURL(), server.plugin.ssfResourceAudience()},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := request(resources...)
			if status != http.StatusBadRequest || body["error"] != "invalid_target" {
				t.Fatalf("status = %d, error = %v; want 400 invalid_target; body = %#v", status, body["error"], body)
			}
		})
	}
}

// TestTokenEndpointRejectsScopesOfDifferentResources covers RFC 9068 Section
// 3: "If the values in the "scope" parameter refer to different default
// resource indicator values, the authorization server SHOULD reject the
// request with "invalid_scope"".
func TestTokenEndpointRejectsScopesOfDifferentResources(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.idp.RegisterClient(&models.Client{
		ID:         "two-resource-client",
		Secret:     "two-resource-secret",
		Name:       "Client Registered For Two Resources",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"api:read", "ssf.read"},
	})
	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"two-resource-client"},
		"client_secret": {"two-resource-secret"},
		"scope":         {"api:read ssf.read"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("status = %d, error = %v; want 400 invalid_scope; body = %#v", status, body["error"], body)
	}
}

// TestIntrospectionAnswersOnlyTheTokensParties covers RFC 7662 Section 4: "If
// the token can be used only at certain resource servers, the authorization
// server MUST determine whether or not the token can be used at the resource
// server making the introspection call." The client a token was issued to
// and a resource server its aud names are told it is active. Section 2.2:
// any other authorized caller gets "active" false and nothing else.
func TestIntrospectionAnswersOnlyTheTokensParties(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	registerDPoPClientCredentialsClient(t, server, "other-client", "other-secret")
	ssfClient, _ := server.idp.GetClient(mockidp.SSFStreamClientID)
	transmitter, ok := server.idp.GetClient(mockidp.SSFTransmitterClientID)
	if ssfClient == nil || !ok || transmitter == nil {
		t.Fatal("the seeded SSF client and SSF Transmitter resource server are required")
	}

	apiToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	ssfToken, _ := clientCredentialsToken(t, server, mockidp.SSFStreamClientID, ssfClient.Secret, "ssf.read")
	refreshToken, err := server.idp.JWTService().CreateRefreshToken("alice", "owner-client", "api:read", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := server.idp.JWTService().CreateIDToken("alice", "owner-client", "", time.Now(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, call := range map[string]struct {
		clientID, secret, token string
		active                  bool
	}{
		"the client the access token was issued to":  {"owner-client", "owner-secret", apiToken, true},
		"the client the refresh token was issued to": {"owner-client", "owner-secret", refreshToken, true},
		"another client":                               {"other-client", "other-secret", apiToken, false},
		"the resource server the aud names":            {mockidp.SSFTransmitterClientID, transmitter.Secret, ssfToken, true},
		"a resource server the aud does not name":      {mockidp.SSFTransmitterClientID, transmitter.Secret, apiToken, false},
		"an ID Token, which is not an OAuth 2.0 token": {"owner-client", "owner-secret", idToken, false},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := introspect(t, server, call.clientID, call.secret, call.token)
			if status != http.StatusOK {
				t.Fatalf("status = %d, body = %#v", status, body)
			}
			if body["active"] != call.active {
				t.Fatalf("active = %v, want %v; body = %#v", body["active"], call.active, body)
			}
			if !call.active && len(body) != 1 {
				t.Fatalf("an inactive response carried more than \"active\": %#v", body)
			}
		})
	}

	// The token under introspection is not a credential for introspecting
	// itself (RFC 7662 Section 2.1).
	request, err := http.NewRequest(http.MethodPost, server.server.URL+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {apiToken}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer "+apiToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("a token presented as its own credential: body = %#v, want invalid_client", body)
	}
}

// postWithClientAuth posts form to an OAuth 2.0 endpoint. configure sets the
// request's credentials and Looking Glass session, when there are any.
func postWithClientAuth(t *testing.T, endpoint string, form url.Values, configure func(*http.Request)) (int, map[string]interface{}, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if configure != nil {
		configure(request)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("response body %q: %v", raw, err)
		}
	}
	return response.StatusCode, body, response.Header
}

func basicAuth(clientID, secret string) func(*http.Request) {
	return func(request *http.Request) { request.SetBasicAuth(clientID, secret) }
}

func authorization(value string) func(*http.Request) {
	return func(request *http.Request) { request.Header.Set("Authorization", value) }
}

// publicAppAccessToken redeems an authorization code as the seeded public
// client and returns the access token it was issued.
func publicAppAccessToken(t *testing.T, server *oauthAssertionTestServer) string {
	t.Helper()
	accessToken, _ := publicAppTokens(t, server)
	return accessToken
}

// publicAppTokens redeems an authorization code as the seeded public client
// and returns the access token and refresh token it was issued.
func publicAppTokens(t *testing.T, server *oauthAssertionTestServer) (accessToken, refreshToken string) {
	t.Helper()
	code := createDPoPTestAuthCode(t, server)
	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("token status = %d, body = %#v", status, body)
	}
	accessToken, _ = body["access_token"].(string)
	refreshToken, _ = body["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("no access_token or refresh_token in %#v", body)
	}
	return accessToken, refreshToken
}

// TestIntrospectionRequiresAnAuthenticatedConfidentialCaller covers RFC 7662
// Section 2.1: "To prevent token scanning attacks, the endpoint MUST also
// require some form of authorization to access this endpoint, such as client
// authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0
// access token". A public client's client_id authorizes nothing (RFC 6749
// Section 2.3: "the authorization server MUST NOT rely on public client
// authentication for the purpose of identifying the client"), so the token a
// public client was issued cannot be read by anyone who names that client.
//
// It also covers the status of each refusal. RFC 7662 Section 2.3: "If the
// protected resource uses OAuth 2.0 client credentials to authenticate to
// the introspection endpoint and its credentials are invalid, the
// authorization server responds with an HTTP 401 (Unauthorized) as described
// in Section 5.2 of OAuth 2.0 [RFC6749]." RFC 6749 Section 5.2: a client
// that "attempted to authenticate via the "Authorization" request header
// field" gets 401 with "the "WWW-Authenticate" response header field
// matching the authentication scheme used by the client."
func TestIntrospectionRequiresAnAuthenticatedConfidentialCaller(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	publicToken := publicAppAccessToken(t, server)
	endpoint := server.server.URL + "/oauth2/introspect"

	const basicChallenge = `Basic realm="oauth2"`
	for name, call := range map[string]struct {
		token      string
		form       url.Values
		query      string
		configure  func(*http.Request)
		status     int
		errorCode  string
		challenges []string
	}{
		"a public client named in the body": {
			token: publicToken, form: url.Values{"client_id": {"public-app"}},
			status: http.StatusBadRequest, errorCode: "invalid_client",
		},
		"a public client over HTTP Basic with an empty password": {
			token: publicToken, configure: basicAuth("public-app", ""),
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"a public client with a made-up client_secret": {
			token: publicToken, form: url.Values{"client_id": {"public-app"}, "client_secret": {"anything"}},
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"no credentials at all": {
			token:  ownerToken,
			status: http.StatusBadRequest, errorCode: "invalid_client",
		},
		"a confidential client named without its secret": {
			token: ownerToken, form: url.Values{"client_id": {"owner-client"}},
			status: http.StatusBadRequest, errorCode: "invalid_client",
		},
		"an unknown client over HTTP Basic": {
			token: ownerToken, configure: basicAuth("no-such-client", "owner-secret"),
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"a wrong secret over HTTP Basic": {
			token: ownerToken, configure: basicAuth("owner-client", "wrong-secret"),
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"a prefix of the secret over HTTP Basic": {
			token: ownerToken, configure: basicAuth("owner-client", "owner-secre"),
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"a wrong secret in the body": {
			token: ownerToken, form: url.Values{"client_id": {"owner-client"}, "client_secret": {"wrong-secret"}},
			status: http.StatusUnauthorized, errorCode: "invalid_client", challenges: []string{basicChallenge},
		},
		"the right secret in the request URI": {
			token: ownerToken, query: "?client_id=owner-client&client_secret=owner-secret",
			status: http.StatusBadRequest, errorCode: "invalid_client",
		},
		"HTTP Basic and a body secret together": {
			token: ownerToken, form: url.Values{"client_secret": {"owner-secret"}}, configure: basicAuth("owner-client", "owner-secret"),
			status: http.StatusBadRequest, errorCode: "invalid_request",
		},
		// RFC 7662 Section 2.3 sends a bearer token that is "invalid for
		// this request" to RFC 6750 Section 3, hence the error attribute.
		"the token as its own Bearer credential": {
			token: ownerToken, configure: authorization("Bearer " + ownerToken),
			status: http.StatusUnauthorized, errorCode: "invalid_client",
			challenges: []string{basicChallenge, `Bearer realm="oauth2", error="invalid_token"`},
		},
		"another authentication scheme": {
			token: ownerToken, configure: authorization("DPoP " + ownerToken),
			status: http.StatusUnauthorized, errorCode: "invalid_client",
			challenges: []string{basicChallenge, "DPoP"},
		},
		"a scheme that is not an RFC 9110 token": {
			token: ownerToken, configure: authorization(`Sche"me, x`),
			status: http.StatusUnauthorized, errorCode: "invalid_client",
			challenges: []string{basicChallenge},
		},
	} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"token": {call.token}}
			for key, values := range call.form {
				form[key] = values
			}
			status, body, header := postWithClientAuth(t, endpoint+call.query, form, call.configure)
			if status != call.status {
				t.Fatalf("status = %d, want %d; body = %#v", status, call.status, body)
			}
			if body["error"] != call.errorCode {
				t.Fatalf("error = %v, want %s; body = %#v", body["error"], call.errorCode, body)
			}
			if _, leaked := body["active"]; leaked {
				t.Fatalf("a refused caller was given an introspection response: %#v", body)
			}
			if got := header.Values("WWW-Authenticate"); !reflect.DeepEqual(got, call.challenges) {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, call.challenges)
			}
		})
	}

	for name, method := range map[string]struct {
		form      url.Values
		configure func(*http.Request)
	}{
		"client_secret_basic": {configure: basicAuth("owner-client", "owner-secret")},
		"client_secret_post":  {form: url.Values{"client_id": {"owner-client"}, "client_secret": {"owner-secret"}}},
	} {
		t.Run("the token's confidential client with "+name, func(t *testing.T) {
			form := url.Values{"token": {ownerToken}}
			for key, values := range method.form {
				form[key] = values
			}
			status, body, header := postWithClientAuth(t, endpoint, form, method.configure)
			if status != http.StatusOK || body["active"] != true {
				t.Fatalf("status = %d, body = %#v, want 200 and active true", status, body)
			}
			if got := header.Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q on a successful response", got)
			}
		})
	}
}

// TestIntrospectionRefusalsReachLookingGlass checks that each refusal at the
// introspection endpoint is an event with its reason and the specification
// section it applies.
func TestIntrospectionRefusalsReachLookingGlass(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	endpoint := server.server.URL + "/oauth2/introspect"

	for name, call := range map[string]struct {
		form       url.Values
		configure  func(*http.Request)
		title      string
		reason     string
		references []string
	}{
		"public client": {
			form:  url.Values{"client_id": {"public-app"}},
			title: "Introspection Refused: Public Client", reason: "public_client",
			references: []string{"RFC 7662 Section 2.1", "RFC 6749 Section 2.3"},
		},
		"no client authentication": {
			title: "Introspection Refused: No Client Authentication", reason: "no_client_authentication",
			references: []string{"RFC 7662 Section 2.1"},
		},
		"unknown client": {
			configure: basicAuth("no-such-client", "x"),
			title:     "Introspection Refused: Unknown Client", reason: "unknown_client",
			references: []string{"RFC 7662 Section 2.1"},
		},
		"wrong secret": {
			configure: basicAuth("owner-client", "wrong-secret"),
			title:     "Introspection Refused: Client Authentication Failed", reason: "invalid_credentials",
			references: []string{"RFC 7662 Section 2.1", "RFC 7662 Section 2.3"},
		},
		"two authentication methods": {
			form: url.Values{"client_secret": {"owner-secret"}}, configure: basicAuth("owner-client", "owner-secret"),
			title:      "Introspection Refused: Two Client Authentication Methods",
			references: []string{"RFC 6749 Section 2.3"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			session, _ := createOwnedOAuthSession(t, server.engine)
			form := url.Values{"token": {ownerToken}}
			for key, values := range call.form {
				form[key] = values
			}
			postWithClientAuth(t, endpoint, form, func(request *http.Request) {
				request.Header.Set("X-Looking-Glass-Session", session.ID)
				if call.configure != nil {
					call.configure(request)
				}
			})

			stored, ok := server.engine.GetSession(session.ID)
			if !ok {
				t.Fatal("Looking Glass session not found")
			}
			for _, event := range stored.Events {
				if event.Title != call.title {
					continue
				}
				if call.reason != "" && event.Data["reason"] != call.reason {
					t.Fatalf("reason = %v, want %s", event.Data["reason"], call.reason)
				}
				var references []string
				for _, annotation := range event.Annotations {
					references = append(references, annotation.Reference)
				}
				if !reflect.DeepEqual(references, call.references) {
					t.Fatalf("references = %q, want %q", references, call.references)
				}
				return
			}
			t.Fatalf("event %q not found in %#v", call.title, stored.Events)
		})
	}
}

// TestFailedClientAuthenticationOverBasicIsChallenged covers RFC 6749 Section
// 5.2 at the revocation and token endpoints: "If the client attempted to
// authenticate via the "Authorization" request header field, the
// authorization server MUST respond with an HTTP 401 (Unauthorized) status
// code and include the "WWW-Authenticate" response header field matching the
// authentication scheme used by the client." The same failure with the
// credentials in the body is a 400. RFC 7009 Section 2.2.1: "The error
// presentation conforms to the definition in Section 5.2 of [RFC6749]."
func TestFailedClientAuthenticationOverBasicIsChallenged(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	demoApp, ok := server.idp.GetClient("demo-app")
	if !ok || demoApp == nil || demoApp.Public {
		t.Fatal("the seeded confidential demo-app client is required")
	}
	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")

	for name, endpoint := range map[string]struct {
		path string
		form url.Values
	}{
		"revocation":                      {"/oauth2/revoke", url.Values{"token": {ownerToken}}},
		"token, authorization_code":       {"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {"none"}}},
		"token, refresh_token":            {"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"none"}}},
		"token, client_credentials":       {"/oauth2/token", url.Values{"grant_type": {"client_credentials"}}},
		"token, device_code":              {"/oauth2/token", url.Values{"grant_type": {mockidp.DeviceCodeGrantType}, "device_code": {"none"}}},
		"device authorization (RFC 8628)": {"/oauth2/device/authorize", url.Values{}},
	} {
		for failure, clientID := range map[string]string{"a wrong secret": "demo-app", "an unknown client": "no-such-client"} {
			t.Run(name+", "+failure+" over HTTP Basic", func(t *testing.T) {
				status, body, header := postWithClientAuth(t, server.server.URL+endpoint.path, endpoint.form, basicAuth(clientID, "wrong-secret"))
				if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
					t.Fatalf("status = %d, body = %#v, want 401 invalid_client", status, body)
				}
				if got := header.Values("WWW-Authenticate"); !reflect.DeepEqual(got, []string{`Basic realm="oauth2"`}) {
					t.Fatalf("WWW-Authenticate = %q", got)
				}
			})
			t.Run(name+", "+failure+" in the body", func(t *testing.T) {
				form := url.Values{"client_id": {clientID}, "client_secret": {"wrong-secret"}}
				for key, values := range endpoint.form {
					form[key] = values
				}
				status, body, header := postWithClientAuth(t, server.server.URL+endpoint.path, form, nil)
				if status != http.StatusBadRequest || body["error"] != "invalid_client" {
					t.Fatalf("status = %d, body = %#v, want 400 invalid_client", status, body)
				}
				if got := header.Get("WWW-Authenticate"); got != "" {
					t.Fatalf("WWW-Authenticate = %q on a 400", got)
				}
			})
		}
	}

	// The token was not revoked by any refused request above, and the
	// client it was issued to can still revoke it.
	if server.idp.IsTokenRevoked(ownerToken) {
		t.Fatal("a refused revocation request revoked the token")
	}
	status, _, _ := postWithClientAuth(t, server.server.URL+"/oauth2/revoke", url.Values{"token": {ownerToken}}, basicAuth("owner-client", "owner-secret"))
	if status != http.StatusOK || !server.idp.IsTokenRevoked(ownerToken) {
		t.Fatalf("revocation by the token's client: status = %d, revoked = %v", status, server.idp.IsTokenRevoked(ownerToken))
	}

	// Two authentication methods in one revocation request (RFC 6749
	// Section 2.3).
	status, body, _ := postWithClientAuth(t, server.server.URL+"/oauth2/revoke",
		url.Values{"token": {ownerToken}, "client_secret": {"owner-secret"}}, basicAuth("owner-client", "owner-secret"))
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("two methods: status = %d, body = %#v, want 400 invalid_request", status, body)
	}
}

// TestRevocationIsLimitedToTheTokensClient covers RFC 7009 Section 2.1: "The
// authorization server first validates the client credentials (in case of a
// confidential client) and then verifies whether the token was issued to the
// client making the revocation request. If this validation fails, the
// request is refused and the client is informed of the error by the
// authorization server as described below." Section 2.2.1 takes the error
// from RFC 6749 Section 5.2, where invalid_grant is the code for a
// credential that "was issued to another client". Section 2.2: "The
// authorization server responds with HTTP status code 200 if the token has
// been revoked successfully or if the client submitted an invalid token."
func TestRevocationIsLimitedToTheTokensClient(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	registerDPoPClientCredentialsClient(t, server, "other-client", "other-secret")
	endpoint := server.server.URL + "/oauth2/revoke"
	owner := basicAuth("owner-client", "owner-secret")
	other := basicAuth("other-client", "other-secret")
	asPublicApp := url.Values{"client_id": {"public-app"}}

	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	publicToken, publicRefresh := publicAppTokens(t, server)
	server.idp.StoreRefreshToken("owner-refresh-token", "owner-client", "alice", "api:read", time.Now(), time.Now().Add(time.Hour))
	idToken, err := server.idp.JWTService().CreateIDToken("alice", "owner-client", "", time.Now(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Access tokens outside the RFC 9068 profile ("typ": "JWT"), as the
	// OID4VCI token endpoint mints them: one for a client, one for a
	// Pre-Authorized Code request that named no client.
	unprofiled := internalcrypto.AccessToken{Subject: "wallet:alice", Audience: server.server.URL + "/oid4vci", ClientID: "owner-client", Scope: "vc:issue", Lifetime: time.Hour}
	unprofiledToken, err := server.idp.JWTService().CreateUnprofiledAccessToken(unprofiled)
	if err != nil {
		t.Fatal(err)
	}
	unprofiled.ClientID = ""
	anonymousToken, err := server.idp.JWTService().CreateUnprofiledAccessToken(unprofiled)
	if err != nil {
		t.Fatal(err)
	}
	// JWTs the same key signed that are not access tokens or refresh tokens
	// of this server.
	signedUserInfo, err := server.idp.JWTService().SignClaimsRS256(map[string]interface{}{"sub": "alice", "client_id": "owner-client"})
	if err != nil {
		t.Fatal(err)
	}
	lookalike := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": server.server.URL + "/agents", "sub": "agent-1", "aud": server.server.URL, "client_id": "owner-client",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nbf": time.Now().Unix(), "jti": "lookalike-jti", "scope": "api:read",
	})
	lookalike.Header["kid"] = server.plugin.keySet.RSAKeyID()
	lookalikeToken, err := lookalike.SignedString(server.plugin.keySet.RSAPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	refreshTokenIsLive := func(token string) bool {
		_, live := server.idp.GetRefreshToken(token)
		return live
	}

	for name, refused := range map[string]struct {
		token     string
		hint      string
		form      url.Values
		configure func(*http.Request)
	}{
		"another confidential client, an access token":       {token: ownerToken, configure: other},
		"another confidential client, a refresh token":       {token: "owner-refresh-token", configure: other},
		"a wrong token_type_hint does not hide the owner":    {token: "owner-refresh-token", hint: "access_token", configure: other},
		"anyone naming the public client, an access token":   {token: ownerToken, form: asPublicApp},
		"anyone naming the public client, a refresh token":   {token: "owner-refresh-token", form: asPublicApp},
		"a confidential client, the public client's token":   {token: publicToken, configure: owner},
		"a confidential client, the public client's refresh": {token: publicRefresh, configure: owner},
		"another client, an unprofiled access token":         {token: unprofiledToken, configure: other},
		"an access token issued to no identified client":     {token: anonymousToken, configure: owner},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			form := url.Values{"token": {refused.token}}
			if refused.hint != "" {
				form.Set("token_type_hint", refused.hint)
			}
			for key, values := range refused.form {
				form[key] = values
			}
			status, body, header := postWithClientAuth(t, endpoint, form, refused.configure)
			if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("status = %d, body = %#v, want 400 invalid_grant", status, body)
			}
			if got := header.Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q: the client authenticated, the token is the problem", got)
			}
		})
	}
	if server.idp.IsTokenRevoked(ownerToken) || server.idp.IsTokenRevoked(publicToken) ||
		server.idp.IsTokenRevoked(unprofiledToken) || server.idp.IsTokenRevoked(anonymousToken) {
		t.Fatal("a refused revocation request revoked an access token")
	}

	// RFC 7009 Section 2.2.1: "unsupported_token_type: The authorization
	// server does not support the revocation of the presented token type."
	// A valid JWT of this server's key that it issued as neither a refresh
	// token nor an access token is such a type, whoever asks and whatever
	// client it names.
	for name, token := range map[string]string{
		"an ID Token issued to the caller":                          idToken,
		"a signed UserInfo response":                                signedUserInfo,
		"a JWT with access token claims that was not minted as one": lookalikeToken,
	} {
		t.Run("unsupported token type: "+name, func(t *testing.T) {
			status, body, header := postWithClientAuth(t, endpoint, url.Values{"token": {token}}, owner)
			if status != http.StatusBadRequest || body["error"] != "unsupported_token_type" {
				t.Fatalf("status = %d, body = %#v, want 400 unsupported_token_type", status, body)
			}
			if got := header.Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q: the client authenticated", got)
			}
			if server.idp.IsTokenRevoked(token) {
				t.Fatal("a token of an unsupported type was recorded as revoked")
			}
		})
	}
	if !refreshTokenIsLive("owner-refresh-token") || !refreshTokenIsLive(publicRefresh) {
		t.Fatal("a refused revocation request revoked a refresh token")
	}

	// An invalid token is answered with 200 and changes nothing.
	unstored, err := server.idp.JWTService().CreateRefreshToken("alice", "other-client", "api:read", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"a string that is no token":                      "not-a-token",
		"no token at all":                                "",
		"a refresh token JWT that is no longer in store": unstored,
	} {
		t.Run("200 for an invalid token: "+name, func(t *testing.T) {
			status, body, _ := postWithClientAuth(t, endpoint, url.Values{"token": {token}}, owner)
			if status != http.StatusOK || body != nil {
				t.Fatalf("status = %d, body = %#v, want 200 with an empty body", status, body)
			}
			if token != "" && server.idp.IsTokenRevoked(token) {
				t.Fatal("an invalid token was recorded as revoked")
			}
		})
	}

	// The client a token was issued to revokes it, whatever the hint says.
	for name, revoked := range map[string]struct {
		token     string
		hint      string
		form      url.Values
		configure func(*http.Request)
		gone      func() bool
	}{
		"a confidential client's access token": {
			token: ownerToken, hint: "refresh_token", configure: owner,
			gone: func() bool { return server.idp.IsTokenRevoked(ownerToken) },
		},
		"a confidential client's refresh token": {
			token: "owner-refresh-token", hint: "access_token", configure: owner,
			gone: func() bool { return !refreshTokenIsLive("owner-refresh-token") },
		},
		"the public client's access token": {
			token: publicToken, form: asPublicApp,
			gone: func() bool { return server.idp.IsTokenRevoked(publicToken) },
		},
		"the public client's refresh token": {
			token: publicRefresh, form: asPublicApp,
			gone: func() bool { return !refreshTokenIsLive(publicRefresh) },
		},
		"a confidential client's unprofiled access token": {
			token: unprofiledToken, configure: owner,
			gone: func() bool { return server.idp.IsTokenRevoked(unprofiledToken) },
		},
	} {
		t.Run("revoked: "+name, func(t *testing.T) {
			form := url.Values{"token": {revoked.token}}
			if revoked.hint != "" {
				form.Set("token_type_hint", revoked.hint)
			}
			for key, values := range revoked.form {
				form[key] = values
			}
			status, body, _ := postWithClientAuth(t, endpoint, form, revoked.configure)
			if status != http.StatusOK || body != nil {
				t.Fatalf("status = %d, body = %#v, want 200 with an empty body", status, body)
			}
			if !revoked.gone() {
				t.Fatal("the token is still usable after a 200")
			}
			// Revoking it again is still a 200 (Section 2.2).
			if status, _, _ := postWithClientAuth(t, endpoint, form, revoked.configure); status != http.StatusOK {
				t.Fatalf("second revocation: status = %d, want 200", status)
			}
		})
	}
}

// TestRevocationOutcomesReachLookingGlass checks that a refusal for a token
// issued to another client, a request for an invalid token and a revocation
// are each an event with the RFC 7009 section it applies.
func TestRevocationOutcomesReachLookingGlass(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	registerDPoPClientCredentialsClient(t, server, "other-client", "other-secret")
	owner := basicAuth("owner-client", "owner-secret")
	other := basicAuth("other-client", "other-secret")
	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	server.idp.StoreRefreshToken("owner-refresh-token", "owner-client", "alice", "api:read", time.Now(), time.Now().Add(time.Hour))
	idToken, err := server.idp.JWTService().CreateIDToken("alice", "owner-client", "", time.Now(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	anonymousToken, err := server.idp.JWTService().CreateUnprofiledAccessToken(internalcrypto.AccessToken{
		Subject: "wallet:alice", Audience: server.server.URL + "/oid4vci", Scope: "vc:issue", Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ordered: the access token is revoked by the last call.
	for _, call := range []struct {
		name       string
		token      string
		configure  func(*http.Request)
		title      string
		references []string
		data       map[string]interface{}
		// explains is text the last annotation must contain.
		explains string
	}{
		{
			name: "another client, an access token", token: ownerToken, configure: other,
			title: "Revocation Refused: Token Issued To Another Client", references: []string{"RFC 7009 Section 2.1", "RFC 6749 Section 5.2"},
			data:     map[string]interface{}{"error": "invalid_grant", "client_id": "other-client", "token_client_id": "owner-client", "token_type": "access_token", "revoked": false},
			explains: "No Section 5.2 code covers an access token by its words; invalid_grant is the only one that names the condition.",
		},
		{
			name: "another client, a refresh token", token: "owner-refresh-token", configure: other,
			title: "Revocation Refused: Token Issued To Another Client", references: []string{"RFC 7009 Section 2.1", "RFC 6749 Section 5.2"},
			data:     map[string]interface{}{"error": "invalid_grant", "token_client_id": "owner-client", "token_type": "refresh_token", "revoked": false},
			explains: `or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client." This token is a refresh token, which those words cover.`,
		},
		{
			name: "an access token issued to no identified client", token: anonymousToken, configure: owner,
			title: "Revocation Refused: Token Issued To No Identified Client", references: []string{"RFC 7009 Section 2.1", "RFC 6749 Section 5.2"},
			data:     map[string]interface{}{"error": "invalid_grant", "client_id": "owner-client", "token_client_id": "", "token_type": "access_token", "revoked": false},
			explains: "No Section 5.2 code covers this case by its words.",
		},
		{
			name: "an ID Token", token: idToken, configure: owner,
			title: "Revocation Refused: Unsupported Token Type", references: []string{"RFC 7009 Section 2.2.1"},
			data:     map[string]interface{}{"error": "unsupported_token_type", "client_id": "owner-client", "revoked": false},
			explains: "The authorization server does not support the revocation of the presented token type.",
		},
		{
			name: "an invalid token", token: "not-a-token", configure: owner,
			title: "Nothing To Revoke: Invalid Token", references: []string{"RFC 7009 Section 2.2"},
			data: map[string]interface{}{"client_id": "owner-client", "revoked": false},
		},
		{
			name: "the token's client", token: ownerToken, configure: owner,
			title: "Token Revoked", references: []string{"RFC 7009 Section 2.1"},
			data: map[string]interface{}{"client_id": "owner-client", "token_type": "access_token", "revoked": true},
		},
	} {
		t.Run(call.name, func(t *testing.T) {
			session, _ := createOwnedOAuthSession(t, server.engine)
			postWithClientAuth(t, server.server.URL+"/oauth2/revoke", url.Values{"token": {call.token}}, func(request *http.Request) {
				request.Header.Set("X-Looking-Glass-Session", session.ID)
				call.configure(request)
			})

			stored, ok := server.engine.GetSession(session.ID)
			if !ok {
				t.Fatal("Looking Glass session not found")
			}
			for _, event := range stored.Events {
				if event.Title != call.title {
					continue
				}
				for key, want := range call.data {
					if event.Data[key] != want {
						t.Errorf("%s = %v, want %v", key, event.Data[key], want)
					}
				}
				if event.Data["token"] != call.token {
					t.Errorf("the event does not show the submitted token in full")
				}
				var references []string
				for _, annotation := range event.Annotations {
					references = append(references, annotation.Reference)
				}
				if !reflect.DeepEqual(references, call.references) {
					t.Fatalf("references = %q, want %q", references, call.references)
				}
				if last := event.Annotations[len(event.Annotations)-1].Description; !strings.Contains(last, call.explains) {
					t.Fatalf("the annotation does not say %q: %s", call.explains, last)
				}
				return
			}
			t.Fatalf("event %q not found in %#v", call.title, stored.Events)
		})
	}
}

// TestFailedClientAuthenticationChallengesTheSchemeTheClientUsed covers RFC
// 6749 Section 5.2 for a client that used a scheme other than Basic in the
// Authorization header: the authorization server "MUST respond with an HTTP
// 401 (Unauthorized) status code and include the "WWW-Authenticate" response
// header field matching the authentication scheme used by the client." Basic,
// the scheme these endpoints support, is listed first (RFC 9110 Section 11.3:
// "A workaround for this problem is to list well-supported schemes (such as
// "basic") first."). A scheme is repeated only when it is an RFC 9110 token.
// The Bearer challenge has no "error" attribute here: RFC 6750 Section 3 is
// reached only from the introspection endpoint, through RFC 7662 Section 2.3.
func TestFailedClientAuthenticationChallengesTheSchemeTheClientUsed(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	const basicChallenge = `Basic realm="oauth2"`
	for name, endpoint := range map[string]struct {
		path string
		form url.Values
	}{
		"revocation":                      {"/oauth2/revoke", url.Values{"token": {"not-a-token"}}},
		"token, authorization_code":       {"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {"none"}}},
		"token, refresh_token":            {"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"none"}}},
		"token, client_credentials":       {"/oauth2/token", url.Values{"grant_type": {"client_credentials"}}},
		"token, device_code":              {"/oauth2/token", url.Values{"grant_type": {mockidp.DeviceCodeGrantType}, "device_code": {"none"}}},
		"device authorization (RFC 8628)": {"/oauth2/device/authorize", url.Values{}},
	} {
		for credentials, challenges := range map[string][]string{
			"Bearer some-token":       {basicChallenge, `Bearer realm="oauth2"`},
			"bearer some-token":       {basicChallenge, `Bearer realm="oauth2"`},
			"DPoP some-token":         {basicChallenge, "DPoP"},
			"Negotiate":               {basicChallenge, "Negotiate"},
			`Sche"me, injected="x" y`: {basicChallenge},
			"Basic !not-base64!":      {basicChallenge},
		} {
			t.Run(name+", Authorization: "+credentials, func(t *testing.T) {
				// demo-app is confidential and presents no usable credentials.
				form := url.Values{"client_id": {"demo-app"}}
				for key, values := range endpoint.form {
					form[key] = values
				}
				status, body, header := postWithClientAuth(t, server.server.URL+endpoint.path, form, authorization(credentials))
				if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
					t.Fatalf("status = %d, body = %#v, want 401 invalid_client", status, body)
				}
				if got := header.Values("WWW-Authenticate"); !reflect.DeepEqual(got, challenges) {
					t.Fatalf("WWW-Authenticate = %q, want %q", got, challenges)
				}
			})
		}
	}
}

// TestAuthorizationServerMetadataNamesEndpointAuthMethods covers RFC 8414
// Section 2. introspection_endpoint_auth_methods_supported lists the client
// password methods and not "none". revocation_endpoint_auth_methods_supported
// adds private_key_jwt and "none", because a public client revokes its own
// tokens by client_id; "If omitted, the default is "client_secret_basic"",
// which would leave those out. With private_key_jwt listed,
// revocation_endpoint_auth_signing_alg_values_supported "MUST be present".
func TestAuthorizationServerMetadataNamesEndpointAuthMethods(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	response, err := http.Get(server.server.URL + "/oauth2/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var metadata map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	want := []interface{}{"client_secret_basic", "client_secret_post"}
	if got := metadata["introspection_endpoint_auth_methods_supported"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("introspection_endpoint_auth_methods_supported = %#v, want %#v", got, want)
	}
	want = append(want, "private_key_jwt", "none")
	if got := metadata["revocation_endpoint_auth_methods_supported"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("revocation_endpoint_auth_methods_supported = %#v, want %#v", got, want)
	}
	algorithms := []interface{}{"RS256", "ES256", "EdDSA"}
	if got := metadata["revocation_endpoint_auth_signing_alg_values_supported"]; !reflect.DeepEqual(got, algorithms) {
		t.Fatalf("revocation_endpoint_auth_signing_alg_values_supported = %#v, want %#v", got, algorithms)
	}
}

// TestRevocationAuthenticatesPrivateKeyJWTClients covers client
// authentication with a JWT at the revocation endpoint. RFC 7009 Section 2.1:
// "The client also includes its authentication credentials as described in
// Section 2.3. of [RFC6749]". RFC 7523 Section 3: the JWT MUST contain an
// "aud" claim "containing a value that identifies the authorization server
// as an intended audience. The token endpoint URL of the authorization
// server MAY be used as a value for an "aud" element", and Section 3.2: "If
// the client JWT is not valid [...] The value of the "error" parameter MUST
// be the "invalid_client" error code."
func TestRevocationAuthenticatesPrivateKeyJWTClients(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "ES256", "revocation-key")
	server.registerSigner(signer)
	registerDPoPClientCredentialsClient(t, server, "owner-client", "owner-secret")
	const clientID = "machine-client-pkjwt"
	base := server.server.URL
	endpoint := base + "/oauth2/revoke"
	issued := 0
	assertionFor := func(audience string) string {
		t.Helper()
		issued++
		return signer.sign(t, validAssertionClaims(*server.now, clientID, audience, fmt.Sprintf("revocation-jti-%d", issued)), "")
	}
	accessToken := func() string {
		t.Helper()
		status, body := postClientAssertion(t, base, assertionForm(clientID, assertionFor(base+"/oauth2/token")), "", "", "")
		token, _ := body["access_token"].(string)
		if status != http.StatusOK || token == "" {
			t.Fatalf("token status = %d, body = %#v", status, body)
		}
		return token
	}
	withAssertion := func(token, assertion string) url.Values {
		return url.Values{"token": {token}, "client_assertion_type": {clientAssertionType}, "client_assertion": {assertion}}
	}

	// Each value that identifies this server is an accepted audience.
	for name, audience := range map[string]string{
		"the issuer identifier":                base + "/oauth2",
		"the token endpoint URL":               base + "/oauth2/token",
		"the OpenID Provider's issuer":         base,
		"the OpenID Provider's token endpoint": base + "/oidc/token",
	} {
		t.Run("revoked with aud "+name, func(t *testing.T) {
			token := accessToken()
			status, body, _ := postWithClientAuth(t, endpoint, withAssertion(token, assertionFor(audience)), nil)
			if status != http.StatusOK || body != nil {
				t.Fatalf("status = %d, body = %#v, want 200 with an empty body", status, body)
			}
			if !server.idp.IsTokenRevoked(token) {
				t.Fatal("the token is still usable after a 200")
			}
		})
	}

	token := accessToken()
	ownerToken, _ := clientCredentialsToken(t, server, "owner-client", "owner-secret", "api:read")
	otherSigner := newAssertionSigner(t, "ES256", "revocation-key")
	replayed := assertionFor(base + "/oauth2/token")
	if status, _, _ := postWithClientAuth(t, endpoint, withAssertion("not-a-token", replayed), nil); status != http.StatusOK {
		t.Fatalf("first use of the assertion: status = %d, want 200", status)
	}
	for name, refused := range map[string]struct {
		form      url.Values
		configure func(*http.Request)
		status    int
		code      string
	}{
		"an audience that is another server": {
			form: withAssertion(token, assertionFor("https://other.example/oauth2/token")), status: http.StatusBadRequest, code: "invalid_client",
		},
		"an assertion signed with another key": {
			form:   withAssertion(token, otherSigner.sign(t, validAssertionClaims(*server.now, clientID, base+"/oauth2", "other-key-jti"), "")),
			status: http.StatusBadRequest, code: "invalid_client",
		},
		"an assertion that was already used": {
			form: withAssertion(token, replayed), status: http.StatusBadRequest, code: "invalid_client",
		},
		"an unsupported client_assertion_type": {
			form:   url.Values{"token": {token}, "client_assertion_type": {"urn:example:other"}, "client_assertion": {assertionFor(base + "/oauth2")}},
			status: http.StatusBadRequest, code: "invalid_client",
		},
		"client_id alone for a private_key_jwt client": {
			form: url.Values{"token": {token}, "client_id": {clientID}}, status: http.StatusBadRequest, code: "invalid_client",
		},
		"a client_assertion without its type": {
			form: url.Values{"token": {token}, "client_assertion": {assertionFor(base + "/oauth2")}}, status: http.StatusBadRequest, code: "invalid_request",
		},
		"an assertion and HTTP Basic together": {
			form: withAssertion(token, assertionFor(base+"/oauth2")), configure: basicAuth("owner-client", "owner-secret"),
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"an assertion and a client_secret together": {
			form: func() url.Values {
				form := withAssertion(token, assertionFor(base+"/oauth2"))
				form.Set("client_secret", "anything")
				return form
			}(),
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"a token issued to another client": {
			form: withAssertion(ownerToken, assertionFor(base+"/oauth2")), status: http.StatusBadRequest, code: "invalid_grant",
		},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			status, body, header := postWithClientAuth(t, endpoint, refused.form, refused.configure)
			if status != refused.status || body["error"] != refused.code {
				t.Fatalf("status = %d, body = %#v, want %d %s", status, body, refused.status, refused.code)
			}
			if refused.code == "invalid_client" && refused.form.Has("client_assertion") && body["error_description"] != "client assertion validation failed" {
				t.Fatalf("error_description = %v, want the generic one", body["error_description"])
			}
			if got := header.Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q on a request without an Authorization header", got)
			}
		})
	}
	if server.idp.IsTokenRevoked(token) || server.idp.IsTokenRevoked(ownerToken) {
		t.Fatal("a refused revocation request revoked the token")
	}

	// RFC 7009 Section 2.2.1: "If the server responds with HTTP status code
	// 503, the client must assume the token still exists and may retry after
	// a reasonable delay."
	t.Run("503 when the assertion cannot be checked for replay", func(t *testing.T) {
		replayStore := server.plugin.clientAssertionReplay
		server.plugin.clientAssertionReplay = failingClientAssertionReplayStore{}
		defer func() { server.plugin.clientAssertionReplay = replayStore }()
		status, body, _ := postWithClientAuth(t, endpoint, withAssertion(token, assertionFor(base+"/oauth2")), nil)
		if status != http.StatusServiceUnavailable || body["error"] != "server_error" {
			t.Fatalf("status = %d, body = %#v, want 503 server_error", status, body)
		}
		if server.idp.IsTokenRevoked(token) {
			t.Fatal("the token was revoked although the client was not authenticated")
		}
	})

	// Looking Glass shows the assertion, why one was refused and the
	// verification of the accepted one.
	events := func(form url.Values) []lookingglass.Event {
		t.Helper()
		session, _ := createOwnedOAuthSession(t, server.engine)
		postWithClientAuth(t, endpoint, form, func(request *http.Request) { request.Header.Set("X-Looking-Glass-Session", session.ID) })
		stored, ok := server.engine.GetSession(session.ID)
		if !ok {
			t.Fatal("Looking Glass session not found")
		}
		return stored.Events
	}
	find := func(events []lookingglass.Event, title string) lookingglass.Event {
		t.Helper()
		for _, event := range events {
			if event.Title == title {
				return event
			}
		}
		t.Fatalf("event %q not found in %#v", title, events)
		return lookingglass.Event{}
	}
	wrongAudience := assertionFor("https://other.example/oauth2/token")
	refusedEvents := events(withAssertion(token, wrongAudience))
	if got := find(refusedEvents, "Token Revocation Request").Data["client_assertion"]; got != wrongAudience {
		t.Fatalf("the request event does not show the assertion in full: %v", got)
	}
	refusal := find(refusedEvents, "Revocation Refused: Client Authentication Failed")
	if refusal.Data["reason"] != "invalid_aud" || len(refusal.Annotations) != 1 || refusal.Annotations[0].Reference != "RFC 7523 Section 3.2" {
		t.Fatalf("refusal event = %#v", refusal)
	}
	acceptedEvents := events(withAssertion(token, assertionFor(base+"/oauth2")))
	verified := find(acceptedEvents, "Client Assertion Signature Verified")
	if verified.Data["client_id"] != clientID || verified.Data["alg"] != "ES256" || verified.Data["kid"] != "revocation-key" {
		t.Fatalf("verification event = %#v", verified.Data)
	}
	revoked := find(acceptedEvents, "Token Revoked")
	if revoked.Data["client_id"] != clientID || revoked.Data["client_auth_method"] != "private_key_jwt" {
		t.Fatalf("revocation event = %#v", revoked.Data)
	}
}

// TestRevokingARefreshTokenRevokesTheGrantsAccessTokens covers RFC 7009
// Section 2.1 at the revocation endpoint: "If the particular token is a
// refresh token and the authorization server supports the revocation of
// access tokens, then the authorization server SHOULD also invalidate all
// access tokens based on the same authorization grant". The grant here is one
// authorization code, redeemed once and refreshed once.
func TestRevokingARefreshTokenRevokesTheGrantsAccessTokens(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	firstAccess, firstRefresh := publicAppTokens(t, server)
	status, refreshed := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {firstRefresh},
		"client_id":     {"public-app"},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %#v", status, refreshed)
	}
	secondAccess, _ := refreshed["access_token"].(string)
	secondRefresh, _ := refreshed["refresh_token"].(string)
	if secondAccess == "" || secondRefresh == "" || secondRefresh == firstRefresh {
		t.Fatalf("the refresh did not rotate the tokens: %#v", refreshed)
	}
	otherAccess, otherRefresh := publicAppTokens(t, server)

	session, _ := createOwnedOAuthSession(t, server.engine)
	status, body, _ := postWithClientAuth(t, server.server.URL+"/oauth2/revoke",
		url.Values{"token": {secondRefresh}, "client_id": {"public-app"}},
		func(request *http.Request) { request.Header.Set("X-Looking-Glass-Session", session.ID) })
	if status != http.StatusOK || body != nil {
		t.Fatalf("status = %d, body = %#v, want 200 with an empty body", status, body)
	}

	if _, live := server.idp.GetRefreshToken(secondRefresh); live {
		t.Fatal("the revoked refresh token is still usable")
	}
	if !server.idp.IsTokenRevoked(firstAccess) || !server.idp.IsTokenRevoked(secondAccess) {
		t.Fatal("an access token of the revoked grant is still usable")
	}
	if server.idp.IsTokenRevoked(otherAccess) {
		t.Fatal("an access token of another grant was revoked")
	}
	if _, live := server.idp.GetRefreshToken(otherRefresh); !live {
		t.Fatal("the refresh token of another grant was revoked")
	}

	// Looking Glass names each access token the revocation took with it.
	var want []string
	for _, accessToken := range []string{firstAccess, secondAccess} {
		_, claims := accessTokenParts(t, accessToken)
		jti, _ := claims["jti"].(string)
		want = append(want, jti)
	}
	stored, ok := server.engine.GetSession(session.ID)
	if !ok {
		t.Fatal("Looking Glass session not found")
	}
	for _, event := range stored.Events {
		if event.Title != "Token Revoked" {
			continue
		}
		if got := event.Data["access_token_jtis_revoked"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("access_token_jtis_revoked = %#v, want %#v", got, want)
		}
		if event.Data["token_type"] != "refresh_token" || event.Data["token"] != secondRefresh {
			t.Fatalf("the event does not show the revoked refresh token: %#v", event.Data)
		}
		var references []string
		for _, annotation := range event.Annotations {
			references = append(references, annotation.Reference)
		}
		if !reflect.DeepEqual(references, []string{"RFC 7009 Section 2.1", "RFC 7009 Section 2.1"}) {
			t.Fatalf("references = %q", references)
		}
		return
	}
	t.Fatalf("event \"Token Revoked\" not found in %#v", stored.Events)
}

// TestAuthorizationCodeReplayRevokesRefreshedTokens covers RFC 6749 Section
// 4.1.2 at the token endpoint: "If an authorization code is used more than
// once, the authorization server MUST deny the request and SHOULD revoke
// (when possible) all tokens previously issued based on that authorization
// code." The code here was redeemed and its tokens refreshed once before the
// replay, and Looking Glass names what the replay revoked.
func TestAuthorizationCodeReplayRevokesRefreshedTokens(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	redeem := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, issued := postTokenRequest(t, server.server.URL, redeem, "")
	if status != http.StatusOK {
		t.Fatalf("token status = %d, body = %#v", status, issued)
	}
	firstAccess, _ := issued["access_token"].(string)
	firstRefresh, _ := issued["refresh_token"].(string)
	status, refreshed := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {firstRefresh},
		"client_id":     {"public-app"},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %#v", status, refreshed)
	}
	secondAccess, _ := refreshed["access_token"].(string)
	secondRefresh, _ := refreshed["refresh_token"].(string)
	otherAccess, otherRefresh := publicAppTokens(t, server)

	session, _ := createOwnedOAuthSession(t, server.engine)
	status, body, _ := postWithClientAuth(t, server.server.URL+"/oauth2/token", redeem,
		func(request *http.Request) { request.Header.Set("X-Looking-Glass-Session", session.ID) })
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replay: status = %d, body = %#v, want 400 invalid_grant", status, body)
	}

	if !server.idp.IsTokenRevoked(firstAccess) || !server.idp.IsTokenRevoked(secondAccess) {
		t.Fatal("an access token issued from the replayed code is still usable")
	}
	if _, live := server.idp.GetRefreshToken(secondRefresh); live {
		t.Fatal("the refresh token obtained by refreshing is still usable")
	}
	if server.idp.IsTokenRevoked(otherAccess) {
		t.Fatal("an access token of another code was revoked")
	}
	if _, live := server.idp.GetRefreshToken(otherRefresh); !live {
		t.Fatal("the refresh token of another code was revoked")
	}

	var want []string
	for _, accessToken := range []string{firstAccess, secondAccess} {
		_, claims := accessTokenParts(t, accessToken)
		jti, _ := claims["jti"].(string)
		want = append(want, jti)
	}
	stored, ok := server.engine.GetSession(session.ID)
	if !ok {
		t.Fatal("Looking Glass session not found")
	}
	for _, event := range stored.Events {
		if event.Title != "Authorization Code Replayed: Tokens Revoked" {
			continue
		}
		if got := event.Data["access_token_jtis_revoked"]; !reflect.DeepEqual(got, want) {
			t.Errorf("access_token_jtis_revoked = %#v, want %#v", got, want)
		}
		if event.Data["refresh_tokens_revoked"] != 1 || event.Data["code"] != code.Code {
			t.Errorf("event data = %#v", event.Data)
		}
		if len(event.Annotations) != 1 || event.Annotations[0].Reference != "RFC 6749 Section 4.1.2" {
			t.Fatalf("annotations = %#v", event.Annotations)
		}
		return
	}
	t.Fatalf("replay event not found in %#v", stored.Events)
}

// TestSCIMClientCredentialsTokenNamesTheSCIMResource covers RFC 9068 Section
// 3 for the SCIM service provider: "If a "scope" parameter is present in the
// request, the authorization server SHOULD use it to infer the value of the
// default resource indicator to be used in the "aud" claim." scim.read and
// scim.write have meaning only at the SCIM base URI. RFC 7644 Section 7.4:
// "Bearer tokens MUST have a limited lifetime that can be determined directly
// or indirectly", which here is the "exp" claim.
func TestSCIMClientCredentialsTokenNamesTheSCIMResource(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	client, _ := server.idp.GetClient(mockidp.SCIMClientID)
	serviceProvider, _ := server.idp.GetClient(mockidp.SCIMServiceProviderClientID)
	transmitter, _ := server.idp.GetClient(mockidp.SSFTransmitterClientID)
	if client == nil || client.Secret == "" || serviceProvider == nil || transmitter == nil {
		t.Fatal("the seeded scim-client and the SCIM service provider resource server are required")
	}

	accessToken, _ := clientCredentialsToken(t, server, mockidp.SCIMClientID, client.Secret, "scim.read scim.write")
	_, claims := accessTokenParts(t, accessToken)
	wantAudience := server.plugin.baseURL + "/scim/v2"
	if claims["aud"] != wantAudience {
		t.Errorf("aud = %v, want the SCIM base URI %s", claims["aud"], wantAudience)
	}
	if claims["scope"] != "scim.read scim.write" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if claims["client_id"] != mockidp.SCIMClientID {
		t.Errorf("client_id = %v", claims["client_id"])
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp = %#v, want a lifetime the service provider can determine", claims["exp"])
	}

	// A scope of the SCIM resource and one of another resource are refused.
	server.idp.RegisterClient(&models.Client{
		ID:         "scim-and-api-client",
		Secret:     "scim-and-api-secret",
		Name:       "Client Registered For Two Resources",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"api:read", "scim.read"},
	})
	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"scim-and-api-client"},
		"client_secret": {"scim-and-api-secret"},
		"scope":         {"api:read scim.read"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("status = %d, error = %v; want 400 invalid_scope; body = %#v", status, body["error"], body)
	}

	// RFC 7662 Section 4: the resource server the aud names is answered, and
	// another resource server is not.
	for name, call := range map[string]struct {
		clientID, secret string
		active           bool
	}{
		"the SCIM service provider": {mockidp.SCIMServiceProviderClientID, serviceProvider.Secret, true},
		"the SSF Transmitter":       {mockidp.SSFTransmitterClientID, transmitter.Secret, false},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := introspect(t, server, call.clientID, call.secret, accessToken)
			if status != http.StatusOK || body["active"] != call.active {
				t.Fatalf("status = %d, active = %v, want %v; body = %#v", status, body["active"], call.active, body)
			}
		})
	}
}
