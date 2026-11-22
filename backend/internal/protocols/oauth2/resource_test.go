package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
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
