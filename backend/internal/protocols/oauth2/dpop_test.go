package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

// dpopTestKey is a minimal ES256 key pair for building DPoP proofs in tests,
// distinct from clientauth_jwt_test.go's assertionSigner (which signs client
// assertions, not proofs bound to htm/htu).
type dpopTestKey struct {
	privateKey *ecdsa.PrivateKey
	jwk        internalcrypto.JWK
}

func newDPoPTestKey(t *testing.T) dpopTestKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return dpopTestKey{
		privateKey: privateKey,
		jwk:        internalcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "dpop-test-key"),
	}
}

// proof builds a compact DPoP proof JWT (RFC 9449 Section 4.2) for htm/htu,
// optionally overriding or adding claims (e.g. a stale iat, a foreign jti).
func (k dpopTestKey) proof(t *testing.T, htm, htu string, overrides jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"jti": "dpop-jti-" + randomSuffix(t),
		"htm": htm,
		"htu": htu,
		"iat": time.Now().UTC().Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
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

func randomSuffix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hexEncode(raw)
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}

// failingDPoPReplayStore always fails, used to test that a replay-store
// outage fails closed (500 server_error) rather than silently accepting or
// misreporting a proof as replayed.
type failingDPoPReplayStore struct{}

func (failingDPoPReplayStore) Reserve(context.Context, string, string, time.Time, time.Time) (bool, error) {
	return false, errFailingDPoPReplayStore
}

func (failingDPoPReplayStore) Close() error { return nil }

var errFailingDPoPReplayStore = dpopProofError("dpop replay store unavailable in test double")

func postTokenRequest(t *testing.T, serverURL string, form url.Values, dpopProof string) (int, map[string]interface{}) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/token", strings.NewReader(form.Encode()))
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
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

// postTokenRequestCapturingHeaders mirrors postTokenRequest but also
// returns the response headers, needed for asserting on the DPoP-Nonce
// response header (RFC 9449 Section 8).
func postTokenRequestCapturingHeaders(t *testing.T, serverURL string, form url.Values, dpopProof string) (int, map[string]interface{}, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/token", strings.NewReader(form.Encode()))
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
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body, response.Header
}

func registerDPoPClientCredentialsClient(t *testing.T, server *oauthAssertionTestServer, clientID, secret string) {
	t.Helper()
	server.idp.RegisterClient(&models.Client{
		ID:         clientID,
		Secret:     secret,
		Name:       "DPoP Client Credentials Test Client",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"api:read"},
	})
}

// accessTokenCnfJKT decodes an access token with the plugin's own JWT
// service (proving the token really was signed by this server, not merely
// well-formed) and returns its cnf.jkt claim, or "" if absent.
func accessTokenCnfJKT(t *testing.T, server *oauthAssertionTestServer, accessToken string) string {
	t.Helper()
	claims, err := server.idp.JWTService().ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

func TestClientCredentialsGrantBindsDPoPAccessToken(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "dpop-cc-client", "dpop-cc-secret")
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"dpop-cc-client"},
		"scope":      {"api:read"},
	}
	request, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(dpop.HeaderName, proof)
	request.SetBasicAuth("dpop-cc-client", "dpop-cc-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if decodeErr := json.NewDecoder(response.Body).Decode(&body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", response.StatusCode, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	jkt := accessTokenCnfJKT(t, server, accessToken)
	if jkt != key.jwk.Thumbprint() {
		t.Fatalf("cnf.jkt = %q, want %q", jkt, key.jwk.Thumbprint())
	}
}

func TestClientCredentialsGrantWithoutDPoPStaysBearer(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	registerDPoPClientCredentialsClient(t, server, "bearer-cc-client", "bearer-cc-secret")
	tokenURL := server.server.URL + "/oauth2/token"

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"bearer-cc-client"},
		"scope":      {"api:read"},
	}
	request, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("bearer-cc-client", "bearer-cc-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if decodeErr := json.NewDecoder(response.Body).Decode(&body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", response.StatusCode, body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer (no behavioural change absent DPoP)", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt != "" {
		t.Fatalf("unbound token carries cnf.jkt = %q, want none", jkt)
	}
}

func createDPoPTestAuthCode(t *testing.T, server *oauthAssertionTestServer) *models.AuthorizationCode {
	t.Helper()
	code, err := server.idp.CreateAuthorizationCode(
		"public-app", "alice", "http://localhost:3000/callback", "openid profile", "", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestAuthorizationCodeGrantBindsDPoPAccessAndRefreshToken(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt != key.jwk.Thumbprint() {
		t.Fatalf("cnf.jkt = %q, want %q", jkt, key.jwk.Thumbprint())
	}

	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected a refresh token")
	}
	// The refresh token's binding is exercised end-to-end by the
	// refresh-grant tests below (matching key succeeds, mismatched key and
	// missing proof are rejected); this test only asserts issuance.
}

func TestAuthorizationCodeGrantWithoutDPoPStaysUnbound(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt != "" {
		t.Fatalf("unbound token carries cnf.jkt = %q", jkt)
	}
}

// issueDPoPBoundRefreshToken runs a full authorization_code exchange bound
// to key and returns the resulting refresh token, for refresh-grant tests.
func issueDPoPBoundRefreshToken(t *testing.T, server *oauthAssertionTestServer, key dpopTestKey) string {
	t.Helper()
	code := createDPoPTestAuthCode(t, server)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("initial token issuance status = %d, body = %#v", status, body)
	}
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected a refresh token from the initial exchange")
	}
	return refreshToken
}

func TestRefreshTokenGrantPreservesDPoPBindingWithMatchingProof(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	key := newDPoPTestKey(t)
	refreshToken := issueDPoPBoundRefreshToken(t, server, key)
	tokenURL := server.server.URL + "/oauth2/token"

	refreshProof := key.proof(t, http.MethodPost, tokenURL, nil)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, refreshProof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP (binding must survive refresh)", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt != key.jwk.Thumbprint() {
		t.Fatalf("refreshed cnf.jkt = %q, want %q", jkt, key.jwk.Thumbprint())
	}
}

func TestRefreshTokenGrantRejectsMismatchedDPoPKey(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	originalKey := newDPoPTestKey(t)
	attackerKey := newDPoPTestKey(t)
	refreshToken := issueDPoPBoundRefreshToken(t, server, originalKey)
	tokenURL := server.server.URL + "/oauth2/token"

	wrongKeyProof := attackerKey.proof(t, http.MethodPost, tokenURL, nil)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, wrongKeyProof)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("status = %d, body = %#v, want 400 invalid_grant", status, body)
	}
}

func TestRefreshTokenGrantRejectsMissingProofWhenBound(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	key := newDPoPTestKey(t)
	refreshToken := issueDPoPBoundRefreshToken(t, server, key)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, "")
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("status = %d, body = %#v, want 400 invalid_grant", status, body)
	}
}

func TestRefreshTokenGrantUnboundTokenStaysUnboundEvenWithProofPresented(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	// First exchange with no DPoP header at all -> unbound tokens.
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, "")
	if status != http.StatusOK {
		t.Fatalf("initial exchange status = %d, body = %#v", status, body)
	}
	refreshToken, _ := body["refresh_token"].(string)

	// Refreshing an unbound token with a DPoP proof present must not
	// silently upgrade it to bound -- the plan scopes binding to
	// first-issuance only.
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-app"},
	}
	refreshStatus, refreshBody := postTokenRequest(t, server.server.URL, refreshForm, proof)
	if refreshStatus != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %#v", refreshStatus, refreshBody)
	}
	if refreshBody["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer (unbound refresh token must not gain binding)", refreshBody["token_type"])
	}
}

// TestAuthorizationCodeGrantDoesNotBindRefreshTokenForConfidentialClient
// covers RFC 9449 Section 5's explicit carve-out: "Refresh tokens issued to
// confidential clients ... are not bound to the DPoP proof public key
// because they are already sender-constrained with a different existing
// mechanism" (client authentication). The access token is still bound --
// that half of Section 5 applies regardless of client type -- but a later
// refresh with no DPoP proof at all, for a confidential client, must still
// succeed.
func TestAuthorizationCodeGrantDoesNotBindRefreshTokenForConfidentialClient(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	const clientID = "confidential-dpop-app"
	const clientSecret = "confidential-dpop-secret"
	server.idp.RegisterClient(&models.Client{
		ID:         clientID,
		Secret:     clientSecret,
		Name:       "Confidential DPoP Test Client",
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile"},
		Public:     false,
	})
	code, err := server.idp.CreateAuthorizationCode(
		clientID, "alice", "http://localhost:3000/callback", "openid profile", "", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", status, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP (access token binding applies regardless of client type)", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt == "" {
		t.Fatal("access token should still carry a cnf.jkt claim for a confidential client")
	}
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected a refresh token")
	}

	// Refresh with NO DPoP proof at all. If the refresh token had been
	// (incorrectly) bound to the DPoP key, this would be rejected with
	// invalid_grant per handleRefreshTokenGrant's key-mismatch check --
	// exactly the assertion TestRefreshTokenGrantRejectsMissingProofWhenBound
	// makes for the public-client case that IS supposed to bind.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	refreshStatus, refreshBody := postTokenRequest(t, server.server.URL, refreshForm, "")
	if refreshStatus != http.StatusOK {
		t.Fatalf("refresh without a DPoP proof status = %d, body = %#v, want 200 (confidential client refresh tokens are not DPoP-bound per RFC 9449 Section 5)", refreshStatus, refreshBody)
	}
}

func TestTokenEndpointRejectsInvalidDPoPProof(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, "not-a-valid-proof-jwt")
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorInvalidDPoPProof)
	}
}

// TestTokenEndpointRejectsMultipleDPoPHeaders covers RFC 9449 Section 4.3
// check 1: "There is not more than one DPoP HTTP request header field."
// http.Header.Get (used pre-fix) would silently take the first of two DPoP
// header lines and ignore the second; the token endpoint must instead
// reject the request outright.
func TestTokenEndpointRejectsMultipleDPoPHeaders(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
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
	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || body["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("status = %d, body = %#v, want 400 %s", response.StatusCode, body, dpop.ErrorInvalidDPoPProof)
	}
}

func TestTokenEndpointRejectsReplayedDPoPProof(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	sharedProof := key.proof(t, http.MethodPost, tokenURL, jwt.MapClaims{"jti": "fixed-replay-jti"})

	firstCode := createDPoPTestAuthCode(t, server)
	firstForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {firstCode.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	firstStatus, firstBody := postTokenRequest(t, server.server.URL, firstForm, sharedProof)
	if firstStatus != http.StatusOK {
		t.Fatalf("first request status = %d, body = %#v", firstStatus, firstBody)
	}

	secondCode := createDPoPTestAuthCode(t, server)
	secondForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {secondCode.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	secondStatus, secondBody := postTokenRequest(t, server.server.URL, secondForm, sharedProof)
	if secondStatus != http.StatusBadRequest || secondBody["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("replayed proof status = %d, body = %#v, want 400 %s", secondStatus, secondBody, dpop.ErrorInvalidDPoPProof)
	}
}

func TestTokenEndpointDPoPReplayStoreOutageFailsClosed(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.plugin.dpopReplay = failingDPoPReplayStore{}
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("status = %d, body = %#v, want 500 server_error (fail closed on store outage)", status, body)
	}
}

// TestClientCredentialsGrantBindsDPoPWithPrivateKeyJWTClientAuth exercises
// the combination the plan's Phase 2 SURVEY item flagged directly: DPoP
// proof-of-possession and private_key_jwt client authentication are
// orthogonal mechanisms proving possession of two different keys (the
// client's registered assertion key vs. the DPoP proof key), and both must
// be able to apply to the same client_credentials request.
func TestClientCredentialsGrantBindsDPoPWithPrivateKeyJWTClientAuth(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	assertionSigner := newAssertionSigner(t, "ES256", "pkjwt-dpop-key")
	server.registerSigner(assertionSigner)
	dpopKey := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"

	assertion := assertionSigner.sign(t, validAssertionClaims(*server.now, "machine-client-pkjwt", tokenURL, "pkjwt-dpop-jti"), "")
	proof := dpopKey.proof(t, http.MethodPost, tokenURL, nil)

	request, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(assertionForm("machine-client-pkjwt", assertion).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(dpop.HeaderName, proof)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]interface{}
	if decodeErr := json.NewDecoder(response.Body).Decode(&body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %#v", response.StatusCode, body)
	}
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	accessToken, _ := body["access_token"].(string)
	if jkt := accessTokenCnfJKT(t, server, accessToken); jkt != dpopKey.jwk.Thumbprint() {
		t.Fatalf("cnf.jkt = %q, want %q", jkt, dpopKey.jwk.Thumbprint())
	}
}

// --- Phase 5: DPoP-Nonce (RFC 9449 Section 8) ---
//
// dpopNonceIssuer is nil by default (nonces are opt-in per PluginConfig,
// off unless SHOWCASE_DPOP_NONCE_REQUIRED is set), so these tests turn it
// on directly on the test server's plugin, mirroring how
// TestTokenEndpointDPoPReplayStoreOutageFailsClosed substitutes
// server.plugin.dpopReplay.

func TestTokenEndpointNonceDisabledByDefaultNoBehaviouralChange(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	if server.plugin.dpopNonceIssuer != nil {
		t.Fatal("dpopNonceIssuer must be nil by default -- nonces are opt-in hardening")
	}
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %#v, want 200 (nonces disabled by default)", status, body)
	}
}

func TestTokenEndpointChallengesMissingNonceWhenRequired(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.plugin.dpopNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	proof := key.proof(t, http.MethodPost, tokenURL, nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body, headers := postTokenRequestCapturingHeaders(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	if headers.Get(dpop.NonceHeaderName) == "" {
		t.Fatal("expected a DPoP-Nonce response header on the challenge")
	}
}

func TestTokenEndpointRetryWithChallengedNonceSucceeds(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.plugin.dpopNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"

	firstCode := createDPoPTestAuthCode(t, server)
	firstProof := key.proof(t, http.MethodPost, tokenURL, nil)
	firstForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {firstCode.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body, headers := postTokenRequestCapturingHeaders(t, server.server.URL, firstForm, firstProof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("first request status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	nonce := headers.Get(dpop.NonceHeaderName)
	if nonce == "" {
		t.Fatal("expected a DPoP-Nonce response header on the challenge")
	}

	retryCode := createDPoPTestAuthCode(t, server)
	retryProof := key.proof(t, http.MethodPost, tokenURL, jwt.MapClaims{"nonce": nonce})
	retryForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {retryCode.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	retryStatus, retryBody := postTokenRequest(t, server.server.URL, retryForm, retryProof)
	if retryStatus != http.StatusOK {
		t.Fatalf("retry status = %d, body = %#v", retryStatus, retryBody)
	}
	if retryBody["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", retryBody["token_type"])
	}
}

func TestTokenEndpointForeignOrStaleNonceIsRejectedAsFreshChallenge(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.plugin.dpopNonceIssuer = dpop.NewNonceIssuer(time.Minute)
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	tokenURL := server.server.URL + "/oauth2/token"
	// A nonce this issuer never handed out -- e.g. one from the RS's
	// independent nonce space (Section 8.2), or simply stale/made up.
	proof := key.proof(t, http.MethodPost, tokenURL, jwt.MapClaims{"nonce": "a-nonce-this-issuer-never-issued"})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body, headers := postTokenRequestCapturingHeaders(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorUseDPoPNonce {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorUseDPoPNonce)
	}
	if headers.Get(dpop.NonceHeaderName) == "" {
		t.Fatal("expected a fresh DPoP-Nonce even when the presented nonce was foreign/stale")
	}
}

func TestTokenEndpointDPoPProofHTUMismatchRejected(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	code := createDPoPTestAuthCode(t, server)
	key := newDPoPTestKey(t)
	// Proof bound to a different endpoint than the one actually called.
	proof := key.proof(t, http.MethodPost, "https://attacker.example/oauth2/token", nil)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code.Code},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {"public-app"},
	}
	status, body := postTokenRequest(t, server.server.URL, form, proof)
	if status != http.StatusBadRequest || body["error"] != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("status = %d, body = %#v, want 400 %s", status, body, dpop.ErrorInvalidDPoPProof)
	}
}

func TestClientCredentialsFlowDefinitionCombinesBearerAndDPoP(t *testing.T) {
	flows := NewPlugin().GetFlowDefinitions()
	var clientCredentials *plugin.FlowDefinition
	for i := range flows {
		switch flows[i].ID {
		case "client_credentials":
			clientCredentials = &flows[i]
		case "client_credentials_dpop":
			t.Fatal("client_credentials_dpop must not be exposed as a duplicate selectable flow")
		}
	}
	if clientCredentials == nil {
		t.Fatal("client_credentials flow definition is missing")
	}

	serialized, err := json.Marshal(clientCredentials)
	if err != nil {
		t.Fatal(err)
	}
	definition := string(serialized)
	for _, required := range []string{
		"client_secret_basic",
		"private_key_jwt",
		"Bearer",
		"DPoP",
		"cnf.jkt",
		"RFC 9449",
	} {
		if !strings.Contains(definition, required) {
			t.Fatalf("combined client_credentials definition does not describe %q", required)
		}
	}
}

func TestDemoClientsPublishesCanonicalTokenEndpointForDPoP(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	response, err := http.Get(server.server.URL + "/oauth2/demo/clients")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	want := server.server.URL + "/oauth2/token"
	if got, _ := body["token_endpoint"].(string); got != want {
		t.Fatalf("token_endpoint = %q, want %q", got, want)
	}
}
