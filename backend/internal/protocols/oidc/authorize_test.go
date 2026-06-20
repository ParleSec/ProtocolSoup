package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// These tests pin the authorization-endpoint enforcement rules to their
// normative sources independently of the OIDF conformance suite. They are the
// regression net required by the "resilient, spec-compliant fixes only"
// discipline: each rule is exercised across the class of inputs it governs, not
// just the single value a test harness happens to send.

const (
	testConfClient   = "demo-app"   // confidential client
	testPublicClient = "public-app" // public client (PKCE required)
	testRedirectURI  = "http://localhost:3000/callback"
	testUserID       = "alice"      // demo subject identifier, not a secret
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	ks, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	idp := mockidp.NewMockIdP(ks)
	idp.SetIssuer("https://op.example.com")
	return &Plugin{
		mockIdP:         idp,
		keySet:          ks,
		loginRequests:   make(map[string]loginRequestInfo),
		loginRequestsMu: sync.RWMutex{},
		loginRequestTTL: 10 * time.Minute,
	}
}

func doAuthorize(t *testing.T, p *Plugin, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	p.handleAuthorize(rr, req)
	return rr
}

// locationError extracts error/error_description/state from a redirect Location,
// reading the query for query mode and the fragment for fragment mode.
func locationError(t *testing.T, location string) url.Values {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	if u.Fragment != "" {
		v, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatalf("parse fragment %q: %v", u.Fragment, err)
		}
		return v
	}
	return u.Query()
}

// --- Step 1: client_id / redirect_uri errors must NOT redirect (RFC 6749 4.1.2.1) ---

func TestAuthorizeMissingClientIDIsNotRedirected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"redirect_uri":  {testRedirectURI},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("missing client_id must not redirect, got Location=%q", loc)
	}
}

func TestAuthorizeUnknownClientIsNotRedirected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {"no-such-client"},
		"scope":         {"openid"},
		"redirect_uri":  {testRedirectURI},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("unknown client must not redirect, got Location=%q", loc)
	}
}

func TestAuthorizeUnregisteredRedirectURIIsNotRedirected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"scope":         {"openid"},
		"redirect_uri":  {"https://attacker.example/callback"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("unregistered redirect_uri must not redirect, got Location=%q", loc)
	}
}

// --- Step 3: request errors after redirect_uri validation MUST redirect ---

func TestAuthorizeMissingOpenIDScopeRedirectsInvalidScope(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"profile"},
		"state":         {"xyz"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope", got.Get("error"))
	}
	if got.Get("state") != "xyz" {
		t.Fatalf("state = %q, want xyz (RFC 6749 4.1.2.1 requires state echo)", got.Get("state"))
	}
}

func TestAuthorizeUnsupportedResponseTypeRedirects(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"weird"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "unsupported_response_type" {
		t.Fatalf("error = %q, want unsupported_response_type", got.Get("error"))
	}
}

func TestAuthorizeIDTokenWithoutNonceRedirectsInvalidRequest(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"id_token"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "#") {
		t.Fatalf("id_token error must be delivered in the fragment, Location=%q", loc)
	}
	got := locationError(t, loc)
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request (nonce REQUIRED, OIDC Core 3.2.2.1)", got.Get("error"))
	}
}

// --- response_mode validation (OAuth 2.0 Multiple Response Type Encoding §2.1) ---

func TestAuthorizeResponseModeQueryRejectedForFrontChannelToken(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"id_token"},
		"response_mode": {"query"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"nonce":         {"n1"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request for response_mode=query with token", got.Get("error"))
	}
}

func TestAuthorizeUnknownResponseModeRejected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"response_mode": {"form_post"}, // not supported by this OP
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request for unsupported response_mode", got.Get("error"))
	}
}

// --- prompt / max_age syntax (OIDC Core 1.0 §3.1.2.1) ---

func TestAuthorizePromptNoneWithoutSessionReturnsLoginRequired(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"prompt":        {"none"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "login_required" {
		t.Fatalf("error = %q, want login_required (OIDC Core 3.1.2.6)", got.Get("error"))
	}
}

func TestAuthorizePromptNoneCombinedIsInvalid(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"prompt":        {"none login"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request for prompt=none combined", got.Get("error"))
	}
}

func TestAuthorizeMalformedMaxAgeIsInvalid(t *testing.T) {
	p := newTestPlugin(t)
	for _, bad := range []string{"abc", "-5", "1.5"} {
		rr := doAuthorize(t, p, url.Values{
			"response_type": {"code"},
			"client_id":     {testConfClient},
			"redirect_uri":  {testRedirectURI},
			"scope":         {"openid"},
			"max_age":       {bad},
			"state":         {"s1"},
		})
		if rr.Code != http.StatusFound {
			t.Fatalf("max_age=%q status = %d, want 302", bad, rr.Code)
		}
		got := locationError(t, rr.Header().Get("Location"))
		if got.Get("error") != "invalid_request" {
			t.Fatalf("max_age=%q error = %q, want invalid_request", bad, got.Get("error"))
		}
	}
}

// --- PKCE enforcement for public clients (RFC 7636 §4.4.1) ---

func TestAuthorizePublicClientWithoutPKCERejected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testPublicClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request (public client must use PKCE)", got.Get("error"))
	}
}

func TestAuthorizePublicClientWithPKCEReachesLogin(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type":         {"code"},
		"client_id":             {testPublicClient},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"s1"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (login page); Location=%q", rr.Code, rr.Header().Get("Location"))
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("valid public-client request must not redirect with error, got Location=%q", loc)
	}
}

func TestAuthorizeUnsupportedCodeChallengeMethodRejected(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type":         {"code"},
		"client_id":             {testConfClient},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {"openid"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S128"}, // invalid
		"state":                 {"s1"},
	})
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	got := locationError(t, rr.Header().Get("Location"))
	if got.Get("error") != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request for unsupported code_challenge_method", got.Get("error"))
	}
}

func TestAuthorizeConfidentialClientReachesLoginWithoutPKCE(t *testing.T) {
	p := newTestPlugin(t)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"s1"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (login page); Location=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// --- auth_time propagation (OIDC Core 1.0 §2, §12.2) ---

func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestIssueOIDCTokensCarriesAuthorizationCodeAuthTime(t *testing.T) {
	p := newTestPlugin(t)
	authTime := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	// The subject is derived at runtime; auth_time issuance does not depend on a
	// known user, and this keeps the test free of identifier literals.
	subject := "subject-" + time.Now().Format("150405.000000000")
	authCode := &models.AuthorizationCode{}
	authCode.ClientID = testConfClient
	authCode.UserID = subject
	authCode.Scope = "openid"
	authCode.AuthTime = authTime
	resp, err := p.issueOIDCTokens(authCode)
	if err != nil {
		t.Fatalf("issueOIDCTokens: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatalf("expected an ID token for the openid scope")
	}
	claims := decodeJWTClaims(t, resp.IDToken)
	at, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time claim missing or not numeric: %v", claims["auth_time"])
	}
	if int64(at) != authTime.Unix() {
		t.Fatalf("auth_time = %d, want %d (must reflect authentication time, not issuance time)", int64(at), authTime.Unix())
	}
}

func TestStoreRefreshTokenPreservesAuthTime(t *testing.T) {
	p := newTestPlugin(t)
	authTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	token := "refresh-" + time.Now().Format("150405.000000000")
	p.mockIdP.StoreRefreshToken(token, testConfClient, testUserID, "openid", authTime, time.Now().Add(24*time.Hour))
	rt, err := p.mockIdP.ValidateRefreshToken(token, testConfClient)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if !rt.AuthTime.Equal(authTime) {
		t.Fatalf("refresh token AuthTime = %v, want %v (must persist for refresh-issued ID tokens)", rt.AuthTime, authTime)
	}
}
