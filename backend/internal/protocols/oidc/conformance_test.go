package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

var loginRequestIDRe = regexp.MustCompile(`name="login_request_id" value="([^"]+)"`)

// extractLoginRequestID pulls the hidden login_request_id field from the login
// page so a test can complete the interactive flow end to end.
func extractLoginRequestID(t *testing.T, html string) string {
	t.Helper()
	m := loginRequestIDRe.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("could not find login_request_id in login page")
	}
	return m[1]
}

// redirectParam reads a parameter from a redirect Location, looking in both the
// query and the fragment.
func redirectParam(t *testing.T, location, key string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	if v := u.Query().Get(key); v != "" {
		return v
	}
	if u.Fragment != "" {
		if f, err := url.ParseQuery(u.Fragment); err == nil {
			return f.Get(key)
		}
	}
	return ""
}

// TestFullCodeFlowClaimsPlacement drives the real HTTP path the OIDF suite
// exercises (authorize -> interactive login -> token -> UserInfo) and asserts
// the OIDC Core 1.0 Section 5.4 split: scope claims appear in UserInfo, not the
// ID Token. It reproduces VerifyScopesReturnedInUserInfoClaims and
// EnsureUserInfoContainsName against the genuine flow rather than a minted token.
func TestFullCodeFlowClaimsPlacement(t *testing.T) {
	p := newTestPlugin(t)

	alice, ok := p.mockIdP.GetUser(testUserID)
	if !ok {
		t.Fatalf("seeded user %q not found", testUserID)
	}
	client, ok := p.mockIdP.GetClient(testConfClient)
	if !ok {
		t.Fatalf("seeded client %q not found", testConfClient)
	}

	// 1. Authorization request (GET) -> login page.
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid profile email"},
		"state":         {"st-1"},
		"nonce":         {"nonce-1"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("authorize status = %d; body=%s", rr.Code, rr.Body.String())
	}
	loginReqID := extractLoginRequestID(t, rr.Body.String())

	// 2. Interactive login (POST) -> redirect carrying the code and echoed state.
	loginForm := url.Values{
		"email":            {alice.Email},
		"password":         {alice.Password},
		"login_request_id": {loginReqID},
	}
	lreq := httptest.NewRequest(http.MethodPost, "/oidc/authorize", strings.NewReader(loginForm.Encode()))
	lreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lrr := httptest.NewRecorder()
	p.handleAuthorizePost(lrr, lreq)
	if lrr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body=%s", lrr.Code, lrr.Body.String())
	}
	loc := lrr.Header().Get("Location")
	if got := redirectParam(t, loc, "state"); got != "st-1" {
		t.Fatalf("state = %q, want st-1 (Location=%s)", got, loc)
	}
	code := redirectParam(t, loc, "code")
	if code == "" {
		t.Fatalf("no authorization code in redirect %q", loc)
	}

	// 3. Token exchange (confidential client, HTTP Basic).
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
	}
	tr := postTokenForm(t, p, tokenForm, testConfClient, client.Secret)
	if tr.Code != http.StatusOK {
		t.Fatalf("token status = %d; body=%s", tr.Code, tr.Body.String())
	}
	tokenResp := decodeJSONObject(t, tr.Body.Bytes())
	accessToken, _ := tokenResp["access_token"].(string)
	idToken, _ := tokenResp["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("missing tokens in response: %v", keysOf(tokenResp))
	}

	// ID Token: nonce echoed, scope claims absent (an access token was issued).
	idClaims := decodeJWTClaims(t, idToken)
	if idClaims["nonce"] != "nonce-1" {
		t.Fatalf("id_token nonce = %v, want nonce-1", idClaims["nonce"])
	}
	for _, leaked := range []string{"email", "name", "given_name", "family_name"} {
		if _, present := idClaims[leaked]; present {
			t.Fatalf("id_token must not carry %q in the code flow (OIDC Core 5.4)", leaked)
		}
	}
	// The authentication context performed (single-factor password) is reported
	// truthfully (OIDC Core 1.0 Section 2, RFC 8176).
	if idClaims["acr"] != acrSingleFactorLogin {
		t.Fatalf("id_token acr = %v, want %q", idClaims["acr"], acrSingleFactorLogin)
	}
	if amr, ok := idClaims["amr"].([]interface{}); !ok || len(amr) != 1 || amr[0] != "pwd" {
		t.Fatalf("id_token amr = %v, want [pwd]", idClaims["amr"])
	}

	// 4. UserInfo: must carry the scope claims withheld from the ID Token.
	ureq := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	ureq.Header.Set("Authorization", "Bearer "+accessToken)
	urr := httptest.NewRecorder()
	p.handleUserInfo(urr, ureq)
	if urr.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d; body=%s", urr.Code, urr.Body.String())
	}
	uClaims := decodeJSONObject(t, urr.Body.Bytes())
	for _, want := range []string{"sub", "name", "given_name", "family_name", "email", "email_verified"} {
		if _, ok := uClaims[want]; !ok {
			t.Fatalf("userinfo missing %q for scope=openid profile email; got %v", want, keysOf(uClaims))
		}
	}
}

// TestClaimsParameterCodeFlowReturnsNameFromUserInfo reproduces the OIDF
// oidcc-claims-essential module for the code flow: scope is openid (no profile)
// and the claims parameter requests name as essential in userinfo. The OP must
// return name from UserInfo (EnsureUserInfoContainsName) and must NOT place it
// in the ID Token because an access token is issued (EnsureIdTokenDoesNotContainName,
// OIDC Core 1.0 Section 5.4/5.5). It drives the full HTTP path the suite uses.
func TestClaimsParameterCodeFlowReturnsNameFromUserInfo(t *testing.T) {
	p := newTestPlugin(t)

	alice, ok := p.mockIdP.GetUser(testUserID)
	if !ok {
		t.Fatalf("seeded user %q not found", testUserID)
	}
	client, ok := p.mockIdP.GetClient(testConfClient)
	if !ok {
		t.Fatalf("seeded client %q not found", testConfClient)
	}

	// 1. Authorization request carrying the claims parameter -> login page.
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"st-claims"},
		"nonce":         {"nonce-claims"},
		"claims":        {`{"userinfo":{"name":{"essential":true}}}`},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("authorize status = %d; body=%s", rr.Code, rr.Body.String())
	}
	loginReqID := extractLoginRequestID(t, rr.Body.String())

	// 2. Interactive login -> redirect with the code.
	loginForm := url.Values{
		"email":            {alice.Email},
		"password":         {alice.Password},
		"login_request_id": {loginReqID},
	}
	lreq := httptest.NewRequest(http.MethodPost, "/oidc/authorize", strings.NewReader(loginForm.Encode()))
	lreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lrr := httptest.NewRecorder()
	p.handleAuthorizePost(lrr, lreq)
	if lrr.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body=%s", lrr.Code, lrr.Body.String())
	}
	code := redirectParam(t, lrr.Header().Get("Location"), "code")
	if code == "" {
		t.Fatalf("no authorization code in redirect %q", lrr.Header().Get("Location"))
	}

	// 3. Token exchange.
	tr := postTokenForm(t, p, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
	}, testConfClient, client.Secret)
	if tr.Code != http.StatusOK {
		t.Fatalf("token status = %d; body=%s", tr.Code, tr.Body.String())
	}
	tokenResp := decodeJSONObject(t, tr.Body.Bytes())
	accessToken, _ := tokenResp["access_token"].(string)
	idToken, _ := tokenResp["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("missing tokens in response: %v", keysOf(tokenResp))
	}

	// The userinfo-requested claim must not be in the ID Token.
	if _, present := decodeJWTClaims(t, idToken)["name"]; present {
		t.Fatalf("ID token must not contain name when requested for userinfo (OIDC Core 5.4/5.5)")
	}

	// 4. UserInfo must return the requested name, sourced from the user record.
	ureq := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	ureq.Header.Set("Authorization", "Bearer "+accessToken)
	urr := httptest.NewRecorder()
	p.handleUserInfo(urr, ureq)
	if urr.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d; body=%s", urr.Code, urr.Body.String())
	}
	uClaims := decodeJSONObject(t, urr.Body.Bytes())
	if got, _ := uClaims["name"].(string); got != alice.Name {
		t.Fatalf("userinfo name = %q, want %q (requested via claims parameter)", got, alice.Name)
	}
}

// TestClaimsParameterIDTokenMemberReturnsNameInIDToken covers the id_token
// response-type variant of oidcc-claims-essential: name is requested in the
// id_token member, no access token is issued, so the claim must appear in the
// ID Token (EnsureIdTokenContainsName, OIDC Core 1.0 Section 5.5).
func TestClaimsParameterIDTokenMemberReturnsNameInIDToken(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	alice, ok := p.mockIdP.GetUser(testUserID)
	if !ok {
		t.Fatalf("seeded user %q not found", testUserID)
	}

	params := authParams{
		ClientID:     confClientA,
		RedirectURI:  suiteURI,
		Scope:        "openid",
		State:        "st-i",
		Nonce:        "nonce-i",
		ResponseType: "id_token",
		ResponseMode: "fragment",
		Claims:       `{"id_token":{"name":{"essential":true}}}`,
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	rr := httptest.NewRecorder()
	p.issueAuthorizationResponse(rr, req, "sess", params, testUserID, time.Now())
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	idToken := redirectParam(t, rr.Header().Get("Location"), "id_token")
	if idToken == "" {
		t.Fatalf("no id_token in redirect %q", rr.Header().Get("Location"))
	}
	if got, _ := decodeJWTClaims(t, idToken)["name"].(string); got != alice.Name {
		t.Fatalf("id_token name = %q, want %q (requested via claims parameter)", got, alice.Name)
	}
}

// TestAuthorizationRejectsMalformedClaims pins OIDC Core 1.0 Section 5.5: a
// claims parameter that is not a valid JSON object is invalid_request, delivered
// by redirect with the state echoed, rather than being silently ignored.
func TestAuthorizationRejectsMalformedClaims(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {confClientA},
		"redirect_uri":  {suiteURI},
		"state":         {"st-bad"},
		"claims":        {"not-json"},
	})
	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected a redirect carrying invalid_request; body=%s", rr.Body.String())
	}
	if got := redirectParam(t, loc, "error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request (Location=%s)", got, loc)
	}
	if got := redirectParam(t, loc, "state"); got != "st-bad" {
		t.Fatalf("state = %q, want st-bad", got)
	}
}

// decodeJSONObject decodes a JSON object response body for assertions.
func decodeJSONObject(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode JSON object: %v; body=%s", err, string(body))
	}
	return obj
}

// keysOf returns the sorted keys of a claim map for readable failure messages.
func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// These tests pin the behaviour the OIDF OP conformance suite depends on for
// static-client Basic/Implicit/Hybrid runs: the suite callback must be accepted
// as an exact registered redirect URI, authorization codes must be bound to the
// issuing client (the suite verifies this with a second client), and
// token-endpoint client-authentication failures must follow RFC 6749 Section
// 5.2. They are independent of the suite so a regression is caught before a
// paid certification run.

const (
	confClientA = "conformance-client"
	confClientB = "conformance-client-2"
	confSecret  = "conformance-secret-value"
	suiteURI    = "https://localhost.emobix.co.uk:8443/test/a/protocolsoup-basic/callback"
)

func registerConfClients(t *testing.T, p *Plugin) {
	t.Helper()
	for _, id := range []string{confClientA, confClientB} {
		p.mockIdP.RegisterClient(&models.Client{
			ID:           id,
			Secret:       confSecret,
			Name:         "OIDF Conformance Client",
			RedirectURIs: []string{suiteURI},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       []string{"openid", "profile", "email"},
			Public:       false,
		})
	}
}

func postTokenForm(t *testing.T, p *Plugin, form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	rr := httptest.NewRecorder()
	p.handleToken(rr, req)
	return rr
}

func userInfoStatus(t *testing.T, p *Plugin, accessToken string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	return rr.Code
}

// The suite callback is registered exactly; the authorization endpoint must
// accept it and present the login page rather than the no-redirect error page.
func TestConformanceSuiteRedirectURIAccepted(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {confClientA},
		"redirect_uri":  {suiteURI},
		"state":         {"xyz"},
	})

	body := rr.Body.String()
	if strings.Contains(body, "cannot continue and will not redirect") {
		t.Fatalf("registered suite redirect URI was rejected as invalid; body=%s", body)
	}
	if !strings.Contains(body, `name="login_request_id"`) {
		t.Fatalf("expected the login page for a valid request, got: %s", body)
	}
}

// A redirect URI that is not registered must be rejected without redirecting
// (RFC 6749 Section 3.1.2.3 exact match, Section 4.1.2.1 no redirect on a bad
// redirect_uri).
func TestConformanceUnregisteredRedirectURIRejected(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {confClientA},
		"redirect_uri":  {suiteURI + "?injected=1"},
	})

	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("an unregistered redirect_uri must not redirect, got Location=%q", loc)
	}
	if !strings.Contains(rr.Body.String(), "cannot continue and will not redirect") {
		t.Fatalf("expected the no-redirect error page for an unregistered redirect_uri")
	}
}

// An authorization code issued to one client MUST NOT be redeemable by another
// client, even when that other client authenticates correctly. The suite tests
// this with its second static client.
func TestAuthorizationCodeBoundToIssuingClient(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	code, err := p.mockIdP.CreateAuthorizationCode(
		confClientA, testUserID, suiteURI, "openid", "state-1", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code.Code)
	form.Set("redirect_uri", suiteURI)

	// Redeem as client B (authenticating correctly as itself) — must be refused.
	rr := postTokenForm(t, p, form, confClientB, confSecret)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant for cross-client code reuse; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant, got: %s", rr.Body.String())
	}
}

// RFC 6749 Section 4.1.2: replaying an authorization code MUST be denied
// (invalid_grant) and SHOULD revoke the tokens already issued from it. The OIDF
// oidcc-codereuse module verifies the revocation by re-calling the resource
// (UserInfo) endpoint with the first access token and expecting a 4xx. This
// test pins the full negative path: redeem once, confirm UserInfo works, replay
// the code, then confirm the original access token is now rejected at UserInfo.
func TestAuthorizationCodeReplayRevokesAccessToken(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	authCode, err := p.mockIdP.CreateAuthorizationCode(
		confClientA, testUserID, suiteURI, "openid profile", "state-x", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authCode.Code)
	form.Set("redirect_uri", suiteURI)

	// First redemption succeeds and yields an access token.
	rr := postTokenForm(t, p, form, confClientA, confSecret)
	if rr.Code != http.StatusOK {
		t.Fatalf("first redemption status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	tokens := decodeJSONObject(t, rr.Body.Bytes())
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("expected an access_token in the token response; got %v", keysOf(tokens))
	}

	// The freshly issued token works at the resource (UserInfo) endpoint.
	if code := userInfoStatus(t, p, accessToken); code != http.StatusOK {
		t.Fatalf("UserInfo before replay = %d, want 200", code)
	}

	// Replaying the code MUST be denied with invalid_grant (RFC 6749 4.1.2).
	replay := postTokenForm(t, p, form, confClientA, confSecret)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400 invalid_grant; body=%s", replay.Code, replay.Body.String())
	}
	if !strings.Contains(replay.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant on replay, got: %s", replay.Body.String())
	}

	// The token minted from the now-replayed code MUST be rejected at the
	// resource endpoint (the SHOULD-level revocation the suite checks).
	if code := userInfoStatus(t, p, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("UserInfo after replay = %d, want 401 invalid_token", code)
	}
}

// When the flow issues an access token (the code flow always does), the
// scope-requested claims are served from the UserInfo endpoint, and the ID
// Token carries only authentication claims (OIDC Core 1.0 Section 5.4). The
// OIDF suite enforces this with EnsureIdTokenDoesNotContainEmailForScopeEmail.
// Non-standard attributes (the demo "department") must never appear either
// (EnsureIdTokenDoesNotContainNonRequestedClaims).
func TestCodeFlowIDTokenOmitsScopeAndCustomClaims(t *testing.T) {
	p := newTestPlugin(t)

	// testUserID is a seeded demo user carrying a custom "department" attribute
	// and a populated profile/email.
	authCode := &models.AuthorizationCode{}
	authCode.ClientID = testConfClient
	authCode.UserID = testUserID
	authCode.Scope = "openid profile email"
	authCode.AuthTime = time.Now()

	resp, err := p.issueOIDCTokens(authCode)
	if err != nil {
		t.Fatalf("issueOIDCTokens: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatalf("expected an ID token for the openid scope")
	}

	claims := decodeJWTClaims(t, resp.IDToken)

	if claims["sub"] != testUserID {
		t.Fatalf("sub = %v, want %q", claims["sub"], testUserID)
	}
	// Scope-requested claims belong in UserInfo, not the ID Token, because an
	// access token was issued.
	for _, leaked := range []string{"email", "email_verified", "name", "given_name", "family_name", "department"} {
		if _, present := claims[leaked]; present {
			t.Fatalf("code-flow ID token must not carry %q when an access token is issued (OIDC Core 5.4): %v", leaked, claims[leaked])
		}
	}
}

// Counterpart to the rule above: the claims withheld from the ID Token MUST be
// retrievable from the UserInfo endpoint using the access token's scope (OIDC
// Core 1.0 Section 5.3/5.4). This proves the claims were relocated, not lost,
// and pins EnsureUserInfoContainsName / VerifyScopesReturnedInUserInfoClaims.
func TestUserInfoReturnsScopeClaims(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(
		testUserID, testConfClient, "openid profile email", time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	claims := decodeJSONObject(t, rr.Body.Bytes())
	if claims["sub"] != testUserID {
		t.Fatalf("sub = %v, want %q", claims["sub"], testUserID)
	}
	for _, want := range []string{"name", "email", "email_verified"} {
		if _, ok := claims[want]; !ok {
			t.Fatalf("UserInfo missing %q for the requested scopes; got %v", want, keysOf(claims))
		}
	}
}

// TestUserInfoReturnsFullProfileScopeClaims pins OIDC Core 1.0 Section 5.4: the
// profile scope returns the full profile standard-claim set from UserInfo. This
// is exactly the set the OIDF VerifyScopesReturnedInUserInfoClaims condition
// (oidcc-scope-profile) checks. Each claim is sourced from the user record, not
// synthesised, so the values are genuine profile data for the demo persona.
func TestUserInfoReturnsFullProfileScopeClaims(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(
		testUserID, testConfClient, "openid profile", time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	claims := decodeJSONObject(t, rr.Body.Bytes())
	// The full OIDC Core 1.0 Section 5.4 profile claim set; the demo users
	// populate every one, so all must be present.
	for _, want := range []string{
		"sub", "name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	} {
		if _, ok := claims[want]; !ok {
			t.Fatalf("UserInfo missing profile claim %q; got %v", want, keysOf(claims))
		}
	}
}

// TestUserInfoReturnsAddressAndPhoneScopeClaims pins OIDC Core 1.0 Section 5.1
// and 5.1.1 for the address and phone scopes. These back oidcc-scope-address,
// oidcc-scope-phone, and oidcc-scope-all: VerifyScopesReturnedInUserInfoClaims
// expects address for the address scope and both phone_number and
// phone_number_verified for the phone scope, while ValidateUserInfoStandardClaims
// requires the address claim to be a JSON object of non-blank string members,
// phone_number a string, and phone_number_verified a boolean. Every value is
// sourced from the user record, not synthesised.
func TestUserInfoReturnsAddressAndPhoneScopeClaims(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(
		testUserID, testConfClient, "openid address phone", time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	claims := decodeJSONObject(t, rr.Body.Bytes())

	// phone scope: phone_number (string) and phone_number_verified (boolean).
	if phone, _ := claims["phone_number"].(string); phone == "" {
		t.Fatalf("UserInfo missing phone_number string for the phone scope; got %v", keysOf(claims))
	}
	if _, ok := claims["phone_number_verified"].(bool); !ok {
		t.Fatalf("phone_number_verified must be a boolean; got %T (%v)", claims["phone_number_verified"], claims["phone_number_verified"])
	}

	// address scope: a JSON object with non-blank string members (Section 5.1.1).
	addr, ok := claims["address"].(map[string]interface{})
	if !ok {
		t.Fatalf("address claim must be a JSON object; got %T (%v)", claims["address"], claims["address"])
	}
	if len(addr) == 0 {
		t.Fatalf("address claim must not be an empty object")
	}
	for member, value := range addr {
		s, ok := value.(string)
		if !ok || strings.TrimSpace(s) == "" {
			t.Fatalf("address.%s must be a non-blank string (suite ValidateUserInfoStandardClaims); got %T (%v)", member, value, value)
		}
	}
	// At least the structured locality/country should be present for the demo
	// persona, confirming the value is real rather than a placeholder.
	if _, ok := addr["country"]; !ok {
		t.Fatalf("address claim missing country; got %v", keysOf(addr))
	}
}

// RFC 6750 Section 2.2 / OIDC Core 1.0 Section 5.3.1: the UserInfo endpoint must
// accept the access token in a form-encoded POST body (access_token parameter),
// not only in the Authorization header. The OIDF suite checks this with
// UserInfoEndpointWithAccessTokenInBodyNotSupported.
func TestUserInfoAcceptsAccessTokenInPostBody(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(
		testUserID, testConfClient, "openid email", time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	form := url.Values{"access_token": {accessToken}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/userinfo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for body-borne access token; body=%s", rr.Code, rr.Body.String())
	}
	claims := decodeJSONObject(t, rr.Body.Bytes())
	if claims["sub"] != testUserID {
		t.Fatalf("sub = %v, want %q", claims["sub"], testUserID)
	}
	if _, ok := claims["email"]; !ok {
		t.Fatalf("UserInfo (POST body) missing email for the email scope; got %v", keysOf(claims))
	}
}

// RFC 6750 Section 2: a client MUST NOT transmit the access token by more than
// one method in a single request. Presenting both a header and a body token is
// an invalid_request.
func TestUserInfoRejectsMultipleTokenMethods(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(
		testUserID, testConfClient, "openid", time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	form := url.Values{"access_token": {accessToken}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/userinfo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_request for two token methods; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid_request") {
		t.Fatalf("expected invalid_request, got: %s", rr.Body.String())
	}
}

// OIDC Core 1.0 Section 3.1.2.1: the authorization endpoint MUST accept requests
// by HTTP POST. A POST carrying authorization parameters (and no login form
// fields) is an authorization request and must be handled like GET, presenting
// the login page rather than the "Missing login request" error from the login
// submission path. Pins oidcc-ensure-post-request-succeeds.
func TestAuthorizationEndpointAcceptsPost(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	form := url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {confClientA},
		"redirect_uri":  {suiteURI},
		"state":         {"post-state"},
		"nonce":         {"post-nonce"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleAuthorizePost(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "Missing login request") {
		t.Fatalf("POST authorization request was mis-routed to the login submission path: %s", body)
	}
	if !strings.Contains(body, `name="login_request_id"`) {
		t.Fatalf("expected the login page for a valid POST authorization request, got: %s", body)
	}
}

// OIDC Core 1.0 Section 2 / OIDCC-3.1.2.1 / OIDCC-15.1: when a client requests
// an authentication context via acr_values, the OP returns an acr claim
// reflecting the authentication actually performed. The OP advertises its single
// genuine context in acr_values_supported, so a request for that value is
// satisfied and returned (this is what oidcc-ensure-request-with-acr-values
// checks). The value is never a requested assurance level the OP cannot meet.
func TestAcrValuesReturnsAdvertisedContext(t *testing.T) {
	p := newTestPlugin(t)

	// Discovery advertises the single supported acr value plus acr/amr as
	// claims, so a client can request the context and know it is returnable. The
	// code-flow ID Token actually carrying acr/amr is asserted end to end by
	// TestFullCodeFlowClaimsPlacement.
	dreq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	drr := httptest.NewRecorder()
	p.handleDiscovery(drr, dreq)
	disc := decodeJSONObject(t, drr.Body.Bytes())

	acrValues, _ := disc["acr_values_supported"].([]interface{})
	if len(acrValues) != 1 || acrValues[0] != acrSingleFactorLogin {
		t.Fatalf("acr_values_supported = %v, want [%q]", disc["acr_values_supported"], acrSingleFactorLogin)
	}
	claimsSupported, _ := disc["claims_supported"].([]interface{})
	for _, want := range []string{"acr", "amr"} {
		found := false
		for _, c := range claimsSupported {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("claims_supported must include %q, got %v", want, claimsSupported)
		}
	}
}

// OIDC Core 1.0 Section 6.2.1 / 6.3.1: an OP that does not support the request
// or request_uri parameter MUST reject a request carrying it with
// request_not_supported / request_uri_not_supported, delivered to the validated
// redirect URI. This is what makes
// oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported
// pass via the "rejected as unsupported" branch, and it prevents the parameter
// from being silently ignored (which would strip the scope/state/nonce the
// suite carries inside the object).
func TestAuthorizationRejectsRequestObject(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	cases := []struct {
		name    string
		param   string
		value   string
		wantErr string
	}{
		{"request by value", "request", "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCBwcm9maWxlIn0.", "request_not_supported"},
		{"request_uri", "request_uri", "https://client.example.com/request.jwt", "request_uri_not_supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := url.Values{
				"response_type": {"code"},
				"scope":         {"openid"},
				"client_id":     {confClientA},
				"redirect_uri":  {suiteURI},
				"state":         {"req-obj-state"},
			}
			params.Set(tc.param, tc.value)
			rr := doAuthorize(t, p, params)

			if rr.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 error redirect; body=%s", rr.Code, rr.Body.String())
			}
			loc := rr.Header().Get("Location")
			vals := locationError(t, loc)
			if vals.Get("error") != tc.wantErr {
				t.Fatalf("error = %q, want %q (Location=%s)", vals.Get("error"), tc.wantErr, loc)
			}
			if vals.Get("state") != "req-obj-state" {
				t.Fatalf("state = %q, want it echoed on the error", vals.Get("state"))
			}
		})
	}
}

// RFC 6749 Section 5.2: when a client authenticates with HTTP Basic and that
// authentication fails, the response is 401 with a matching
// "WWW-Authenticate: Basic" challenge, and never a Bearer challenge (the token
// endpoint is not a protected resource).
func TestTokenEndpointInvalidClientReturnsBasicChallenge(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "irrelevant")
	form.Set("redirect_uri", suiteURI)

	rr := postTokenForm(t, p, form, confClientA, "wrong-secret")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 invalid_client; body=%s", rr.Code, rr.Body.String())
	}
	challenge := rr.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Basic") {
		t.Fatalf("WWW-Authenticate = %q, want a Basic challenge (RFC 6749 5.2)", challenge)
	}
	if strings.Contains(challenge, "Bearer") {
		t.Fatalf("token-endpoint client-auth failure must not emit a Bearer challenge: %q", challenge)
	}
	if !strings.Contains(rr.Body.String(), "invalid_client") {
		t.Fatalf("expected invalid_client error body, got: %s", rr.Body.String())
	}
}

// Token-endpoint grant errors (here invalid_grant) MUST NOT carry any
// WWW-Authenticate challenge; that header is only for client-authentication
// failures via the Authorization header.
func TestTokenEndpointInvalidGrantHasNoChallenge(t *testing.T) {
	p := newTestPlugin(t)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "does-not-exist")
	form.Set("redirect_uri", testRedirectURI)
	form.Set("client_id", testPublicClient) // public client: no client secret required

	rr := postTokenForm(t, p, form, "", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_grant; body=%s", rr.Code, rr.Body.String())
	}
	if challenge := rr.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Fatalf("invalid_grant must not set WWW-Authenticate, got %q", challenge)
	}
	if !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant error body, got: %s", rr.Body.String())
	}
}
