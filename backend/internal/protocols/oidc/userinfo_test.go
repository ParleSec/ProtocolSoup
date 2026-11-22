package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// TestUserInfoRequiresBearerToken pins OpenID Connect Core 1.0 Section 5.3: the
// UserInfo endpoint MUST be protected, accepting only a valid bearer access
// token, and the returned sub MUST match the token subject.
func TestUserInfoRequiresBearerToken(t *testing.T) {
	p := newTestPlugin(t)

	// No Authorization header is rejected.
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rr.Code)
	}

	// A malformed (non-bearer) scheme is rejected.
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Basic abc")
	rr = httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("non-bearer status = %d, want 401", rr.Code)
	}

	// A garbage bearer token is rejected.
	req = httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr = httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token status = %d, want 401", rr.Code)
	}
}

func TestUserInfoReturnsSubjectForValidToken(t *testing.T) {
	p := newTestPlugin(t)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken(p.accessTokenFor(testUserID, testConfClient, "openid profile email", nil))
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("valid token status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if claims["sub"] != testUserID {
		t.Fatalf("sub = %v, want %q (must match access-token subject)", claims["sub"], testUserID)
	}
}

// userInfoResponse presents accessToken to UserInfo as a Bearer token.
func userInfoResponse(t *testing.T, p *Plugin, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	return rr
}

// TestOIDCAccessTokenFollowsRFC9068 covers RFC 9068 Section 2 for the tokens
// the OP's token endpoint issues: "typ" is at+jwt, "iss" is the issuer that
// discovery publishes, "aud" is UserInfo and "client_id" is the Relying
// Party. UserInfo accepts the token.
func TestOIDCAccessTokenFollowsRFC9068(t *testing.T) {
	p := newTestPlugin(t)
	authCode := &models.AuthorizationCode{}
	authCode.ClientID = testConfClient
	authCode.UserID = testUserID
	authCode.Scope = "openid profile"
	authCode.AuthTime = time.Now()
	resp, err := p.issueOIDCTokens(authCode)
	if err != nil {
		t.Fatalf("issueOIDCTokens: %v", err)
	}

	decoded, err := crypto.DecodeTokenWithoutValidation(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header["typ"] != "at+jwt" {
		t.Errorf("typ = %v, want at+jwt", decoded.Header["typ"])
	}
	if decoded.Payload["iss"] != p.mockIdP.GetIssuer() {
		t.Errorf("iss = %v, want the OP issuer %s", decoded.Payload["iss"], p.mockIdP.GetIssuer())
	}
	if decoded.Payload["aud"] != "https://op.example.com/oidc/userinfo" {
		t.Errorf("aud = %v, want the UserInfo endpoint", decoded.Payload["aud"])
	}
	if decoded.Payload["client_id"] != testConfClient {
		t.Errorf("client_id = %v, want %s", decoded.Payload["client_id"], testConfClient)
	}

	if rr := userInfoResponse(t, p, resp.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("UserInfo status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// TestUserInfoRejectsJWTsThatAreNotItsAccessTokens covers the RFC 9068
// Section 4 checks one at a time. Each token is signed by the OP's own key
// and unexpired, so only the named check can refuse it, with the
// invalid_token error code of RFC 6750 Section 3.1.
func TestUserInfoRejectsJWTsThatAreNotItsAccessTokens(t *testing.T) {
	p := newTestPlugin(t)
	jwtService := p.mockIdP.JWTService()
	base := p.accessTokenFor(testUserID, testConfClient, "openid profile", nil)

	refreshToken, err := jwtService.CreateRefreshToken(testUserID, testConfClient, "openid", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := jwtService.CreateIDToken(testUserID, testConfClient, "", time.Now(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	untyped, err := jwtService.CreateUnprofiledAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer := base
	otherIssuer.Issuer = "https://op.example.com/oauth2"
	fromOtherIssuer, err := jwtService.CreateAccessToken(otherIssuer)
	if err != nil {
		t.Fatal(err)
	}
	otherResource := base
	otherResource.Audience = "https://op.example.com/oauth2/resource"
	forOtherResource, err := jwtService.CreateAccessToken(otherResource)
	if err != nil {
		t.Fatal(err)
	}
	// The previous token shape: the client ID in aud.
	clientAudience := base
	clientAudience.Audience = testConfClient
	forTheClient, err := jwtService.CreateAccessToken(clientAudience)
	if err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]string{
		"a refresh token":                                  refreshToken,
		"an ID Token":                                      idToken,
		"an access token typed JWT":                        untyped,
		"an access token from another issuer":              fromOtherIssuer,
		"an access token whose aud names another resource": forOtherResource,
		"an access token whose aud names the client":       forTheClient,
	} {
		t.Run(name, func(t *testing.T) {
			rr := userInfoResponse(t, p, token)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", rr.Code, rr.Body.String())
			}
			var body map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["error"] != "invalid_token" {
				t.Fatalf("error = %v, want invalid_token", body["error"])
			}
			if challenge := rr.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `error="invalid_token"`) {
				t.Fatalf("WWW-Authenticate = %q, want error=\"invalid_token\"", challenge)
			}
		})
	}
}

// TestOIDCTokenEndpointResourceParameter covers RFC 8707 Section 2 at the
// OP's token endpoint: the OP issues access tokens for UserInfo only, so any
// other "resource" value is refused with invalid_target before the grant is
// touched.
func TestOIDCTokenEndpointResourceParameter(t *testing.T) {
	p := newTestPlugin(t)
	for name, resource := range map[string]string{
		"another resource":      "https://rs.example/api",
		"a relative reference":  "oidc/userinfo",
		"a URI with a fragment": "https://op.example.com/oidc/userinfo#claims",
	} {
		t.Run(name, func(t *testing.T) {
			rr := postTokenForm(t, p, url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"unused"},
				"resource":   {resource},
			}, "", "")
			var body map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rr.Code != http.StatusBadRequest || body["error"] != "invalid_target" {
				t.Fatalf("status = %d, error = %v; want 400 invalid_target", rr.Code, body["error"])
			}
		})
	}

	// Naming UserInfo is accepted: the request proceeds to the grant checks.
	rr := postTokenForm(t, p, url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"unused"},
		"resource":   {"https://op.example.com/oidc/userinfo"},
	}, "", "")
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] == "invalid_target" {
		t.Fatalf("resource naming UserInfo was refused: %#v", body)
	}
}

// TestAuthorizeRejectsUnknownResource covers RFC 8707 Section 2.1 at the
// authorization endpoint: an unacceptable "resource" is returned to the
// client as invalid_target.
func TestAuthorizeRejectsUnknownResource(t *testing.T) {
	p := newTestPlugin(t)
	registerConfClients(t, p)
	rr := doAuthorize(t, p, url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
		"client_id":     {confClientA},
		"redirect_uri":  {suiteURI},
		"state":         {"resource-state"},
		"resource":      {"https://rs.example/api"},
	})
	if rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect: %s", rr.Code, rr.Body.String())
	}
	if got := redirectParam(t, rr.Header().Get("Location"), "error"); got != "invalid_target" {
		t.Fatalf("error = %q, want invalid_target", got)
	}
}
