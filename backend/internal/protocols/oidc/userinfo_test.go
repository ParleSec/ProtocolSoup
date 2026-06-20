package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
