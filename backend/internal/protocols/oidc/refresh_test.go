package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// TestRefreshIDTokenPreservesAuthTimeAndOmitsNonce pins OpenID Connect Core 1.0
// Section 12.2: an ID Token issued from a refresh request carries the original
// auth_time (the End-User did not re-authenticate), and nonce is omitted, which
// is permitted because the section only constrains nonce when it is present.
//
// The public client path is used so the test does not depend on a generated
// client secret; the refresh grant treats public and confidential clients
// identically for ID Token construction.
func TestRefreshIDTokenPreservesAuthTimeAndOmitsNonce(t *testing.T) {
	p := newTestPlugin(t)

	authTime := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	token := "refresh-" + time.Now().Format("150405.000000000")
	p.mockIdP.StoreRefreshToken(token, testPublicClient, testUserID, "openid profile", authTime, time.Now().Add(24*time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)
	form.Set("client_id", testPublicClient)
	form.Set("scope", "openid")

	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	rr := httptest.NewRecorder()
	p.handleRefreshTokenGrant(rr, req, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var resp models.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatalf("refresh with openid scope must return an ID token")
	}

	claims := decodeJWTClaims(t, resp.IDToken)

	at, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing or not numeric: %v", claims["auth_time"])
	}
	if int64(at) != authTime.Unix() {
		t.Fatalf("refreshed auth_time = %d, want original %d (OIDC Core 12.2)", int64(at), authTime.Unix())
	}

	if _, present := claims["nonce"]; present {
		t.Fatalf("refreshed ID token must not invent a nonce; got %v", claims["nonce"])
	}
}
