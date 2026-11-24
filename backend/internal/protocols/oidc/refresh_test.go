package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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

// TestRefreshedAccessTokensStayWithTheirGrant covers the OpenID Provider's
// side of RFC 7009 Section 2.1: "the authorization server SHOULD also
// invalidate all access tokens based on the same authorization grant" when a
// refresh token is revoked. Each access token issued by a refresh request is
// recorded against the rotated refresh token, so revoking the latest refresh
// token invalidates every access token of the chain.
func TestRefreshedAccessTokensStayWithTheirGrant(t *testing.T) {
	p := newTestPlugin(t)
	refresh := func(refreshToken string) models.TokenResponse {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", refreshToken)
		form.Set("client_id", testPublicClient)
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
		return resp
	}

	initial := "refresh-" + time.Now().Format("150405.000000000")
	p.mockIdP.StoreRefreshToken(initial, testPublicClient, testUserID, "openid profile", time.Now(), time.Now().Add(24*time.Hour))
	first := refresh(initial)
	second := refresh(first.RefreshToken)

	var want []string
	for _, accessToken := range []string{first.AccessToken, second.AccessToken} {
		jti, _ := decodeJWTClaims(t, accessToken)["jti"].(string)
		want = append(want, jti)
	}
	if invalidated := p.mockIdP.RevokeRefreshToken(second.RefreshToken); !reflect.DeepEqual(invalidated, want) {
		t.Fatalf("invalidated = %q, want both access tokens of the grant %q", invalidated, want)
	}
	if !p.mockIdP.IsTokenRevoked(first.AccessToken) || !p.mockIdP.IsTokenRevoked(second.AccessToken) {
		t.Fatal("an access token of the revoked grant is still usable")
	}
}

// TestMetadataDocumentsNameEndpointAuthMethods covers the client
// authentication metadata of the issuer's two documents: the RFC 8414
// authorization server metadata and the OpenID Provider configuration. RFC
// 8414 Section 2: each *_endpoint_auth_signing_alg_values_supported entry
// "MUST be present if either of these authentication methods are specified
// in the" matching *_endpoint_auth_methods_supported entry, and
// private_key_jwt is listed for the token endpoint and the revocation
// endpoint. OpenID Connect Discovery 1.0 Section 3 defines the token
// endpoint entries itself and allows the others: "Additional OpenID Provider
// Metadata parameters MAY also be used." Both documents describe the same
// server, so they carry the same values.
func TestMetadataDocumentsNameEndpointAuthMethods(t *testing.T) {
	p := newTestPlugin(t)
	algorithms := []interface{}{"RS256", "ES256", "EdDSA"}
	want := map[string][]interface{}{
		"introspection_endpoint_auth_methods_supported":         {"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":            {"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"revocation_endpoint_auth_signing_alg_values_supported": algorithms,
		"token_endpoint_auth_methods_supported":                 {"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"token_endpoint_auth_signing_alg_values_supported":      algorithms,
	}
	for name, document := range map[string]struct {
		handler http.HandlerFunc
		path    string
	}{
		"RFC 8414 authorization server metadata": {p.handleAuthorizationServerMetadata, authorizationServerWellKnown},
		"OpenID Provider configuration":          {p.handleDiscovery, "/.well-known/openid-configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			document.handler(rr, httptest.NewRequest(http.MethodGet, document.path, nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			for entry, values := range want {
				if got := metadata[entry]; !reflect.DeepEqual(got, values) {
					t.Errorf("%s = %#v, want %#v", entry, got, values)
				}
			}
		})
	}
}
