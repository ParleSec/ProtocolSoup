package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func decodeClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments")
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

func newTestJWT(t *testing.T) *JWTService {
	t.Helper()
	ks, err := NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return NewJWTService(ks, "https://op.example.com")
}

// TestIDTokenRequiredClaims pins OpenID Connect Core 1.0 Section 2: an ID Token
// MUST contain iss, sub, aud, exp, iat (and auth_time as issued here), and
// nonce MUST be echoed only when supplied.
func TestIDTokenRequiredClaims(t *testing.T) {
	svc := newTestJWT(t)
	authTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	token, err := svc.CreateIDToken("user-123", "client-abc", "nonce-xyz", authTime, time.Hour, nil)
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}
	claims := decodeClaims(t, token)

	for _, required := range []string{"iss", "sub", "aud", "exp", "iat", "auth_time"} {
		if _, ok := claims[required]; !ok {
			t.Errorf("ID Token missing required claim %q", required)
		}
	}
	if claims["iss"] != "https://op.example.com" {
		t.Errorf("iss = %v, want issuer", claims["iss"])
	}
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}
	if claims["aud"] != "client-abc" {
		t.Errorf("aud = %v, want client-abc", claims["aud"])
	}
	if claims["nonce"] != "nonce-xyz" {
		t.Errorf("nonce = %v, want echoed nonce-xyz", claims["nonce"])
	}

	// nonce MUST be absent when it was not supplied.
	token2, err := svc.CreateIDToken("user-123", "client-abc", "", authTime, time.Hour, nil)
	if err != nil {
		t.Fatalf("CreateIDToken (no nonce): %v", err)
	}
	if _, present := decodeClaims(t, token2)["nonce"]; present {
		t.Errorf("nonce must be absent when not supplied")
	}
}

// TestIDTokenHashClaims pins OpenID Connect Core 1.0 Section 3.3.2.11: at_hash
// is present when an access token is returned and c_hash when a code is
// returned, each computed as the base64url left-half of the value's hash.
func TestIDTokenHashClaims(t *testing.T) {
	svc := newTestJWT(t)
	authTime := time.Now().Truncate(time.Second)

	accessToken := "test-access-token-value"
	code := "test-authorization-code"

	token, err := svc.CreateIDTokenWithOptions("user-1", "client-1", "n1", authTime, time.Hour, nil, &IDTokenOptions{
		AccessToken:       accessToken,
		AuthorizationCode: code,
	})
	if err != nil {
		t.Fatalf("CreateIDTokenWithOptions: %v", err)
	}
	claims := decodeClaims(t, token)

	atHash, ok := claims["at_hash"].(string)
	if !ok || atHash == "" {
		t.Fatalf("at_hash missing")
	}
	if want := computeHashClaim(accessToken, "RS256"); atHash != want {
		t.Errorf("at_hash = %q, want %q", atHash, want)
	}

	cHash, ok := claims["c_hash"].(string)
	if !ok || cHash == "" {
		t.Fatalf("c_hash missing")
	}
	if want := computeHashClaim(code, "RS256"); cHash != want {
		t.Errorf("c_hash = %q, want %q", cHash, want)
	}

	// Neither hash should appear when its corresponding value is absent.
	plain, err := svc.CreateIDToken("user-1", "client-1", "n1", authTime, time.Hour, nil)
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}
	pc := decodeClaims(t, plain)
	if _, present := pc["at_hash"]; present {
		t.Errorf("at_hash must be absent without an access token")
	}
	if _, present := pc["c_hash"]; present {
		t.Errorf("c_hash must be absent without a code")
	}
}
