package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestVerifySignatureWithKeyRejectsCriticalHeader proves a JWS that carries
// the "crit" Header Parameter is invalid although its signature is valid: no
// JWS extension is understood and supported here (RFC 7515 Section 4.1.11).
func TestVerifySignatureWithKeyRejectsCriticalHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign := func(critical bool) string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "https://issuer.example"})
		if critical {
			token.Header["crit"] = []string{"urn:example:not-understood"}
			token.Header["urn:example:not-understood"] = true
		}
		signed, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	if valid, err := VerifySignatureWithKey(sign(false), &key.PublicKey); err != nil || !valid {
		t.Fatalf("JWS without crit: valid=%v err=%v, want valid", valid, err)
	}
	valid, err := VerifySignatureWithKey(sign(true), &key.PublicKey)
	if valid || err == nil || !strings.Contains(err.Error(), "RFC 7515 Section 4.1.11") {
		t.Fatalf("JWS with crit: valid=%v err=%v, want the RFC 7515 Section 4.1.11 refusal", valid, err)
	}
}

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

// TestCreateAccessTokenFollowsRFC9068 covers RFC 9068 Section 2: the "typ"
// header is at+jwt, and iss, exp, aud, sub, client_id, iat and jti are
// present. A token with no client, audience or subject is not issued.
func TestCreateAccessTokenFollowsRFC9068(t *testing.T) {
	ks, err := NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewJWTService(ks, "https://as.example")
	token := AccessToken{
		Subject:  "alice",
		Audience: "https://rs.example/api",
		ClientID: "client-abc",
		Scope:    "read",
		Lifetime: time.Minute,
		// A caller's extra claims never replace the ones the profile sets.
		Claims: map[string]interface{}{"aud": "client-abc", "department": "physics"},
	}
	signed, err := svc.CreateAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTokenWithoutValidation(signed)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header["typ"] != "at+jwt" {
		t.Errorf("typ = %v, want at+jwt", decoded.Header["typ"])
	}
	for claim, want := range map[string]interface{}{
		"iss":        "https://as.example",
		"sub":        "alice",
		"aud":        "https://rs.example/api",
		"client_id":  "client-abc",
		"scope":      "read",
		"department": "physics",
	} {
		if decoded.Payload[claim] != want {
			t.Errorf("%s = %v, want %v", claim, decoded.Payload[claim], want)
		}
	}
	for _, required := range []string{"exp", "iat", "jti"} {
		if _, present := decoded.Payload[required]; !present {
			t.Errorf("%s is REQUIRED by RFC 9068 Section 2.2 and is missing", required)
		}
	}

	for name, missing := range map[string]func(*AccessToken){
		"client_id": func(a *AccessToken) { a.ClientID = "" },
		"aud":       func(a *AccessToken) { a.Audience = "" },
		"sub":       func(a *AccessToken) { a.Subject = "" },
	} {
		incomplete := token
		missing(&incomplete)
		if _, err := svc.CreateAccessToken(incomplete); err == nil {
			t.Errorf("an access token without %s was issued", name)
		}
	}
}

// TestValidateAccessTokenRunsEachRFC9068Check covers RFC 9068 Section 4. Each
// refused token is signed by the service's own key and unexpired, so the
// named check is what refuses it.
func TestValidateAccessTokenRunsEachRFC9068Check(t *testing.T) {
	ks, err := NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewJWTService(ks, "https://as.example")
	const issuer, resource = "https://as.example", "https://rs.example/api"
	base := AccessToken{Subject: "alice", Audience: resource, ClientID: "client-abc", Scope: "read", Lifetime: time.Minute}

	accepted, err := svc.CreateAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateAccessToken(accepted, issuer, resource); err != nil {
		t.Fatalf("a conforming token was refused: %v", err)
	}

	untyped, err := svc.CreateUnprofiledAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := svc.CreateRefreshToken("alice", "client-abc", "read", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expired := base
	expired.Lifetime = -time.Minute
	expiredToken, err := svc.CreateAccessToken(expired)
	if err != nil {
		t.Fatal(err)
	}
	otherKeys, err := NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := NewJWTService(otherKeys, issuer).CreateAccessToken(base)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		token, issuer, audience, check string
	}{
		"typ is JWT":                     {untyped, issuer, resource, "typ"},
		"a refresh token":                {refreshToken, issuer, resource, "typ"},
		"iss is another server":          {accepted, "https://as.example/oauth2", resource, "iss"},
		"aud names another resource":     {accepted, issuer, "https://rs.example/other", "aud"},
		"the token has expired":          {expiredToken, issuer, resource, "signature"},
		"the signature is another key's": {forged, issuer, resource, "signature"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.ValidateAccessToken(tc.token, tc.issuer, tc.audience)
			var tokenErr *AccessTokenError
			if !errors.As(err, &tokenErr) {
				t.Fatalf("err = %v, want an *AccessTokenError", err)
			}
			if tokenErr.Check != tc.check {
				t.Fatalf("failed check = %q (%s), want %q", tokenErr.Check, tokenErr.Reason, tc.check)
			}
		})
	}
}

// TestAudienceContains covers the two "aud" shapes of RFC 7519 Section 4.1.3:
// an array of strings, or a single string for one audience.
func TestAudienceContains(t *testing.T) {
	const resource = "https://rs.example/api"
	for name, tc := range map[string]struct {
		aud  interface{}
		want bool
	}{
		"single string":           {resource, true},
		"another single string":   {"https://rs.example/other", false},
		"array naming it":         {[]interface{}{"https://rs.example/other", resource}, true},
		"array not naming it":     {[]interface{}{"https://rs.example/other"}, false},
		"string array":            {[]string{resource}, true},
		"a prefix is not a match": {resource + "/v2", false},
		"absent":                  {nil, false},
	} {
		if got := AudienceContains(tc.aud, resource); got != tc.want {
			t.Errorf("%s: AudienceContains = %v, want %v", name, got, tc.want)
		}
	}
	if AudienceContains("", "") {
		t.Error("an empty expected audience matched")
	}
}
