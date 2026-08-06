package oauth2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

type assertionSigner struct {
	alg        string
	kid        string
	privateKey interface{}
	method     jwt.SigningMethod
	jwk        internalcrypto.JWK
}

func newAssertionSigner(t *testing.T, alg, kid string) assertionSigner {
	t.Helper()
	switch alg {
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return assertionSigner{
			alg: alg, kid: kid, privateKey: privateKey, method: jwt.SigningMethodRS256,
			jwk: internalcrypto.JWKFromRSAPublicKey(&privateKey.PublicKey, kid),
		}
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return assertionSigner{
			alg: alg, kid: kid, privateKey: privateKey, method: jwt.SigningMethodES256,
			jwk: internalcrypto.JWKFromECPublicKey(&privateKey.PublicKey, kid),
		}
	case "EdDSA":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return assertionSigner{
			alg: alg, kid: kid, privateKey: privateKey, method: jwt.SigningMethodEdDSA,
			jwk: internalcrypto.JWKFromEd25519PublicKey(publicKey, kid),
		}
	default:
		t.Fatalf("unsupported test signing algorithm %q", alg)
		return assertionSigner{}
	}
}

func (s assertionSigner) sign(t *testing.T, claims map[string]interface{}, headerAlg string) string {
	t.Helper()
	headers := map[string]interface{}{"kid": s.kid}
	if headerAlg != "" {
		headers["alg"] = headerAlg
	}
	return s.signWithHeaders(t, claims, headers)
}

func (s assertionSigner) signWithHeaders(
	t *testing.T,
	claims map[string]interface{},
	headers map[string]interface{},
) string {
	t.Helper()
	token := jwt.NewWithClaims(s.method, jwt.MapClaims(claims))
	for name, value := range headers {
		token.Header[name] = value
	}
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func unsignedAssertion(t *testing.T, claims map[string]interface{}, alg, kid string) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]interface{}{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."
}

func validAssertionClaims(now time.Time, clientID, audience, jti string) map[string]interface{} {
	return map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti,
	}
}

type oauthAssertionTestServer struct {
	plugin *Plugin
	idp    *mockidp.MockIdP
	engine *lookingglass.Engine
	server *httptest.Server
	now    *time.Time
}

type failingClientAssertionReplayStore struct{}

func (failingClientAssertionReplayStore) Reserve(
	context.Context,
	string,
	string,
	time.Time,
	time.Time,
) (bool, error) {
	return false, errors.New("replay store unavailable")
}

func (failingClientAssertionReplayStore) Close() error {
	return nil
}

func newOAuthAssertionTestServer(t *testing.T) *oauthAssertionTestServer {
	t.Helper()
	keySet, err := internalcrypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	engine := lookingglass.NewEngine()
	plugin := NewPlugin()
	fixedNow := time.Now().UTC().Truncate(time.Second)
	plugin.mockIdP = idp
	plugin.keySet = keySet
	plugin.lookingGlass = engine
	plugin.now = func() time.Time { return fixedNow }

	router := chi.NewRouter()
	protocolRouter := chi.NewRouter()
	plugin.RegisterRoutes(protocolRouter)
	router.Mount("/oauth2", protocolRouter)
	server := httptest.NewServer(router)
	plugin.baseURL = server.URL
	idp.SetIssuer(server.URL)

	t.Cleanup(server.Close)
	return &oauthAssertionTestServer{
		plugin: plugin,
		idp:    idp,
		engine: engine,
		server: server,
		now:    &fixedNow,
	}
}

func createOwnedOAuthSession(
	t *testing.T,
	engine *lookingglass.Engine,
) (*lookingglass.Session, string) {
	t.Helper()
	session, ownerToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	return session, ownerToken
}

func (s *oauthAssertionTestServer) registerSigner(signer assertionSigner) {
	s.idp.RegisterClient(&models.Client{
		ID:                      "machine-client-pkjwt",
		Name:                    "JWT Test Client",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"api:read", "api:write"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}},
	})
}

func postClientAssertion(
	t *testing.T,
	serverURL string,
	form url.Values,
	basicUser string,
	basicPassword string,
	sessionID string,
) (int, map[string]interface{}) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		request.SetBasicAuth(basicUser, basicPassword)
	}
	if sessionID != "" {
		request.Header.Set("X-Looking-Glass-Session", sessionID)
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

func assertionForm(clientID, assertion string) url.Values {
	return url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
		"scope":                 {"api:read"},
	}
}

func TestPrivateKeyJWTRoundTripForEverySupportedAlgorithm(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			testServer := newOAuthAssertionTestServer(t)
			signer := newAssertionSigner(t, alg, "key-"+strings.ToLower(alg))
			testServer.registerSigner(signer)
			audience := testServer.server.URL + "/oauth2/token"
			assertion := signer.sign(t, validAssertionClaims(*testServer.now, "machine-client-pkjwt", audience, "jti-"+alg), "")

			status, response := postClientAssertion(
				t,
				testServer.server.URL,
				assertionForm("machine-client-pkjwt", assertion),
				"",
				"",
				"",
			)
			if status != http.StatusOK {
				t.Fatalf("status = %d, response = %#v", status, response)
			}
			if response["access_token"] == "" {
				t.Fatalf("access_token missing from %#v", response)
			}
		})
	}
}

func TestClientAssertionClaimAndHeaderValidationReasons(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clientID := "machine-client-pkjwt"
	audience := "https://as.example/oauth2/token"
	signer := newAssertionSigner(t, "RS256", "rsa-test")

	tests := []struct {
		name      string
		assertion func() string
		reason    string
	}{
		{
			name: "expired",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "expired")
				claims["iat"] = now.Add(-5 * time.Minute).Unix()
				claims["exp"] = now.Add(-61 * time.Second).Unix()
				return signer.sign(t, claims, "")
			},
			reason: "assertion_expired",
		},
		{
			name: "not yet valid",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "nbf")
				claims["nbf"] = now.Add(61 * time.Second).Unix()
				return signer.sign(t, claims, "")
			},
			reason: "assertion_not_yet_valid",
		},
		{
			name: "wrong audience",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, "https://other.example/token", "aud")
				return signer.sign(t, claims, "")
			},
			reason: "invalid_aud",
		},
		{
			name: "trailing slash audience mismatch",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience+"/", "aud-slash")
				return signer.sign(t, claims, "")
			},
			reason: "invalid_aud",
		},
		{
			name: "issuer audience rejected by exact token endpoint profile",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, "https://as.example/oauth2", "aud-issuer")
				return signer.sign(t, claims, "")
			},
			reason: "invalid_aud",
		},
		{
			name: "audience array accepted only on exact member",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "aud-array")
				claims["aud"] = []string{"https://other.example", audience}
				return signer.sign(t, claims, "")
			},
			reason: "",
		},
		{
			name: "audience array rejects non-string members",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "aud-array-invalid")
				claims["aud"] = []interface{}{audience, 42}
				return signer.sign(t, claims, "")
			},
			reason: "invalid_aud",
		},
		{
			name: "missing issuer",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "missing-iss")
				delete(claims, "iss")
				return signer.sign(t, claims, "")
			},
			reason: "missing_iss",
		},
		{
			name: "missing subject",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "missing-sub")
				delete(claims, "sub")
				return signer.sign(t, claims, "")
			},
			reason: "missing_sub",
		},
		{
			name: "issuer subject mismatch",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "iss-sub")
				claims["sub"] = "different-client"
				return signer.sign(t, claims, "")
			},
			reason: "iss_sub_mismatch",
		},
		{
			name: "request client mismatch",
			assertion: func() string {
				claims := validAssertionClaims(now, "different-client", audience, "client-mismatch")
				return signer.sign(t, claims, "")
			},
			reason: "client_id_claim_mismatch",
		},
		{
			name: "missing issued at",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "missing-iat")
				delete(claims, "iat")
				return signer.sign(t, claims, "")
			},
			reason: "missing_or_invalid_iat",
		},
		{
			name: "issued at in future",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "future-iat")
				claims["iat"] = now.Add(61 * time.Second).Unix()
				claims["exp"] = now.Add(2 * time.Minute).Unix()
				return signer.sign(t, claims, "")
			},
			reason: "iat_in_future",
		},
		{
			name: "missing expiration",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "missing-exp")
				delete(claims, "exp")
				return signer.sign(t, claims, "")
			},
			reason: "missing_or_invalid_exp",
		},
		{
			name: "lifetime too long",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "lifetime")
				claims["exp"] = now.Add(301 * time.Second).Unix()
				return signer.sign(t, claims, "")
			},
			reason: "assertion_lifetime_exceeds_300_seconds",
		},
		{
			name: "missing jti",
			assertion: func() string {
				claims := validAssertionClaims(now, clientID, audience, "missing-jti")
				delete(claims, "jti")
				return signer.sign(t, claims, "")
			},
			reason: "missing_jti",
		},
		{
			name: "alg none",
			assertion: func() string {
				return unsignedAssertion(t, validAssertionClaims(now, clientID, audience, "none"), "none", signer.kid)
			},
			reason: "alg_none_rejected",
		},
		{
			name: "disallowed HS256",
			assertion: func() string {
				return unsignedAssertion(t, validAssertionClaims(now, clientID, audience, "hs"), "HS256", signer.kid)
			},
			reason: "disallowed_alg",
		},
		{
			name: "invalid kid type",
			assertion: func() string {
				return signer.signWithHeaders(
					t,
					validAssertionClaims(now, clientID, audience, "invalid-kid"),
					map[string]interface{}{"kid": 42},
				)
			},
			reason: "invalid_kid",
		},
		{
			name: "unsupported critical header",
			assertion: func() string {
				return signer.signWithHeaders(
					t,
					validAssertionClaims(now, clientID, audience, "critical-header"),
					map[string]interface{}{"kid": signer.kid, "crit": []string{"example"}, "example": true},
				)
			},
			reason: "unsupported_critical_header",
		},
		{
			name: "unencoded payload header",
			assertion: func() string {
				return signer.signWithHeaders(
					t,
					validAssertionClaims(now, clientID, audience, "b64-header"),
					map[string]interface{}{"kid": signer.kid, "b64": false},
				)
			},
			reason: "unsupported_unencoded_payload",
		},
		{
			name:      "malformed",
			assertion: func() string { return "not.a.jwt.with.too.many.parts" },
			reason:    "malformed_client_assertion",
		},
		{
			name:      "oversized",
			assertion: func() string { return strings.Repeat("x", maxClientAssertionSize+1) },
			reason:    "assertion_too_large",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseAndValidateClientAssertion(test.assertion(), clientID, audience, now)
			if test.reason == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if got := clientAssertionFailureReason(err); got != test.reason {
				t.Fatalf("reason = %q, want %q (err %v)", got, test.reason, err)
			}
		})
	}
}

func TestClientAssertionNumericDatesPreserveFractionalSeconds(t *testing.T) {
	signer := newAssertionSigner(t, "RS256", "fractional-dates")
	now := time.Unix(1_700_000_000, 500_000_000).UTC()
	clientID := "fractional-client"
	audience := "https://as.example/oauth2/token"

	validClaims := map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": json.Number("1700000000.123456789"),
		"exp": json.Number("1700000300.123456789"),
		"nbf": json.Number("1700000000.5"),
		"jti": "fractional-valid",
	}
	_, validated, err := parseAndValidateClientAssertion(
		signer.sign(t, validClaims, ""),
		clientID,
		audience,
		now,
	)
	if err != nil {
		t.Fatalf("fractional NumericDate assertion rejected: %v", err)
	}
	wantReplayUntil := time.Unix(1_700_000_360, 123_456_789)
	if !validated.replayUntil.Equal(wantReplayUntil) {
		t.Fatalf("replayUntil = %s, want %s", validated.replayUntil, wantReplayUntil)
	}

	tooLong := map[string]interface{}{}
	for name, value := range validClaims {
		tooLong[name] = value
	}
	tooLong["exp"] = json.Number("1700000300.123456790")
	tooLong["jti"] = "fractional-too-long"
	if _, _, err := parseAndValidateClientAssertion(
		signer.sign(t, tooLong, ""),
		clientID,
		audience,
		now,
	); clientAssertionFailureReason(err) != "assertion_lifetime_exceeds_300_seconds" {
		t.Fatalf("fractional lifetime error = %v", err)
	}

	futureNBF := map[string]interface{}{}
	for name, value := range validClaims {
		futureNBF[name] = value
	}
	futureNBF["nbf"] = json.Number("1700000060.500000001")
	futureNBF["jti"] = "fractional-nbf"
	if _, _, err := parseAndValidateClientAssertion(
		signer.sign(t, futureNBF, ""),
		clientID,
		audience,
		now,
	); clientAssertionFailureReason(err) != "assertion_not_yet_valid" {
		t.Fatalf("fractional nbf error = %v", err)
	}

	exactExpiry := map[string]interface{}{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": json.Number("1699999700.5"),
		"exp": json.Number("1699999940.5"),
		"jti": "fractional-exp-boundary",
	}
	if _, _, err := parseAndValidateClientAssertion(
		signer.sign(t, exactExpiry, ""),
		clientID,
		audience,
		now,
	); clientAssertionFailureReason(err) != "assertion_expired" {
		t.Fatalf("exact expiration boundary error = %v", err)
	}
}

func TestClientAssertionFailuresUseGenericExternalErrorAndDetailedEvent(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "rsa-generic")
	testServer.registerSigner(signer)
	session, _ := createOwnedOAuthSession(t, testServer.engine)

	claims := validAssertionClaims(*testServer.now, "machine-client-pkjwt", "https://wrong.example/token", "wrong-aud")
	assertion := signer.sign(t, claims, "")
	status, response := postClientAssertion(
		t,
		testServer.server.URL,
		assertionForm("machine-client-pkjwt", assertion),
		"",
		"",
		session.ID,
	)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, response = %#v", status, response)
	}
	if response["error"] != "invalid_client" ||
		response["error_description"] != "client assertion validation failed" {
		t.Fatalf("unexpected external error %#v", response)
	}

	storedSession, ok := testServer.engine.GetSession(session.ID)
	if !ok {
		t.Fatal("Looking Glass session not found")
	}
	found := false
	for _, event := range storedSession.Events {
		if event.Title == "Client Authentication Failed" && event.Data["reason"] == "invalid_aud" {
			found = true
		}
	}
	if !found {
		t.Fatalf("specific internal reason not found in events %#v", storedSession.Events)
	}
}

func TestEveryClientAssertionValidationFailureIsGenericExternally(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *oauthAssertionTestServer, assertionSigner) url.Values
	}{
		{
			name: "expired",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "expired")
				claims["iat"] = server.now.Add(-5 * time.Minute).Unix()
				claims["exp"] = server.now.Add(-61 * time.Second).Unix()
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "missing expiration",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "exp")
				delete(claims, "exp")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "not yet valid",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "nbf")
				claims["nbf"] = server.now.Add(61 * time.Second).Unix()
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "wrong audience",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", "https://wrong.example/token", "aud")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "trailing slash audience mismatch",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token/", "aud-slash")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "missing issuer",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "iss")
				delete(claims, "iss")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "missing subject",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "sub")
				delete(claims, "sub")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "issuer subject mismatch",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "iss-sub")
				claims["sub"] = "other"
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "request client mismatch",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "client")
				return assertionForm("different-client", signer.sign(t, claims, ""))
			},
		},
		{
			name: "missing request client id",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "no-client")
				form := assertionForm("", signer.sign(t, claims, ""))
				form.Del("client_id")
				return form
			},
		},
		{
			name: "missing issued at",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "iat")
				delete(claims, "iat")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "lifetime over 300 seconds",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "lifetime")
				claims["exp"] = server.now.Add(301 * time.Second).Unix()
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "missing jti",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "jti")
				delete(claims, "jti")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
		{
			name: "alg none",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "none")
				return assertionForm("machine-client-pkjwt", unsignedAssertion(t, claims, "none", signer.kid))
			},
		},
		{
			name: "HS256",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "hs")
				return assertionForm("machine-client-pkjwt", unsignedAssertion(t, claims, "HS256", signer.kid))
			},
		},
		{
			name: "unknown kid",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, _ assertionSigner) url.Values {
				unregistered := newAssertionSigner(t, "RS256", "unknown")
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "kid")
				return assertionForm("machine-client-pkjwt", unregistered.sign(t, claims, ""))
			},
		},
		{
			name: "missing kid with multiple keys",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				second := newAssertionSigner(t, "RS256", "second")
				server.idp.RegisterClient(&models.Client{
					ID: "machine-client-pkjwt", Name: "multiple", GrantTypes: []string{"client_credentials"},
					Scopes: []string{"api:read"}, TokenEndpointAuthMethod: "private_key_jwt",
					JWKS: &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk, second.jwk}},
				})
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "no-kid")
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
				signed, err := token.SignedString(signer.privateKey)
				if err != nil {
					t.Fatal(err)
				}
				return assertionForm("machine-client-pkjwt", signed)
			},
		},
		{
			name: "algorithm key type mismatch",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, _ assertionSigner) url.Values {
				ecSigner := newAssertionSigner(t, "ES256", "ec-mismatch")
				jwk := ecSigner.jwk
				jwk.Alg = ""
				server.idp.RegisterClient(&models.Client{
					ID: "machine-client-pkjwt", Name: "mismatch", GrantTypes: []string{"client_credentials"},
					Scopes: []string{"api:read"}, TokenEndpointAuthMethod: "private_key_jwt",
					JWKS: &internalcrypto.JWKS{Keys: []internalcrypto.JWK{jwk}},
				})
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "mismatch")
				return assertionForm("machine-client-pkjwt", ecSigner.sign(t, claims, "RS256"))
			},
		},
		{
			name: "invalid signature",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, _ assertionSigner) url.Values {
				registered := newAssertionSigner(t, "RS256", "shared-kid")
				attacker := newAssertionSigner(t, "RS256", "shared-kid")
				server.registerSigner(registered)
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "signature")
				return assertionForm("machine-client-pkjwt", attacker.sign(t, claims, ""))
			},
		},
		{
			name: "malformed assertion",
			prepare: func(_ *testing.T, _ *oauthAssertionTestServer, _ assertionSigner) url.Values {
				return assertionForm("machine-client-pkjwt", "not.a.valid.compact.jwt")
			},
		},
		{
			name: "oversized assertion",
			prepare: func(_ *testing.T, _ *oauthAssertionTestServer, _ assertionSigner) url.Values {
				return assertionForm("machine-client-pkjwt", strings.Repeat("x", maxClientAssertionSize+1))
			},
		},
		{
			name: "unsupported assertion type",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "type")
				form := assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
				form.Set("client_assertion_type", "urn:example:unsupported")
				return form
			},
		},
		{
			name: "authentication method not registered",
			prepare: func(t *testing.T, server *oauthAssertionTestServer, signer assertionSigner) url.Values {
				server.idp.RegisterClient(&models.Client{
					ID:         "machine-client-pkjwt",
					Name:       "Method Not Registered",
					GrantTypes: []string{"client_credentials"},
					Scopes:     []string{"api:read"},
					JWKS:       &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}},
				})
				claims := validAssertionClaims(*server.now, "machine-client-pkjwt", server.server.URL+"/oauth2/token", "method")
				return assertionForm("machine-client-pkjwt", signer.sign(t, claims, ""))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testServer := newOAuthAssertionTestServer(t)
			signer := newAssertionSigner(t, "RS256", "registered")
			testServer.registerSigner(signer)
			status, response := postClientAssertion(t, testServer.server.URL, test.prepare(t, testServer, signer), "", "", "")
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, response = %#v", status, response)
			}
			if response["error"] != "invalid_client" ||
				response["error_description"] != "client assertion validation failed" {
				t.Fatalf("non-generic response %#v", response)
			}
		})
	}
}

func TestClientAssertionReplayStoreOutageReturnsServerError(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "replay-outage")
	testServer.registerSigner(signer)
	testServer.plugin.clientAssertionReplay = failingClientAssertionReplayStore{}
	session, ownerToken := createOwnedOAuthSession(t, testServer.engine)
	assertion := signer.sign(t, validAssertionClaims(
		*testServer.now,
		"machine-client-pkjwt",
		testServer.server.URL+"/oauth2/token",
		"replay-outage-jti",
	), "")

	status, response := postClientAssertion(
		t,
		testServer.server.URL,
		assertionForm("machine-client-pkjwt", assertion),
		"",
		"",
		session.ID,
	)
	if status != http.StatusInternalServerError ||
		response["error"] != "server_error" {
		t.Fatalf("status = %d, response = %#v", status, response)
	}
	snapshot, authorized := testServer.engine.AuthorizedSessionSnapshot(session.ID, ownerToken)
	if !authorized {
		t.Fatal("session owner capability was rejected")
	}
	for _, event := range snapshot.Events {
		if event.Title == "Client Assertion Signature Verified" ||
			event.Title == "Client Authenticated" {
			t.Fatalf("assertion was published before replay reservation: %#v", event)
		}
	}
}

func TestClientAssertionReplayIsBoundedToOriginalValidityWindow(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "rsa-replay")
	testServer.registerSigner(signer)
	audience := testServer.server.URL + "/oauth2/token"
	claims := validAssertionClaims(*testServer.now, "machine-client-pkjwt", audience, "single-use-jti")
	assertion := signer.sign(t, claims, "")

	status, _ := postClientAssertion(t, testServer.server.URL, assertionForm("machine-client-pkjwt", assertion), "", "", "")
	if status != http.StatusOK {
		t.Fatalf("first request status = %d", status)
	}
	status, response := postClientAssertion(t, testServer.server.URL, assertionForm("machine-client-pkjwt", assertion), "", "", "")
	if status != http.StatusBadRequest ||
		response["error"] != "invalid_client" ||
		response["error_description"] != "client assertion validation failed" {
		t.Fatalf("replay status = %d, response = %#v", status, response)
	}

	*testServer.now = testServer.now.Add(2*time.Minute + 30*time.Second)
	status, response = postClientAssertion(t, testServer.server.URL, assertionForm("machine-client-pkjwt", assertion), "", "", "")
	if status != http.StatusBadRequest || response["error"] != "invalid_client" {
		t.Fatalf("replay during expiration skew status = %d, response = %#v", status, response)
	}

	*testServer.now = testServer.now.Add(31 * time.Second)
	newClaims := validAssertionClaims(*testServer.now, "machine-client-pkjwt", audience, "single-use-jti")
	newAssertion := signer.sign(t, newClaims, "")
	status, response = postClientAssertion(t, testServer.server.URL, assertionForm("machine-client-pkjwt", newAssertion), "", "", "")
	if status != http.StatusOK {
		t.Fatalf("post-expiry reuse status = %d, response = %#v", status, response)
	}
}

func TestConcurrentClientAssertionReplayAllowsExactlyOneRequest(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "rsa-concurrent-replay")
	testServer.registerSigner(signer)
	assertion := signer.sign(t, validAssertionClaims(
		*testServer.now,
		"machine-client-pkjwt",
		testServer.server.URL+"/oauth2/token",
		"concurrent-single-use-jti",
	), "")

	const requestCount = 12
	statuses := make(chan int, requestCount)
	var requests sync.WaitGroup
	for range requestCount {
		requests.Add(1)
		go func() {
			defer requests.Done()
			request, err := http.NewRequest(
				http.MethodPost,
				testServer.server.URL+"/oauth2/token",
				strings.NewReader(assertionForm("machine-client-pkjwt", assertion).Encode()),
			)
			if err != nil {
				statuses <- 0
				return
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	requests.Wait()
	close(statuses)

	successes := 0
	rejections := 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			rejections++
		default:
			t.Fatalf("unexpected concurrent status %d", status)
		}
	}
	if successes != 1 || rejections != requestCount-1 {
		t.Fatalf("successes = %d, rejections = %d", successes, rejections)
	}
}

func TestClientAssertionKeySelectionAndAlgorithmBinding(t *testing.T) {
	rsaSigner := newAssertionSigner(t, "RS256", "rsa")
	ecSigner := newAssertionSigner(t, "ES256", "ec")

	if _, err := selectClientJWK(internalcrypto.JWKS{Keys: []internalcrypto.JWK{rsaSigner.jwk, ecSigner.jwk}}, "", "RS256"); err == nil {
		t.Fatal("missing kid was accepted with multiple registered keys")
	}
	rsaWithoutAlg := rsaSigner.jwk
	rsaWithoutAlg.Alg = ""
	ecWithoutAlg := ecSigner.jwk
	ecWithoutAlg.Alg = ""
	if _, err := selectClientJWK(internalcrypto.JWKS{Keys: []internalcrypto.JWK{rsaWithoutAlg, ecWithoutAlg}}, "", "RS256"); err == nil {
		t.Fatal("missing kid was accepted with multiple candidate keys")
	}
	if _, err := selectClientJWK(internalcrypto.JWKS{Keys: []internalcrypto.JWK{rsaSigner.jwk}}, "unknown", "RS256"); err == nil {
		t.Fatal("unknown kid was accepted")
	}
	for name, setPrivateMember := range map[string]func(*internalcrypto.JWK){
		"d":   func(key *internalcrypto.JWK) { key.D = "private" },
		"p":   func(key *internalcrypto.JWK) { key.P = "private" },
		"q":   func(key *internalcrypto.JWK) { key.Q = "private" },
		"dp":  func(key *internalcrypto.JWK) { key.DP = "private" },
		"dq":  func(key *internalcrypto.JWK) { key.DQ = "private" },
		"qi":  func(key *internalcrypto.JWK) { key.QI = "private" },
		"oth": func(key *internalcrypto.JWK) { key.Oth = json.RawMessage(`[{}]`) },
		"k":   func(key *internalcrypto.JWK) { key.K = "private" },
	} {
		privateJWK := rsaSigner.jwk
		setPrivateMember(&privateJWK)
		if _, err := selectClientJWK(
			internalcrypto.JWKS{Keys: []internalcrypto.JWK{rsaSigner.jwk, privateJWK}},
			rsaSigner.kid,
			"RS256",
		); err == nil {
			t.Fatalf("static JWKS private member %q was accepted", name)
		}
	}
	duplicate := rsaSigner.jwk
	if _, err := selectClientJWK(
		internalcrypto.JWKS{Keys: []internalcrypto.JWK{rsaSigner.jwk, duplicate}},
		rsaSigner.kid,
		"RS256",
	); err == nil {
		t.Fatal("duplicate kid was accepted")
	}
	signOnlyJWK := rsaSigner.jwk
	signOnlyJWK.KeyOps = []string{"sign"}
	if reason := clientAssertionFailureReason(validateClientAssertionKeyBinding(signOnlyJWK, "RS256")); reason != "registered_key_not_for_verification" {
		t.Fatalf("sign-only key_ops reason = %q", reason)
	}
	ecWithoutDeclaredAlg := ecSigner.jwk
	ecWithoutDeclaredAlg.Alg = ""
	if reason := clientAssertionFailureReason(validateClientAssertionKeyBinding(ecWithoutDeclaredAlg, "RS256")); reason != "alg_key_type_mismatch" {
		t.Fatalf("RSA header against EC key reason = %q", reason)
	}
	rsaWithoutDeclaredAlg := rsaSigner.jwk
	rsaWithoutDeclaredAlg.Alg = ""
	if reason := clientAssertionFailureReason(validateClientAssertionKeyBinding(rsaWithoutDeclaredAlg, "ES256")); reason != "alg_key_type_mismatch" {
		t.Fatalf("EC header against RSA key reason = %q", reason)
	}
}

func TestPrivateKeyJWTRequiresRegisteredAuthenticationMethod(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "rsa-method-registration")
	testServer.idp.RegisterClient(&models.Client{
		ID:         "machine-client-pkjwt",
		Name:       "JWT Test Client Without Auth Method",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"api:read"},
		JWKS:       &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}},
	})
	assertion := signer.sign(t, validAssertionClaims(
		*testServer.now,
		"machine-client-pkjwt",
		testServer.server.URL+"/oauth2/token",
		"unregistered-method",
	), "")

	status, response := postClientAssertion(
		t,
		testServer.server.URL,
		assertionForm("machine-client-pkjwt", assertion),
		"",
		"",
		"",
	)
	if status != http.StatusBadRequest ||
		response["error"] != "invalid_client" ||
		response["error_description"] != "client assertion validation failed" {
		t.Fatalf("status = %d, response = %#v", status, response)
	}
}

func TestClientAssertionParameterPairAndMultipleAuthMethods(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "rsa-params")
	testServer.registerSigner(signer)
	audience := testServer.server.URL + "/oauth2/token"
	assertion := signer.sign(t, validAssertionClaims(*testServer.now, "machine-client-pkjwt", audience, "params"), "")

	tests := []struct {
		name  string
		form  url.Values
		basic bool
	}{
		{
			name: "type without assertion",
			form: url.Values{
				"grant_type": {"client_credentials"}, "client_id": {"machine-client-pkjwt"},
				"client_assertion_type": {clientAssertionType},
			},
		},
		{
			name: "assertion without type",
			form: url.Values{
				"grant_type": {"client_credentials"}, "client_id": {"machine-client-pkjwt"},
				"client_assertion": {assertion},
			},
		},
		{
			name: "assertion plus post secret",
			form: func() url.Values {
				form := assertionForm("machine-client-pkjwt", assertion)
				form.Set("client_secret", "secret")
				return form
			}(),
		},
		{
			name:  "assertion plus basic",
			form:  assertionForm("machine-client-pkjwt", assertion),
			basic: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, password := "", ""
			if test.basic {
				user, password = "machine-client", "secret"
			}
			status, response := postClientAssertion(t, testServer.server.URL, test.form, user, password, "")
			if status != http.StatusBadRequest || response["error"] != "invalid_request" {
				t.Fatalf("status = %d, response = %#v", status, response)
			}
		})
	}
}

func TestClientAssertionIsRejectedForOutOfScopeGrants(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	for _, grantType := range []string{"authorization_code", "refresh_token"} {
		form := url.Values{
			"grant_type":            {grantType},
			"client_id":             {"machine-client-pkjwt"},
			"client_assertion_type": {clientAssertionType},
			"client_assertion":      {"header.payload.signature"},
		}
		status, response := postClientAssertion(t, testServer.server.URL, form, "", "", "")
		if status != http.StatusBadRequest || response["error"] != "invalid_client" {
			t.Fatalf("%s status = %d, response = %#v", grantType, status, response)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func resolverWithResponse(t *testing.T, responseBody []byte) (*clientJWKSResolver, *atomic.Int32) {
	t.Helper()
	resolver := newClientJWKSResolver()
	resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	calls := &atomic.Int32{}
	resolver.httpClient = &http.Client{
		Timeout: time.Second,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		}),
	}
	return resolver, calls
}

func TestClientJWKSResolutionStaticAndURI(t *testing.T) {
	signer := newAssertionSigner(t, "RS256", "remote-rsa")
	staticClient := &models.Client{
		ID: "static", JWKS: &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}},
	}
	resolver := newClientJWKSResolver()
	if key, err := resolver.resolve(staticClient, signer.kid, signer.alg); err != nil || key.Kid != signer.kid {
		t.Fatalf("static resolution key = %#v, err = %v", key, err)
	}

	body, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}})
	if err != nil {
		t.Fatal(err)
	}
	resolver, calls := resolverWithResponse(t, body)
	remoteClient := &models.Client{ID: "remote", JWKSURI: "https://keys.example/jwks"}
	key, err := resolver.resolve(remoteClient, signer.kid, signer.alg)
	if err != nil || key.Kid != signer.kid {
		t.Fatalf("URI resolution key = %#v, err = %v", key, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1", calls.Load())
	}
	if _, err := resolver.resolve(remoteClient, signer.kid, signer.alg); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cache fetch count = %d, want 1", calls.Load())
	}

	staticSigner := newAssertionSigner(t, "RS256", "static-rsa")
	combinedResolver, combinedCalls := resolverWithResponse(t, body)
	combinedClient := &models.Client{
		ID:      "combined",
		JWKS:    &internalcrypto.JWKS{Keys: []internalcrypto.JWK{staticSigner.jwk}},
		JWKSURI: "https://keys.example/jwks",
	}
	if key, err := combinedResolver.resolve(combinedClient, signer.kid, signer.alg); err != nil || key.Kid != signer.kid {
		t.Fatalf("URI fallback on static kid miss key = %#v, err = %v", key, err)
	}
	if combinedCalls.Load() != 1 {
		t.Fatalf("combined fallback fetch count = %d, want 1", combinedCalls.Load())
	}
	invalidStatic := staticSigner.jwk
	invalidStatic.D = "private-key-material"
	combinedClient.JWKS = &internalcrypto.JWKS{Keys: []internalcrypto.JWK{invalidStatic}}
	if _, err := combinedResolver.resolve(combinedClient, staticSigner.kid, staticSigner.alg); err == nil {
		t.Fatal("invalid static key was bypassed through jwks_uri fallback")
	}
	if combinedCalls.Load() != 1 {
		t.Fatalf("invalid static key caused a remote fetch; count = %d", combinedCalls.Load())
	}

	testServer := newOAuthAssertionTestServer(t)
	testServer.idp.RegisterClient(&models.Client{
		ID:                      "machine-client-pkjwt",
		Name:                    "Remote JWKS Client",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 "https://keys.example/jwks",
	})
	testServer.plugin.clientKeyResolver = resolver
	claims := validAssertionClaims(
		*testServer.now,
		"machine-client-pkjwt",
		testServer.server.URL+"/oauth2/token",
		"remote-signature",
	)
	assertion := signer.sign(t, claims, "")
	if _, _, err := testServer.plugin.authenticatePrivateKeyJWT("machine-client-pkjwt", assertion); err != nil {
		t.Fatalf("hand-signed assertion did not verify through jwks_uri: %v", err)
	}
}

func TestClientJWKSURIRealHTTPSRoundTrip(t *testing.T) {
	signer := newAssertionSigner(t, "RS256", "live-https-rsa")
	jwksBody, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}})
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksServer.Close()

	certificate, err := x509.ParseCertificate(jwksServer.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	_, port, err := net.SplitHostPort(jwksServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	resolver := newClientJWKSResolver()
	resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	resolver.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, jwksServer.Listener.Addr().String())
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = resolver.secureDialContext
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "example.com",
	}
	resolver.httpClient = &http.Client{
		Timeout:   clientJWKSFetchTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("JWKS redirects are not allowed")
		},
	}

	testServer := newOAuthAssertionTestServer(t)
	testServer.idp.RegisterClient(&models.Client{
		ID:                      "machine-client-pkjwt",
		Name:                    "Live HTTPS JWKS Client",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 "https://example.com:" + port + "/jwks",
	})
	testServer.plugin.clientKeyResolver = resolver
	assertion := signer.sign(t, validAssertionClaims(
		*testServer.now,
		"machine-client-pkjwt",
		testServer.server.URL+"/oauth2/token",
		"live-https-jwks",
	), "")

	status, response := postClientAssertion(
		t,
		testServer.server.URL,
		assertionForm("machine-client-pkjwt", assertion),
		"",
		"",
		"",
	)
	if status != http.StatusOK || response["access_token"] == "" {
		t.Fatalf("status = %d, response = %#v", status, response)
	}
	if requests.Load() != 1 {
		t.Fatalf("real JWKS HTTPS request count = %d, want 1", requests.Load())
	}
}

func TestClientJWKSURIControls(t *testing.T) {
	t.Run("DNS resolution is covered by the fetch timeout", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		resolver.fetchTimeout = 10 * time.Millisecond
		resolver.lookupIPs = func(ctx context.Context, _ string) ([]net.IP, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		started := time.Now()
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil {
			t.Fatal("timed out DNS resolution was accepted")
		}
		if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
			t.Fatalf("DNS timeout took %s", elapsed)
		}
	})

	t.Run("SSRF address rejected before fetch", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		var called atomic.Bool
		resolver.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			called.Store(true)
			return nil, errors.New("must not fetch")
		})
		if _, err := resolver.fetch("client", "https://localhost/jwks", false); err == nil {
			t.Fatal("loopback jwks_uri was accepted")
		}
		if called.Load() {
			t.Fatal("HTTP fetch occurred before SSRF rejection")
		}
	})

	t.Run("HTTP scheme rejected", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		if _, err := resolver.fetch("client", "http://keys.example/jwks", false); err == nil {
			t.Fatal("HTTP jwks_uri was accepted")
		}
	})

	t.Run("redirect rejected", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		resolver.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://other.example/jwks"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    request,
			}, nil
		})
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil {
			t.Fatal("redirecting jwks_uri was accepted")
		}
	})

	t.Run("response over 64KB rejected", func(t *testing.T) {
		resolver, _ := resolverWithResponse(t, bytes.Repeat([]byte("x"), maxClientJWKSResponseSize+1))
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil ||
			!strings.Contains(err.Error(), "exceeds 64KB") {
			t.Fatalf("oversize error = %v", err)
		}
	})

	t.Run("unreachable endpoint rejected", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		resolver.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network unreachable")
		})
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil {
			t.Fatal("unreachable jwks_uri was accepted")
		}
	})

	t.Run("timeout rejected", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		resolver.httpClient = &http.Client{
			Timeout: 10 * time.Millisecond,
			Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}),
		}
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil {
			t.Fatal("timed out jwks_uri was accepted")
		}
	})

	t.Run("environment proxies are disabled", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		transport, ok := resolver.httpClient.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport type = %T", resolver.httpClient.Transport)
		}
		if transport.Proxy != nil {
			t.Fatal("JWKS transport can use environment proxies")
		}
	})

	t.Run("DNS rebinding is rejected at dial time", func(t *testing.T) {
		resolver := newClientJWKSResolver()
		var lookups atomic.Int32
		resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
			if lookups.Add(1) == 1 {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		var dialed atomic.Bool
		resolver.dialContext = func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("must not dial")
		}
		if _, err := resolver.fetch("client", "https://keys.example/jwks", false); err == nil ||
			!strings.Contains(err.Error(), "blocked JWKS address") {
			t.Fatalf("DNS rebinding error = %v", err)
		}
		if dialed.Load() {
			t.Fatal("dialer received a rebound private address")
		}
	})
}

func TestBlockedJWKSAddressRanges(t *testing.T) {
	for _, value := range []string{
		"0.0.0.1",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"240.0.0.1",
		"64:ff9b::1",
		"100::1",
		"2001:db8::1",
		"3fff::1",
		"fc00::1",
		"fe80::1",
	} {
		if !isBlockedJWKSAddress(net.ParseIP(value)) {
			t.Errorf("special-use address %s was allowed", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if isBlockedJWKSAddress(net.ParseIP(value)) {
			t.Errorf("global address %s was blocked", value)
		}
	}
}

func TestRemoteClientJWKSMixedSetIgnoresUnusableUnrelatedKeys(t *testing.T) {
	signer := newAssertionSigner(t, "RS256", "usable")
	weakModulus := make([]byte, 128)
	weakModulus[0] = 0x80
	weakModulus[len(weakModulus)-1] = 1
	body, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{
		{Kty: "EC", Crv: "P-384", Alg: "ES384", Kid: "unrelated", X: "bad", Y: "bad"},
		{Kty: "RSA", Alg: "RS256", Kid: "malformed-supported", N: base64.RawURLEncoding.EncodeToString(weakModulus), E: "AQAB"},
		signer.jwk,
	}})
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := resolverWithResponse(t, body)
	jwks, err := resolver.fetch("mixed", "https://keys.example/jwks", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != signer.kid {
		t.Fatalf("usable filtered keys = %#v", jwks.Keys)
	}
}

func TestRemoteClientJWKSRejectsEveryPrivateMember(t *testing.T) {
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		t.Run(member, func(t *testing.T) {
			body := fmt.Appendf(nil,
				`{"keys":[{"kty":"unsupported","kid":"ignored","%s":null}]}`,
				member,
			)
			resolver, _ := resolverWithResponse(t, body)
			if _, err := resolver.fetch("private", "https://keys.example/jwks", false); err == nil ||
				!strings.Contains(err.Error(), "private key material") {
				t.Fatalf("private member %q error = %v", member, err)
			}
		})
	}
}

func TestClientJWKSFetchesAreCoalescedAcrossConcurrentResolvers(t *testing.T) {
	oldSigner := newAssertionSigner(t, "RS256", "old-coalesced")
	rotatedSigner := newAssertionSigner(t, "RS256", "rotated-coalesced")
	oldBody, _ := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{oldSigner.jwk}})
	rotatedBody, _ := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{rotatedSigner.jwk}})
	resolver := newClientJWKSResolver()
	resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	var calls atomic.Int32
	forcedStarted := make(chan struct{})
	releaseForced := make(chan struct{})
	resolver.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		body := oldBody
		if call == 2 {
			close(forcedStarted)
			<-releaseForced
			body = rotatedBody
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	})}
	client := &models.Client{ID: "coalesced", JWKSURI: "https://keys.example/jwks"}
	if key, err := resolver.resolve(client, oldSigner.kid, "RS256"); err != nil || key.Kid != oldSigner.kid {
		t.Fatalf("initial key = %#v, error = %v", key, err)
	}

	const requests = 24
	var wait sync.WaitGroup
	errorsCh := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, err := resolver.resolve(client, rotatedSigner.kid, "RS256")
			if err != nil {
				errorsCh <- err
				return
			}
			if key.Kid != rotatedSigner.kid {
				errorsCh <- fmt.Errorf("kid = %q", key.Kid)
			}
		}()
	}
	<-forcedStarted
	close(releaseForced)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("network fetches = %d, want one initial and one forced fetch", calls.Load())
	}
}

func TestClientJWKSRefetchOnKidMissIsRateLimited(t *testing.T) {
	firstSigner := newAssertionSigner(t, "RS256", "old")
	secondSigner := newAssertionSigner(t, "RS256", "rotated")
	firstBody, _ := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{firstSigner.jwk}})
	secondBody, _ := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{secondSigner.jwk}})
	resolver := newClientJWKSResolver()
	resolver.lookupIPs = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	var calls atomic.Int32
	resolver.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		call := calls.Add(1)
		body := firstBody
		if call > 1 {
			body = secondBody
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	client := &models.Client{ID: "rotating", JWKSURI: "https://keys.example/jwks"}
	if key, err := resolver.resolve(client, "rotated", "RS256"); err != nil || key.Kid != "rotated" {
		t.Fatalf("rotated key = %#v, err = %v", key, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("fetch count after one miss = %d, want 2", calls.Load())
	}
	if _, err := resolver.resolve(client, "still-unknown", "RS256"); err == nil {
		t.Fatal("unknown kid was accepted")
	}
	if calls.Load() != 2 {
		t.Fatalf("rate-limited miss fetch count = %d, want 2", calls.Load())
	}
}

func TestOAuthAuthorizationServerMetadataAdvertisesImplementedJWTAuth(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	testServer.plugin.baseURL = "https://as.example"
	response, err := http.Get(testServer.server.URL + "/oauth2/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var metadata map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	methods, _ := metadata["token_endpoint_auth_methods_supported"].([]interface{})
	if !containsInterfaceString(methods, "private_key_jwt") {
		t.Fatalf("private_key_jwt missing from %#v", methods)
	}
	algorithms, _ := metadata["token_endpoint_auth_signing_alg_values_supported"].([]interface{})
	for _, algorithm := range []string{"RS256", "ES256", "EdDSA"} {
		if !containsInterfaceString(algorithms, algorithm) {
			t.Fatalf("%s missing from %#v", algorithm, algorithms)
		}
	}
}

// TestOAuthAuthorizationServerMetadataAdvertisesDPoPAlgorithms covers RFC
// 9449 Section 5.1's dpop_signing_alg_values_supported metadata parameter,
// which signals DPoP support and the acceptable proof JWS algorithms.
func TestOAuthAuthorizationServerMetadataAdvertisesDPoPAlgorithms(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	testServer.plugin.baseURL = "https://as.example"
	response, err := http.Get(testServer.server.URL + "/oauth2/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var metadata map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	algorithms, _ := metadata["dpop_signing_alg_values_supported"].([]interface{})
	for _, algorithm := range dpop.AllowedAlgorithmsList {
		if !containsInterfaceString(algorithms, algorithm) {
			t.Fatalf("%s missing from %#v", algorithm, algorithms)
		}
	}
}

func TestOAuthAuthorizationServerMetadataRejectsNonHTTPSIssuer(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	response, err := http.Get(testServer.server.URL + "/oauth2/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestOAuthAuthorizationServerMetadataRejectsPathfulBaseURL(t *testing.T) {
	for _, baseURL := range []string{"https://as.example/base", "https://as.example/"} {
		t.Run(baseURL, func(t *testing.T) {
			if _, err := authorizationServerMetadataIssuer(baseURL); err == nil {
				t.Fatal("pathful base URL was accepted")
			}
		})
	}
}

func TestDemoClientRegistersOnlyPublicJWKMaterial(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "browser-rsa")
	body, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}})
	if err != nil {
		t.Fatal(err)
	}
	session, ownerToken := createOwnedOAuthSession(t, testServer.engine)
	request, err := http.NewRequest(
		http.MethodPost,
		testServer.server.URL+"/oauth2/demo/clients/machine-client-pkjwt/jwks",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Looking-Glass-Session", session.ID)
	request.Header.Set(lookingglass.OwnerTokenHeader, ownerToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("public registration status = %d", response.StatusCode)
	}
	var registration map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&registration); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	registeredClientID, _ := registration["client_id"].(string)
	if registeredClientID == "" || registeredClientID == "machine-client-pkjwt" {
		t.Fatalf("registration did not issue an isolated client ID: %#v", registration)
	}
	if registration["token_endpoint"] != testServer.server.URL+"/oauth2/token" {
		t.Fatalf("token_endpoint = %#v", registration["token_endpoint"])
	}
	if expiresAt, ok := registration["expires_at"].(string); !ok || expiresAt == "" {
		t.Fatalf("expires_at missing from %#v", registration)
	}
	client, ok := testServer.idp.GetClient(registeredClientID)
	if !ok || client.JWKS == nil || len(client.JWKS.Keys) != 1 || client.JWKS.Keys[0].Kid != signer.kid {
		t.Fatalf("registered client key = %#v", client)
	}
	if client.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Fatalf("registered authentication method = %q", client.TokenEndpointAuthMethod)
	}
	if client.ExpiresAt == nil || !client.ExpiresAt.Equal(testServer.now.Add(demoClientRegistrationTTL)) {
		t.Fatalf("registered client expiration = %#v", client.ExpiresAt)
	}

	privateJWK := signer.jwk
	privateJWK.D = "private-material-must-not-cross-boundary"
	body, _ = json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{privateJWK}})
	request, err = http.NewRequest(
		http.MethodPost,
		testServer.server.URL+"/oauth2/demo/clients/machine-client-pkjwt/jwks",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Looking-Glass-Session", session.ID)
	request.Header.Set(lookingglass.OwnerTokenHeader, ownerToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("private JWK registration status = %d", response.StatusCode)
	}

	expiredAt := time.Now().Add(-time.Second)
	testServer.idp.RegisterClient(&models.Client{
		ID:        "expired-demo-client",
		ExpiresAt: &expiredAt,
	})
	if _, exists := testServer.idp.GetClient("expired-demo-client"); exists {
		t.Fatal("expired demo client registration was not pruned")
	}
}

func TestDemoClientRegistrationsAreIsolatedAcrossSessions(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signers := []assertionSigner{
		newAssertionSigner(t, "RS256", "browser-session-one"),
		newAssertionSigner(t, "RS256", "browser-session-two"),
	}
	clientIDs := make([]string, len(signers))
	for index, signer := range signers {
		session, ownerToken := createOwnedOAuthSession(t, testServer.engine)
		body, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(
			http.MethodPost,
			testServer.server.URL+"/oauth2/demo/clients/machine-client-pkjwt/jwks",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Looking-Glass-Session", session.ID)
		request.Header.Set(lookingglass.OwnerTokenHeader, ownerToken)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var registration map[string]interface{}
		decodeErr := json.NewDecoder(response.Body).Decode(&registration)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil {
			t.Fatalf("registration %d status = %d, decode error = %v", index, response.StatusCode, decodeErr)
		}
		clientIDs[index], _ = registration["client_id"].(string)
	}
	if clientIDs[0] == "" || clientIDs[0] == clientIDs[1] {
		t.Fatalf("session client IDs are not isolated: %#v", clientIDs)
	}

	for index, signer := range signers {
		assertion := signer.sign(t, validAssertionClaims(
			*testServer.now,
			clientIDs[index],
			testServer.server.URL+"/oauth2/token",
			fmt.Sprintf("isolated-session-%d", index),
		), "")
		status, response := postClientAssertion(
			t,
			testServer.server.URL,
			assertionForm(clientIDs[index], assertion),
			"",
			"",
			"",
		)
		if status != http.StatusOK || response["access_token"] == "" {
			t.Fatalf("isolated client %d status = %d, response = %#v", index, status, response)
		}
	}
}

func TestDemoClientRegistrationRequiresOwnerAndIsOneShot(t *testing.T) {
	testServer := newOAuthAssertionTestServer(t)
	signer := newAssertionSigner(t, "RS256", "one-shot-browser-key")
	body, err := json.Marshal(internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}})
	if err != nil {
		t.Fatal(err)
	}
	session, ownerToken := createOwnedOAuthSession(t, testServer.engine)
	register := func(token string) (int, error) {
		request, requestErr := http.NewRequest(
			http.MethodPost,
			testServer.server.URL+"/oauth2/demo/clients/machine-client-pkjwt/jwks",
			bytes.NewReader(body),
		)
		if requestErr != nil {
			return 0, requestErr
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Looking-Glass-Session", session.ID)
		if token != "" {
			request.Header.Set(lookingglass.OwnerTokenHeader, token)
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			return 0, requestErr
		}
		defer response.Body.Close()
		_, requestErr = io.Copy(io.Discard, response.Body)
		return response.StatusCode, requestErr
	}

	if status, err := register(""); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("ownerless status = %d, error = %v", status, err)
	}
	if status, err := register("wrong-owner"); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("wrong-owner status = %d, error = %v", status, err)
	}

	var accepted atomic.Int32
	var conflicts atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, requestErr := register(ownerToken)
			if requestErr != nil {
				t.Errorf("registration request: %v", requestErr)
				return
			}
			switch status {
			case http.StatusOK:
				accepted.Add(1)
			case http.StatusConflict:
				conflicts.Add(1)
			default:
				t.Errorf("unexpected registration status %d", status)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || conflicts.Load() != 15 {
		t.Fatalf("accepted = %d, conflicts = %d", accepted.Load(), conflicts.Load())
	}
}

func containsInterfaceString(values []interface{}, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
