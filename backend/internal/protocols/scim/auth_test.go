package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

const (
	testOrigin   = "https://sp.example"
	testIssuer   = testOrigin + "/oauth2"
	testResource = testOrigin + "/scim/v2"
)

// authTestServer is a SCIM service provider whose authorization server runs
// in the same process, as on the monolith.
type authTestServer struct {
	idp    *mockidp.MockIdP
	keySet *crypto.KeySet
	router http.Handler
}

func newAuthTestServer(t *testing.T) *authTestServer {
	t.Helper()
	for _, name := range []string{"SCIM_AS_ISSUER", "SCIM_RESOURCE", "SCIM_AS_JWKS_URI", "SCIM_AS_INTROSPECT_URI", "SCIM_AS_INTROSPECT_CLIENT_SECRET"} {
		t.Setenv(name, "")
	}
	t.Setenv("SCIM_DATA_DIR", t.TempDir())
	t.Setenv("SCIM_RETENTION", "0")

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	idp := mockidp.NewMockIdP(keySet)
	p := NewPlugin()
	if err := p.Initialize(context.Background(), plugin.PluginConfig{BaseURL: testOrigin, MockIdP: idp}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})

	router := chi.NewRouter()
	router.Route("/scim", p.RegisterRoutes)
	return &authTestServer{idp: idp, keySet: keySet, router: router}
}

// accessToken signs an RFC 9068 access token as the authorization server
// would for scim-client.
func (s *authTestServer) accessToken(t *testing.T, change func(*crypto.AccessToken)) string {
	t.Helper()
	token := crypto.AccessToken{
		Issuer:   testIssuer,
		Subject:  mockidp.SCIMClientID,
		Audience: testResource,
		ClientID: mockidp.SCIMClientID,
		Scope:    ScopeRead,
		Lifetime: time.Minute,
	}
	if change != nil {
		change(&token)
	}
	signed, err := s.idp.JWTService().CreateAccessToken(token)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return signed
}

func (s *authTestServer) do(method, path, authorization, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if body != "" {
		request.Header.Set("Content-Type", ContentTypeSCIM)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, request)
	return recorder
}

// scimErrorBody decodes an RFC 7644 Section 3.12 error response, keeping the
// JSON type of "status".
func scimErrorBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v: %s", err, recorder.Body.String())
	}
	return body
}

// RFC 7644 Section 2: "a SCIM service provider SHALL indicate supported HTTP
// authentication schemes via the "WWW-Authenticate" header." RFC 6750 Section
// 3.1: with no authentication information, "the resource server SHOULD NOT
// include an error code or other error information."
func TestRequestWithoutCredentialsIsChallengedWithBearer(t *testing.T) {
	server := newAuthTestServer(t)

	for name, authorization := range map[string]string{
		"no Authorization header": "",
		"an unsupported scheme":   "Basic c2NpbTpzY2lt",
	} {
		t.Run(name, func(t *testing.T) {
			recorder := server.do(http.MethodGet, "/scim/v2/Users", authorization, "")
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != `Bearer realm="scim"` {
				t.Errorf("WWW-Authenticate = %q, want the bare Bearer challenge", got)
			}
			body := scimErrorBody(t, recorder)
			// RFC 7644 Section 3.12: status is "The HTTP status code ...
			// expressed as a JSON string."
			if status, ok := body["status"].(string); !ok || status != "401" {
				t.Errorf("status = %#v, want the JSON string \"401\"", body["status"])
			}
			// Table 9 defines scimType values for HTTP 400 alone.
			if _, present := body["scimType"]; present {
				t.Errorf("scimType = %#v on a 401, want none", body["scimType"])
			}
			if got := recorder.Header().Get("Content-Type"); got != ContentTypeSCIM {
				t.Errorf("Content-Type = %q, want %q", got, ContentTypeSCIM)
			}
		})
	}
}

func TestMalformedBearerCredentialsAreInvalidRequest(t *testing.T) {
	server := newAuthTestServer(t)
	recorder := server.do(http.MethodGet, "/scim/v2/Users", "Bearer ", "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"invalid_request\"", got)
	}
}

// RFC 9068 Section 4 lists what a resource server checks. Each token below
// fails one check and is refused with invalid_token (RFC 6750 Section 3.1).
func TestAccessTokenThatFailsValidationIsRefused(t *testing.T) {
	server := newAuthTestServer(t)

	otherKeys, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	forged, err := mockidp.NewMockIdP(otherKeys).JWTService().CreateAccessToken(crypto.AccessToken{
		Issuer: testIssuer, Subject: mockidp.SCIMClientID, Audience: testResource, ClientID: mockidp.SCIMClientID, Scope: ScopeRead, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}
	idToken, err := server.idp.JWTService().CreateIDToken("alice", mockidp.SCIMClientID, "", time.Now(), time.Minute, nil)
	if err != nil {
		t.Fatalf("sign ID Token: %v", err)
	}
	revoked := server.accessToken(t, nil)
	server.idp.RevokeAccessToken(revoked)

	tokens := map[string]string{
		"not a JWT":                       "opaque-shared-secret",
		"signed by another key":           forged,
		"expired":                         server.accessToken(t, func(token *crypto.AccessToken) { token.Lifetime = -time.Minute }),
		"an ID Token (typ is not at+jwt)": idToken,
		"issued by another issuer":        server.accessToken(t, func(token *crypto.AccessToken) { token.Issuer = testOrigin }),
		"issued for another resource":     server.accessToken(t, func(token *crypto.AccessToken) { token.Audience = testOrigin + "/oauth2/resource" }),
		"revoked":                         revoked,
		"bound to a key (RFC 7800 cnf)": server.accessToken(t, func(token *crypto.AccessToken) {
			token.Claims = map[string]interface{}{"cnf": map[string]interface{}{"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}
		}),
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			recorder := server.do(http.MethodGet, "/scim/v2/Users", "Bearer "+token, "")
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", recorder.Code, recorder.Body.String())
			}
			challenge := recorder.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, `Bearer realm="scim", error="invalid_token", error_description="`) {
				t.Errorf("WWW-Authenticate = %q, want an invalid_token Bearer challenge", challenge)
			}
			// RFC 6750 Section 3: error_description "MUST NOT include
			// characters outside the set %x20-21 / %x23-5B / %x5D-7E".
			description := strings.TrimSuffix(strings.SplitN(challenge, `error_description="`, 2)[1], `"`)
			for _, r := range description {
				if r < 0x20 || r > 0x7E || r == '"' || r == '\\' {
					t.Errorf("error_description %q has a character RFC 6750 Section 3 does not allow: %q", description, r)
				}
			}
			if status, _ := scimErrorBody(t, recorder)["status"].(string); status != "401" {
				t.Errorf("body status = %q, want \"401\"", status)
			}
		})
	}
}

// RFC 7644 Section 2: the service provider "MUST be able to map the
// authenticated client to an access control policy in order to determine the
// client's authorization to retrieve and update SCIM resources."
func TestScopeDecidesRetrievalAndUpdate(t *testing.T) {
	server := newAuthTestServer(t)
	read := "Bearer " + server.accessToken(t, nil)
	write := "Bearer " + server.accessToken(t, func(token *crypto.AccessToken) { token.Scope = ScopeWrite })
	both := "Bearer " + server.accessToken(t, func(token *crypto.AccessToken) { token.Scope = ScopeRead + " " + ScopeWrite })
	const user = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"scope.test@example.com"}`
	const search = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"userName pr"}`

	cases := []struct {
		name, method, path, authorization, body string
		want                                    int
		wantScope                               string
	}{
		{"read token retrieves", http.MethodGet, "/scim/v2/Users", read, "", http.StatusOK, ""},
		{"read token queries with POST", http.MethodPost, "/scim/v2/.search", read, search, http.StatusOK, ""},
		{"read token cannot create", http.MethodPost, "/scim/v2/Users", read, user, http.StatusForbidden, ScopeWrite},
		{"read token cannot delete", http.MethodDelete, "/scim/v2/Users/any", read, "", http.StatusForbidden, ScopeWrite},
		{"write token cannot retrieve", http.MethodGet, "/scim/v2/Users", write, "", http.StatusForbidden, ScopeRead},
		{"write token creates", http.MethodPost, "/scim/v2/Users", write, user, http.StatusCreated, ""},
		{"a token with both retrieves", http.MethodGet, "/scim/v2/Groups", both, "", http.StatusOK, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := server.do(testCase.method, testCase.path, testCase.authorization, testCase.body)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, testCase.want, recorder.Body.String())
			}
			if testCase.want != http.StatusForbidden {
				return
			}
			challenge := recorder.Header().Get("WWW-Authenticate")
			if !strings.Contains(challenge, `error="insufficient_scope"`) || !strings.HasSuffix(challenge, `scope="`+testCase.wantScope+`"`) {
				t.Errorf("WWW-Authenticate = %q, want insufficient_scope naming %s", challenge, testCase.wantScope)
			}
			if status, _ := scimErrorBody(t, recorder)["status"].(string); status != "403" {
				t.Errorf("body status = %q, want \"403\"", status)
			}
		})
	}
}

// RFC 7643 Section 5: "the service provider SHOULD, with the appropriate
// security considerations, make the authenticationSchemes attribute publicly
// accessible without prior authentication."
func TestServiceProviderConfigIsPublicAndNamesTheOneScheme(t *testing.T) {
	server := newAuthTestServer(t)
	recorder := server.do(http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without credentials: %s", recorder.Code, recorder.Body.String())
	}
	var config ServiceProviderConfig
	if err := json.Unmarshal(recorder.Body.Bytes(), &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(config.AuthenticationSchemes) != 1 || config.AuthenticationSchemes[0].Type != "oauthbearertoken" {
		t.Fatalf("authenticationSchemes = %#v, want the oauthbearertoken scheme alone", config.AuthenticationSchemes)
	}

	// The other discovery endpoints are not covered by that SHOULD, and
	// neither is the provisioning event log, which carries User attributes.
	for _, path := range []string{"/scim/v2/Schemas", "/scim/v2/ResourceTypes", "/scim/events"} {
		if got := server.do(http.MethodGet, path, "", "").Code; got != http.StatusUnauthorized {
			t.Errorf("GET %s without credentials = %d, want 401", path, got)
		}
	}
}

// RFC 7644 Section 4: "If a "filter" is provided, the service provider SHOULD
// respond with HTTP status code 403 (Forbidden)".
func TestFilteredDiscoveryQueryIsForbidden(t *testing.T) {
	server := newAuthTestServer(t)
	read := "Bearer " + server.accessToken(t, nil)
	for _, path := range []string{"/scim/v2/Schemas", "/scim/v2/ResourceTypes"} {
		if got := server.do(http.MethodGet, path, read, "").Code; got != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, got)
		}
		recorder := server.do(http.MethodGet, path+"?filter=name+eq+%22User%22", read, "")
		if recorder.Code != http.StatusForbidden {
			t.Errorf("GET %s with a filter = %d, want 403", path, recorder.Code)
		}
		if status, _ := scimErrorBody(t, recorder)["status"].(string); status != "403" {
			t.Errorf("body status = %q, want \"403\"", status)
		}
	}
}

// A service provider that runs apart from its authorization server validates
// with the JWK Set that server publishes (RFC 9068 Section 4).
func TestSplitServiceProviderValidatesWithTheAuthorizationServersJWKSet(t *testing.T) {
	as := newAuthTestServer(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(as.keySet.PublicJWKS())
	}))
	defer jwks.Close()

	t.Setenv("SCIM_DATA_DIR", t.TempDir())
	t.Setenv("SCIM_AS_JWKS_URI", jwks.URL)
	p := NewPlugin()
	if err := p.Initialize(context.Background(), plugin.PluginConfig{BaseURL: testOrigin}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	router := chi.NewRouter()
	router.Route("/scim", p.RegisterRoutes)
	split := &authTestServer{router: router}

	if got := split.do(http.MethodGet, "/scim/v2/Users", "Bearer "+as.accessToken(t, nil), "").Code; got != http.StatusOK {
		t.Errorf("valid token = %d, want 200", got)
	}
	wrongAudience := as.accessToken(t, func(token *crypto.AccessToken) { token.Audience = testOrigin })
	if got := split.do(http.MethodGet, "/scim/v2/Users", "Bearer "+wrongAudience, "").Code; got != http.StatusUnauthorized {
		t.Errorf("token for another resource = %d, want 401", got)
	}
}

func TestServiceProviderWithoutAnAuthorizationServerDoesNotStart(t *testing.T) {
	t.Setenv("SCIM_AS_JWKS_URI", "")
	t.Setenv("SCIM_DATA_DIR", t.TempDir())
	p := NewPlugin()
	err := p.Initialize(context.Background(), plugin.PluginConfig{BaseURL: testOrigin})
	if err == nil || !strings.Contains(err.Error(), "SCIM_AS_JWKS_URI") {
		t.Fatalf("initialize error = %v, want one naming SCIM_AS_JWKS_URI", err)
	}
}
