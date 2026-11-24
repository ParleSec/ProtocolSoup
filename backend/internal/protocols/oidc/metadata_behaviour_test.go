package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// These tests pin that the endpoints do what the OpenID Provider configuration
// and the RFC 8414 metadata for the same issuer say they do.

func metadataDocument(t *testing.T, handler http.HandlerFunc, path string) map[string]interface{} {
	t.Helper()
	rr := httptest.NewRecorder()
	handler(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("%s status = %d", path, rr.Code)
	}
	return decodeJSONObject(t, rr.Body.Bytes())
}

func TestTheTwoMetadataDocumentsAgree(t *testing.T) {
	p := newTestPlugin(t)
	provider := metadataDocument(t, p.handleDiscovery, "/.well-known/openid-configuration")
	server := metadataDocument(t, p.handleAuthorizationServerMetadata, authorizationServerWellKnown)

	shared := 0
	for name, value := range server {
		other, both := provider[name]
		if !both {
			continue
		}
		shared++
		if !reflect.DeepEqual(value, other) {
			t.Errorf("%s differs: openid-configuration %v, oauth-authorization-server %v", name, other, value)
		}
	}
	if shared < 15 {
		t.Fatalf("only %d members are in both documents; the comparison is not looking at them", shared)
	}

	for name, document := range map[string]map[string]interface{}{"openid-configuration": provider, "oauth-authorization-server": server} {
		if got := document["code_challenge_methods_supported"]; !reflect.DeepEqual(got, []interface{}{"S256"}) {
			t.Errorf("%s code_challenge_methods_supported = %v, want [S256]", name, got)
		}
	}
	// OpenID Connect Discovery 1.0 Section 3: "Servers SHOULD support none and RS256."
	if got := provider["request_object_signing_alg_values_supported"]; !reflect.DeepEqual(got, []interface{}{"none", "RS256"}) {
		t.Errorf("request_object_signing_alg_values_supported = %v, want [none RS256]", got)
	}
}

func authenticationRequest(extra url.Values) url.Values {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {testConfClient},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"st-1"},
		"nonce":         {"nonce-1"},
	}
	for name, values := range extra {
		if len(values) == 0 {
			params.Del(name)
			continue
		}
		params[name] = values
	}
	return params
}

// signIn posts alice's credentials for the login request on page and returns
// the response.
func signIn(t *testing.T, p *Plugin, page string) *httptest.ResponseRecorder {
	t.Helper()
	alice, ok := p.mockIdP.GetUser(testUserID)
	if !ok {
		t.Fatalf("seeded user %q not found", testUserID)
	}
	form := url.Values{
		"email":            {alice.Email},
		"password":         {alice.Password},
		"login_request_id": {extractLoginRequestID(t, page)},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleAuthorizePost(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("sign-in status = %d, want 302; body=%s", rr.Code, rr.Body.String())
	}
	return rr
}

// codeFlow runs the authorization code flow for the seeded confidential
// client and returns the Token Response.
func codeFlow(t *testing.T, p *Plugin, extra url.Values) map[string]interface{} {
	t.Helper()
	rr := doAuthorize(t, p, authenticationRequest(extra))
	if rr.Code != http.StatusOK {
		t.Fatalf("authorize status = %d; Location=%s", rr.Code, rr.Header().Get("Location"))
	}
	code := redirectParam(t, signIn(t, p, rr.Body.String()).Header().Get("Location"), "code")
	if code == "" {
		t.Fatal("no authorization code in the Authorization Response")
	}
	client, _ := p.mockIdP.GetClient(testConfClient)
	tr := postTokenForm(t, p, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
	}, testConfClient, client.Secret)
	if tr.Code != http.StatusOK {
		t.Fatalf("token status = %d; body=%s", tr.Code, tr.Body.String())
	}
	return decodeJSONObject(t, tr.Body.Bytes())
}

// RFC 7636 Section 4.4.1: "If the server supporting PKCE does not support the
// requested transformation, the authorization endpoint MUST return the
// authorization error response with "error" value set to "invalid_request"."
// Section 4.3 makes an absent code_challenge_method a request for plain.
func TestAuthorizationRefusesEveryPKCETransformationButS256(t *testing.T) {
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	for name, method := range map[string][]string{"plain": {"plain"}, "absent": nil, "unregistered": {"S512"}} {
		t.Run(name, func(t *testing.T) {
			p := newTestPlugin(t)
			rr := doAuthorize(t, p, authenticationRequest(url.Values{
				"code_challenge":        {challenge},
				"code_challenge_method": method,
			}))
			if rr.Code != http.StatusFound {
				t.Fatalf("status = %d, want a redirect carrying the error", rr.Code)
			}
			if got := locationError(t, rr.Header().Get("Location")).Get("error"); got != "invalid_request" {
				t.Fatalf("error = %q, want invalid_request (Location=%s)", got, rr.Header().Get("Location"))
			}
		})
	}

	p := newTestPlugin(t)
	rr := doAuthorize(t, p, authenticationRequest(url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("S256 status = %d, want the sign-in page", rr.Code)
	}
}

// OpenID Connect Core 1.0 Section 3.1.2.1: "Scope values used that are not
// understood by an implementation SHOULD be ignored."
func TestScopeValuesTheProviderDoesNotSupportAreIgnored(t *testing.T) {
	p := newTestPlugin(t)
	tokens := codeFlow(t, p, url.Values{"scope": {"openid made_up profile"}})
	if tokens["scope"] != "openid profile" {
		t.Fatalf("granted scope = %q, want %q", tokens["scope"], "openid profile")
	}
	if got := decodeJWTClaims(t, tokens["access_token"].(string))["scope"]; got != "openid profile" {
		t.Fatalf("access token scope = %q, want %q", got, "openid profile")
	}
}

// OpenID Connect Core 1.0 Section 11: the Authorization Server "MUST ignore
// the offline_access request unless the Client is using a response_type value
// that would result in an Authorization Code being returned", and ignores it
// unless the prompt parameter contains consent.
func TestOfflineAccessNeedsConsentOnARequestThatReturnsACode(t *testing.T) {
	t.Run("ignored without prompt=consent", func(t *testing.T) {
		tokens := codeFlow(t, newTestPlugin(t), url.Values{"scope": {"openid offline_access"}})
		if tokens["scope"] != "openid" {
			t.Fatalf("granted scope = %q, want openid", tokens["scope"])
		}
	})
	t.Run("granted with prompt=consent", func(t *testing.T) {
		tokens := codeFlow(t, newTestPlugin(t), url.Values{"scope": {"openid offline_access"}, "prompt": {"consent"}})
		if tokens["scope"] != "openid offline_access" {
			t.Fatalf("granted scope = %q, want openid offline_access", tokens["scope"])
		}
	})
	t.Run("ignored when no code is returned", func(t *testing.T) {
		granted, ignored := grantedScope("openid offline_access", []string{"consent"}, "id_token token")
		if granted != "openid" || len(ignored) != 1 || ignored[0].Value != "offline_access" {
			t.Fatalf("granted = %q, ignored = %+v", granted, ignored)
		}
	})
	t.Run("granted for a hybrid response type that returns a code", func(t *testing.T) {
		granted, ignored := grantedScope("openid offline_access", []string{"consent"}, "code id_token")
		if granted != "openid offline_access" || len(ignored) != 0 {
			t.Fatalf("granted = %q, ignored = %+v", granted, ignored)
		}
	})
}

// OpenID Connect Core 1.0 Section 3.1.2.1, prompt=consent: "The Authorization
// Server SHOULD prompt the End-User for consent before returning information
// to the Client."
func TestPromptConsentIsNotCompletedFromASessionAlone(t *testing.T) {
	p := newTestPlugin(t)
	first := doAuthorize(t, p, authenticationRequest(nil))
	cookies := signIn(t, p, first.Body.String()).Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("the sign-in set no session cookie")
	}
	withSession := func(extra url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authenticationRequest(extra).Encode(), nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		p.handleAuthorize(rr, req)
		return rr
	}

	// The session alone completes a max_age request, which is what makes the
	// consent case below a real check.
	if rr := withSession(url.Values{"max_age": {"3600"}}); rr.Code != http.StatusFound {
		t.Fatalf("max_age within the session's age: status = %d, want a redirect with the code", rr.Code)
	}
	rr := withSession(url.Values{"max_age": {"3600"}, "prompt": {"consent"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "login_request_id") {
		t.Fatalf("prompt=consent: status = %d, want the sign-in page that names the requested scopes", rr.Code)
	}
}

// OpenID Connect Core 1.0 Section 5.5: "id_token OPTIONAL. Requests that the
// listed individual Claims be returned in the ID Token."
func TestCodeFlowIDTokenCarriesIndividuallyRequestedClaims(t *testing.T) {
	p := newTestPlugin(t)
	alice, _ := p.mockIdP.GetUser(testUserID)

	tokens := codeFlow(t, p, url.Values{"claims": {`{"id_token":{"email":null}}`}})
	claims := decodeJWTClaims(t, tokens["id_token"].(string))
	if claims["email"] != alice.Email {
		t.Fatalf("ID Token email = %v, want %q", claims["email"], alice.Email)
	}
	if claims["sub"] == "" || claims["nonce"] != "nonce-1" {
		t.Fatalf("the requested claim must add to the default claims, got %v", claims)
	}

	tokens = codeFlow(t, p, nil)
	if _, present := decodeJWTClaims(t, tokens["id_token"].(string))["email"]; present {
		t.Fatal("email was not requested for the ID Token and the scope is openid alone")
	}
}

func unsecuredRequestObject(t *testing.T, claims map[string]interface{}, signature string) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"none"}`)) + "." + encode(payload) + "." + signature
}

// OpenID Connect Dynamic Client Registration 1.0 Section 2, on
// request_object_signing_alg: "All Request Objects from this Client MUST be
// rejected, if not signed with this algorithm." and "The value none MAY be
// used."
func TestUnsignedRequestObjectIsAcceptedOnlyFromAClientRegisteredForNone(t *testing.T) {
	p := newTestPlugin(t)
	claims := map[string]interface{}{"client_id": "rp", "iss": "rp", "aud": p.mockIdP.GetIssuer(), "scope": "openid"}
	unsigned := unsecuredRequestObject(t, claims, "")

	got, err := p.verifyRequestObjectJWT(unsigned, &models.Client{ID: "rp", RequestObjectSigningAlg: "none"})
	if err != nil || got["scope"] != "openid" {
		t.Fatalf("registered for none: claims = %v, err = %v", got, err)
	}
	for name, client := range map[string]*models.Client{
		"registered for RS256":    {ID: "rp", RequestObjectSigningAlg: "RS256"},
		"registered no algorithm": {ID: "rp"},
	} {
		if _, err := p.verifyRequestObjectJWT(unsigned, client); err == nil {
			t.Errorf("%s: an unsigned Request Object must be refused", name)
		}
	}
	if _, err := p.verifyRequestObjectJWT(unsecuredRequestObject(t, claims, "c2ln"), &models.Client{ID: "rp", RequestObjectSigningAlg: "none"}); err == nil {
		t.Error("alg none with a signature is not an Unsecured JWT and must be refused")
	}
	claims["iss"] = "someone-else"
	if _, err := p.verifyRequestObjectJWT(unsecuredRequestObject(t, claims, ""), &models.Client{ID: "rp", RequestObjectSigningAlg: "none"}); err == nil {
		t.Error("the iss check applies to an unsigned Request Object too")
	}

	for _, alg := range []string{"none", "RS256"} {
		if err := validateRegistrationRequest(&registrationRequest{RedirectURIs: []string{"https://rp.example/cb"}, RequestObjectSigningAlg: alg}); err != nil {
			t.Errorf("registering request_object_signing_alg %s: %v", alg, err)
		}
	}
	if err := validateRegistrationRequest(&registrationRequest{RedirectURIs: []string{"https://rp.example/cb"}, RequestObjectSigningAlg: "HS256"}); err == nil {
		t.Error("an algorithm the OP does not advertise must be refused at registration")
	}
}
