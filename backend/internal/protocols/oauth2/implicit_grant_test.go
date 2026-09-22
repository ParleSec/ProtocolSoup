package oauth2

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestImplicitGrantReturnsAccessTokenInFragment(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	server.plugin.baseURL = "https://as.example"
	email, password := demoUserCredentials(t, server, "alice")
	redirectURI := "http://localhost:3000/callback"

	loginRequestID := implicitLoginRequestID(t, server.server.URL, url.Values{
		"response_type":  {"token"},
		"client_id":      {"public-app"},
		"redirect_uri":   {redirectURI},
		"scope":          {"profile"},
		"state":          {"csrf-state"},
		"code_challenge": {"ignored-because-there-is-no-code"},
	})

	location := submitImplicitLogin(t, server.server.URL, loginRequestID, email, password)
	if !strings.HasPrefix(location, redirectURI+"#") {
		t.Fatalf("location = %q, want fragment on %s", location, redirectURI)
	}
	if strings.Contains(strings.SplitN(location, "#", 2)[0], "access_token") {
		t.Fatalf("access token leaked into the query: %s", location)
	}

	fragment, err := url.ParseQuery(strings.SplitN(location, "#", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	accessToken := fragment.Get("access_token")
	if len(strings.Split(accessToken, ".")) != 3 {
		t.Fatalf("access_token = %q, want a JWT", accessToken)
	}
	if fragment.Get("token_type") != "Bearer" {
		t.Fatalf("token_type = %q", fragment.Get("token_type"))
	}
	if fragment.Get("expires_in") != "3600" {
		t.Fatalf("expires_in = %q", fragment.Get("expires_in"))
	}
	if fragment.Get("scope") != "profile" {
		t.Fatalf("scope = %q", fragment.Get("scope"))
	}
	if fragment.Get("state") != "csrf-state" {
		t.Fatalf("state = %q", fragment.Get("state"))
	}
	if fragment.Get("iss") != "https://as.example/oauth2" {
		t.Fatalf("iss = %q", fragment.Get("iss"))
	}
	if fragment.Get("refresh_token") != "" || fragment.Has("refresh_token") || fragment.Get("code") != "" {
		t.Fatalf("implicit response must not include a refresh token or code: %#v", fragment)
	}
}

func TestImplicitGrantRejectsConfidentialClientInFragment(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	redirectURI := "http://localhost:3000/callback"
	status, location, body := getAuthorize(t, server.server.URL, url.Values{
		"response_type": {"token"},
		"client_id":     {"demo-app"},
		"redirect_uri":  {redirectURI},
		"scope":         {"profile"},
		"state":         {"csrf-state"},
	})
	if status != http.StatusFound {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	if !strings.HasPrefix(location, redirectURI+"#") {
		t.Fatalf("location = %q", location)
	}
	fragment, err := url.ParseQuery(strings.SplitN(location, "#", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Get("error") != "unauthorized_client" {
		t.Fatalf("error = %q", fragment.Get("error"))
	}
	if fragment.Get("state") != "csrf-state" {
		t.Fatalf("state = %q", fragment.Get("state"))
	}
	if fragment.Get("access_token") != "" {
		t.Fatalf("access token issued to confidential client: %s", location)
	}
}

func TestImplicitGrantDoesNotRedirectInvalidClientOrRedirectURI(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	cases := []url.Values{
		{
			"response_type": {"token"},
			"redirect_uri":  {"http://localhost:3000/callback"},
			"state":         {"csrf-state"},
		},
		{
			"response_type": {"token"},
			"client_id":     {"missing-client"},
			"redirect_uri":  {"http://localhost:3000/callback"},
		},
		{
			"response_type": {"token"},
			"client_id":     {"public-app"},
			"redirect_uri":  {"https://evil.example/callback"},
		},
		{
			"response_type": {"token"},
			"client_id":     {"public-app"},
		},
	}
	for _, query := range cases {
		status, location, body := getAuthorize(t, server.server.URL, query)
		if status == http.StatusFound || location != "" {
			t.Fatalf("query %v redirected to %q", query, location)
		}
		if status != http.StatusBadRequest || !strings.Contains(body, `"error"`) {
			t.Fatalf("query %v status = %d body = %s", query, status, body)
		}
		if strings.Contains(body, "https://evil.example") {
			t.Fatalf("error body echoed an unregistered redirect: %s", body)
		}
	}
}

func TestImplicitGrantInvalidScopeUsesFragment(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	redirectURI := "http://localhost:3000/callback"
	status, location, body := getAuthorize(t, server.server.URL, url.Values{
		"response_type": {"token"},
		"client_id":     {"public-app"},
		"redirect_uri":  {redirectURI},
		"scope":         {"api:write"},
		"state":         {"csrf-state"},
	})
	if status != http.StatusFound {
		t.Fatalf("status = %d body = %s", status, body)
	}
	fragment, err := url.ParseQuery(strings.SplitN(location, "#", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Get("error") != "invalid_scope" {
		t.Fatalf("error = %q location = %s", fragment.Get("error"), location)
	}
	if fragment.Get("access_token") != "" {
		t.Fatal("token issued for an unregistered scope")
	}
}

func TestUnsupportedResponseTypeUsesFragmentOnlyWhenRedirectIsRegistered(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	redirectURI := "http://localhost:3000/callback"
	status, location, _ := getAuthorize(t, server.server.URL, url.Values{
		"response_type": {"id_token"},
		"client_id":     {"public-app"},
		"redirect_uri":  {redirectURI},
		"state":         {"csrf-state"},
	})
	if status != http.StatusFound {
		t.Fatalf("status = %d", status)
	}
	fragment, err := url.ParseQuery(strings.SplitN(location, "#", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if fragment.Get("error") != "unsupported_response_type" || fragment.Get("state") != "csrf-state" {
		t.Fatalf("fragment = %#v", fragment)
	}

	status, location, body := getAuthorize(t, server.server.URL, url.Values{
		"response_type": {"id_token"},
		"client_id":     {"public-app"},
		"redirect_uri":  {"https://evil.example/callback"},
	})
	if status == http.StatusFound || location != "" {
		t.Fatalf("unregistered redirect was followed: %s", location)
	}
	if !strings.Contains(body, "unsupported_response_type") {
		t.Fatalf("body = %s", body)
	}
}

func TestImplicitGrantTypeIsNotAcceptedAtTokenEndpoint(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	status, body := postClientAssertion(t, server.server.URL, url.Values{
		"grant_type": {"implicit"},
		"client_id":  {"public-app"},
	}, "", "", "")
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("token endpoint implicit grant = %d %#v", status, body)
	}
}

func demoUserCredentials(t *testing.T, server *oauthAssertionTestServer, userID string) (string, string) {
	t.Helper()
	for _, preset := range server.idp.GetDemoUserPresets() {
		if preset.ID == userID {
			return preset.Credentials.Email, preset.Credentials.Password
		}
	}
	t.Fatalf("demo user %s missing", userID)
	return "", ""
}

func implicitLoginRequestID(t *testing.T, serverURL string, query url.Values) string {
	t.Helper()
	status, location, body := getAuthorize(t, serverURL, query)
	if status != http.StatusOK {
		t.Fatalf("authorize status = %d location = %q body = %s", status, location, body)
	}
	if !strings.Contains(body, "OAuth 2.0 Implicit Grant") {
		t.Fatal("login page subtitle missing")
	}
	const marker = `name="login_request_id" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("login_request_id missing: %s", body)
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end <= 0 {
		t.Fatal("login_request_id not terminated")
	}
	return rest[:end]
}

func submitImplicitLogin(t *testing.T, serverURL, loginRequestID, email, password string) string {
	t.Helper()
	form := url.Values{
		"login_request_id": {loginRequestID},
		"email":            {email},
		"password":         {password},
	}
	request, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := noRedirectClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d body = %s", response.StatusCode, payload)
	}
	location := response.Header.Get("Location")
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %q %q", response.Header.Get("Cache-Control"), response.Header.Get("Pragma"))
	}
	return location
}

func getAuthorize(t *testing.T, serverURL string, query url.Values) (int, string, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, serverURL+"/oauth2/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.URL.RawQuery = query.Encode()
	response, err := noRedirectClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Get("Location"), string(payload)
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
