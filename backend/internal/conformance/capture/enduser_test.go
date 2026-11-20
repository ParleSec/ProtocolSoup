package capture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthorizeAsEndUserDeliversTheResponseToTheWallet proves the End-User
// leg is played against the authorization server without being recorded, and
// that the Authorization Response reaches the wallet's callback as a recorded
// JSON call followed by the wallet's own hops.
func TestAuthorizeAsEndUserDeliversTheResponseToTheWallet(t *testing.T) {
	var walletURL string
	var posted map[string]string
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/oidc/authorize":
			if r.URL.Query().Get("request_uri") == "" {
				t.Errorf("the Authorization Request lost its query: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<form method="POST" action="/oidc/authorize"><input type="hidden" name="login_request_id" value="lr-1"></form>`))
		case r.Method == http.MethodGet && r.URL.Path == "/oauth2/demo/users":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{
				{"id": "alice", "credentials": map[string]string{"email": "alice@example.com", "password": "pw"}},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/oidc/authorize":
			_ = r.ParseForm()
			posted = map[string]string{"login_request_id": r.PostForm.Get("login_request_id"), "email": r.PostForm.Get("email"), "password": r.PostForm.Get("password")}
			http.Redirect(w, r, walletURL+"/api/oid4vci/callback?code=c1&state=s1&iss=https%3A%2F%2Fas.example", http.StatusFound)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer as.Close()
	wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/oid4vci/callback" || r.URL.Query().Get("code") != "c1" || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-Wallet-Session") != "conformance-x" {
			t.Errorf("unexpected wallet request %s %s %v", r.Method, r.URL, r.Header)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "success",
			"credential_jwt": "eyJ.credential",
			"_protocol_exchanges": []map[string]any{{
				"step": "Token Request", "method": "POST", "url": "https://as.example/oid4vci/token",
				"request_body": "grant_type=authorization_code&code=c1", "response_status": 200, "response_body": `{"access_token":"t"}`,
			}},
		})
	}))
	defer wallet.Close()
	walletURL = wallet.URL

	recorder := NewRecorder(nil)
	env := NewEnv(as.URL, wallet.URL, "", recorder, 6000)
	result, response, err := AuthorizeAsEndUser(context.Background(), env, as.URL+"/oidc/authorize?client_id=w&request_uri=urn%3Ar", "conformance-x")
	if err != nil {
		t.Fatalf("AuthorizeAsEndUser: %v", err)
	}
	if result.Status != http.StatusOK || result.Body["credential_jwt"] != "eyJ.credential" || result.Hop("Token Request") == nil {
		t.Fatalf("unexpected callback result %+v", result)
	}
	if response.Get("code") != "c1" || response.Get("state") != "s1" || response.Get("iss") != "https://as.example" {
		t.Fatalf("Authorization Response parameters = %v", response)
	}
	if posted["login_request_id"] != "lr-1" || posted["email"] != "alice@example.com" || posted["password"] != "pw" {
		t.Fatalf("the login form was posted as %v", posted)
	}
	exchanges := recorder.Take()
	if len(exchanges) != 2 {
		t.Fatalf("want the callback call and one wallet hop recorded, got %d", len(exchanges))
	}
	if exchanges[0].Request.Method != http.MethodGet || exchanges[0].Request.URL != wallet.URL+"/api/oid4vci/callback?code=c1&state=s1&iss=https%3A%2F%2Fas.example" {
		t.Fatalf("the first recorded exchange is not the Authorization Response delivered to the wallet: %+v", exchanges[0].Request)
	}
	if exchanges[1].Meta.CaptureSource != "hosted_wallet" || exchanges[1].Request.Body.Data != "grant_type=authorization_code&code=c1" {
		t.Fatalf("the wallet's Token Request hop was not lifted: %+v", exchanges[1])
	}
}

// TestAuthorizeAsEndUserRefusesAResponseSentElsewhere proves an
// Authorization Response redirected anywhere but the wallet's callback is an
// error, not a request the client follows.
func TestAuthorizeAsEndUserRefusesAResponseSentElsewhere(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/oauth2/demo/users":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"credentials": map[string]string{"email": "a@example.com", "password": "pw"}}}})
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`<input type="hidden" name="login_request_id" value="lr-2">`))
		default:
			http.Redirect(w, r, "https://elsewhere.example/callback?code=c1", http.StatusFound)
		}
	}))
	defer as.Close()
	recorder := NewRecorder(nil)
	env := NewEnv(as.URL, "http://wallet.localhost", "", recorder, 6000)
	if _, _, err := AuthorizeAsEndUser(context.Background(), env, as.URL+"/oidc/authorize?client_id=w", "conformance-y"); err == nil {
		t.Fatal("a response sent elsewhere must be refused")
	}
	if len(recorder.Take()) != 0 {
		t.Fatal("nothing of the End-User leg may be recorded")
	}
}
