package oauth2

import (
	"net/http"
	"net/url"
	"testing"
)

func TestPasswordGrantIsUnsupported(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	demo, ok := server.idp.GetClient("demo-app")
	if !ok {
		t.Fatal("demo-app missing")
	}

	status, body := postClientAssertion(
		t,
		server.server.URL,
		url.Values{
			"grant_type":    {"password"},
			"username":      {"alice"},
			"password":      {"secret"},
			"client_id":     {"demo-app"},
			"client_secret": {demo.Secret},
		},
		"",
		"",
		"",
	)
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant = %d %#v", status, body)
	}
}
