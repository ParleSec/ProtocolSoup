package main

import (
	"net/url"
	"testing"
)

func TestClassifyOID4VCIProtocolHop(t *testing.T) {
	cases := []struct {
		rawURL string
		want   string
	}{
		{"https://issuer.example/oid4vci/.well-known/openid-credential-issuer", "Fetch Credential Issuer Metadata"},
		{"https://issuer.example/.well-known/oauth-authorization-server/oid4vci", "Fetch Authorization Server Metadata"},
		{"https://issuer.example/oid4vci/credential-offer/abc", "Fetch Credential Offer"},
		{"https://issuer.example/oid4vci/token", "Token Request"},
		{"https://issuer.example/oid4vci/nonce", "Nonce Request"},
		{"https://issuer.example/oid4vci/credential", "Credential Request"},
		{"https://issuer.example/oid4vci/deferred_credential", "Deferred Credential Poll"},
		{"https://issuer.example/oid4vci/notification", "Credential Status Notification"},
		{"https://issuer.example/api/.well-known/jwks.json", "Fetch Issuer JWKS"},
	}
	for _, testCase := range cases {
		parsed, err := url.Parse(testCase.rawURL)
		if err != nil {
			t.Fatalf("parse %q: %v", testCase.rawURL, err)
		}
		step, _ := classifyOID4VCIProtocolHop("POST", parsed)
		if step != testCase.want {
			t.Fatalf("%s: got %q, want %q", testCase.rawURL, step, testCase.want)
		}
	}
}
