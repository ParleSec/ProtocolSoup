package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newFakeUpstream(t *testing.T, name string, protocolIDs ...string) *httptest.Server {
	t.Helper()
	protocols := make([]ProtocolSummary, 0, len(protocolIDs))
	for _, id := range protocolIDs {
		protocols = append(protocols, ProtocolSummary{ID: id})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/protocols" {
			_ = json.NewEncoder(w).Encode(protocolListResponse{Protocols: protocols})
			return
		}
		w.Header().Set("X-Upstream", name)
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestWellKnownRoutesReachOwningUpstream(t *testing.T) {
	federation := newFakeUpstream(t, "federation", "oauth2", "oidc", "oid4vci", "oid4vp")
	ssf := newFakeUpstream(t, "ssf", "ssf")

	gw, err := NewGateway(Config{Upstreams: []UpstreamConfig{
		{Name: "federation", BaseURL: federation.URL},
		{Name: "ssf", BaseURL: ssf.URL},
	}})
	if err != nil {
		t.Fatal(err)
	}
	router := gw.Router()

	tests := []struct {
		path         string
		wantUpstream string
	}{
		{"/.well-known/openid-credential-issuer/oid4vci", "federation"},
		{"/.well-known/openid-credential-issuer/oid4vci/", "federation"},
		{"/.well-known/oauth-authorization-server/oid4vci", "federation"},
		{"/.well-known/oauth-authorization-server/oauth2", "federation"},
		{"/.well-known/oauth-protected-resource/oidc/userinfo", "federation"},
		{"/.well-known/openid-configuration", "federation"},
		{"/.well-known/oauth-authorization-server", "federation"},
		{"/.well-known/oauth-protected-resource", "federation"},
		{"/.well-known/ssf-configuration", "ssf"},
		{"/oid4vci/.well-known/openid-credential-issuer", "federation"},
		{"/.well-known/openid-credential-issuer", ""},
		{"/.well-known/openid-credential-issuer/unknown", ""},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))

			gotUpstream := response.Header().Get("X-Upstream")
			if tc.wantUpstream == "" {
				if response.Code != http.StatusNotFound || gotUpstream != "" {
					t.Fatalf("status = %d, upstream = %q; want 404 without proxying", response.Code, gotUpstream)
				}
				return
			}
			if gotUpstream != tc.wantUpstream {
				t.Fatalf("status = %d, upstream = %q; want %q", response.Code, gotUpstream, tc.wantUpstream)
			}
			if gotPath := response.Header().Get("X-Upstream-Path"); gotPath != tc.path {
				t.Fatalf("upstream path = %q; want %q unchanged", gotPath, tc.path)
			}
		})
	}
}
