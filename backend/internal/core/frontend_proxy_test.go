package core_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oidc"
)

// The agent discovery documents (RFC 9727 api-catalog, agent skills index,
// auth.md) are served by the Next.js runtime, but public ingress terminates on
// this server. Registering protocol well-known routes must not shadow the
// catch-all proxy for sibling well-known paths the backend does not own.
func TestFrontendProxyReceivesUnregisteredWellKnownPaths(t *testing.T) {
	var receivedPath atomic.Value
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath.Store(r.URL.Path)
		w.Header().Set("X-Served-By", "frontend")
		w.WriteHeader(http.StatusOK)
	}))
	defer frontend.Close()

	server := newProxyTestServer(t, frontend.URL)

	proxiedPaths := []string{
		"/.well-known/api-catalog",
		"/.well-known/agent-skills/index.json",
		"/.well-known/agent-skills/run-protocol-flow/SKILL.md",
		"/auth.md",
		"/robots.txt",
		"/llms.txt",
		"/",
	}

	for _, path := range proxiedPaths {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://as.example"+path, nil)
			response := httptest.NewRecorder()
			server.Router().ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body = %s)", response.Code, response.Body.String())
			}
			if got := response.Header().Get("X-Served-By"); got != "frontend" {
				t.Fatalf("X-Served-By = %q, want %q: path was not proxied to the frontend", got, "frontend")
			}
			if got, _ := receivedPath.Load().(string); got != path {
				t.Fatalf("frontend received path = %q, want %q", got, path)
			}
		})
	}
}

// The backend owns these well-known paths and must keep answering them itself
// rather than handing them to the frontend.
func TestBackendRetainsProtocolWellKnownPaths(t *testing.T) {
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "frontend")
		w.WriteHeader(http.StatusOK)
	}))
	defer frontend.Close()

	server := newProxyTestServer(t, frontend.URL)

	backendPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server/oauth2",
		"/health",
		"/api",
	}

	for _, path := range backendPaths {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://as.example"+path, nil)
			response := httptest.NewRecorder()
			server.Router().ServeHTTP(response, request)

			if got := response.Header().Get("X-Served-By"); got == "frontend" {
				t.Fatalf("path %q was proxied to the frontend but must be served by the backend", path)
			}
		})
	}
}

// A page can answer with HTML or markdown depending on Accept, so the proxied
// HTML response must tell caches to key on that header.
func TestFrontendProxyMarksHTMLResponsesVaryingOnAccept(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		upstreamary string
		wantAccept  bool
	}{
		{name: "html gains Accept", contentType: "text/html; charset=utf-8", wantAccept: true},
		{
			name:        "html keeps existing fields",
			contentType: "text/html; charset=utf-8",
			upstreamary: "rsc, Accept-Encoding",
			wantAccept:  true,
		},
		{
			name:        "html already varying on Accept is untouched",
			contentType: "text/html; charset=utf-8",
			upstreamary: "Accept",
			wantAccept:  true,
		},
		{name: "json is left alone", contentType: "application/json", wantAccept: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", testCase.contentType)
				if testCase.upstreamary != "" {
					w.Header().Set("Vary", testCase.upstreamary)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer frontend.Close()

			server := newProxyTestServer(t, frontend.URL)
			request := httptest.NewRequest(http.MethodGet, "https://as.example/protocols", nil)
			response := httptest.NewRecorder()
			server.Router().ServeHTTP(response, request)

			varyFields := strings.Join(response.Header().Values("Vary"), ", ")
			gotAccept := false
			for _, field := range strings.Split(varyFields, ",") {
				if strings.EqualFold(strings.TrimSpace(field), "Accept") {
					gotAccept = true
				}
			}

			if gotAccept != testCase.wantAccept {
				t.Fatalf("Vary = %q, want Accept present = %v", varyFields, testCase.wantAccept)
			}
			// Existing field values must survive.
			if testCase.upstreamary == "rsc, Accept-Encoding" && !strings.Contains(varyFields, "rsc") {
				t.Errorf("Vary = %q, want it to retain the upstream fields", varyFields)
			}
		})
	}
}

func newProxyTestServer(t *testing.T, frontendOrigin string) *core.Server {
	t.Helper()

	keySet, err := internalcrypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	engine := lookingglass.NewEngine()
	registry := plugin.NewRegistry()
	oauthPlugin := oauth2.NewPlugin()
	if err := registry.Register(oauthPlugin); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(oidc.NewPlugin(oauthPlugin)); err != nil {
		t.Fatal(err)
	}
	if err := registry.InitializeAll(context.Background(), plugin.PluginConfig{
		BaseURL:      "https://as.example",
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: engine,
	}); err != nil {
		t.Fatal(err)
	}

	return core.NewServer(&core.Config{
		BaseURL:        "https://as.example",
		CORSOrigins:    []string{"https://client.example"},
		FrontendOrigin: frontendOrigin,
	}, registry, engine, keySet)
}
