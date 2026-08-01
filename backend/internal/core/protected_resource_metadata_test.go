package core_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/agentauth"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oidc"
)

func TestProtectedResourceMetadataDocuments(t *testing.T) {
	server := newMetadataTestServer(t)

	testCases := []struct {
		path             string
		wantResource     string
		wantAuthServers  []string
		wantScope        string
		wantBearerMethod string
	}{
		{
			path:             "/.well-known/oauth-protected-resource",
			wantResource:     "https://as.example",
			wantAuthServers:  []string{"https://as.example", "https://as.example/oauth2", "https://as.example/agentauth"},
			wantScope:        "openid",
			wantBearerMethod: "header",
		},
		{
			path:             "/.well-known/oauth-protected-resource/oidc/userinfo",
			wantResource:     "https://as.example/oidc/userinfo",
			wantAuthServers:  []string{"https://as.example"},
			wantScope:        "openid",
			wantBearerMethod: "header",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.path, func(t *testing.T) {
			metadata := getJSON(t, server, testCase.path)

			if metadata["resource"] != testCase.wantResource {
				t.Errorf("resource = %#v, want %q", metadata["resource"], testCase.wantResource)
			}
			if got := stringSlice(metadata["authorization_servers"]); !equalStrings(got, testCase.wantAuthServers) {
				t.Errorf("authorization_servers = %v, want %v", got, testCase.wantAuthServers)
			}
			if got := stringSlice(metadata["scopes_supported"]); !containsString(got, testCase.wantScope) {
				t.Errorf("scopes_supported = %v, want it to contain %q", got, testCase.wantScope)
			}
			if got := stringSlice(metadata["bearer_methods_supported"]); !containsString(got, testCase.wantBearerMethod) {
				t.Errorf("bearer_methods_supported = %v, want it to contain %q", got, testCase.wantBearerMethod)
			}
		})
	}
}

// RFC 9728 Section 3: the authorization servers advertised by the protected
// resource must actually publish metadata whose issuer matches.
func TestProtectedResourceAdvertisesResolvableAuthorizationServers(t *testing.T) {
	server := newMetadataTestServer(t)

	metadata := getJSON(t, server, "/.well-known/oauth-protected-resource")

	// RFC 8414 Section 3.1 well-known URL for each advertised issuer. An
	// issuer with no path component uses the bare suffix; one with a path
	// component has that component appended to it.
	metadataURLs := map[string]string{
		"https://as.example":           "/.well-known/oauth-authorization-server",
		"https://as.example/oauth2":    "/.well-known/oauth-authorization-server/oauth2",
		"https://as.example/agentauth": "/.well-known/oauth-authorization-server/agentauth",
	}

	for _, issuer := range stringSlice(metadata["authorization_servers"]) {
		metadataPath, known := metadataURLs[issuer]
		if !known {
			t.Fatalf("advertised authorization server %q has no known metadata URL", issuer)
		}
		document := getJSON(t, server, metadataPath)
		if document["issuer"] != issuer {
			t.Errorf("%s issuer = %#v, want %q", metadataPath, document["issuer"], issuer)
		}
	}
}

// OpenID Connect Discovery 1.0 Section 4 keeps the OP configuration at its own
// well-known location. Adding the RFC 8414 document for the same issuer must
// not displace it, and the two must agree on who the issuer is.
func TestOriginIssuerPublishesBothMetadataDocuments(t *testing.T) {
	server := newMetadataTestServer(t)

	oauthMetadata := getJSON(t, server, "/.well-known/oauth-authorization-server")
	openIDMetadata := getJSON(t, server, "/.well-known/openid-configuration")

	if oauthMetadata["issuer"] != "https://as.example" {
		t.Errorf("RFC 8414 issuer = %#v, want %q", oauthMetadata["issuer"], "https://as.example")
	}
	if oauthMetadata["issuer"] != openIDMetadata["issuer"] {
		t.Errorf("issuer mismatch: RFC 8414 has %#v, OpenID Connect Discovery has %#v",
			oauthMetadata["issuer"], openIDMetadata["issuer"])
	}
	if oauthMetadata["token_endpoint"] != openIDMetadata["token_endpoint"] {
		t.Errorf("token_endpoint mismatch: RFC 8414 has %#v, OpenID Connect Discovery has %#v",
			oauthMetadata["token_endpoint"], openIDMetadata["token_endpoint"])
	}
}

// The auth.md discovery skill has an agent read the agent_auth block from
// authorization server metadata, so every endpoint it names has to resolve.
func TestAgentAuthBlockIsPublishedAndResolvable(t *testing.T) {
	server := newMetadataTestServer(t)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/agentauth",
	} {
		metadata := getJSON(t, server, path)

		block, ok := metadata["agent_auth"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s has no agent_auth block", path)
		}

		for _, field := range []string{"skill", "register_uri", "identity_endpoint", "claim_uri", "revocation_uri"} {
			value, _ := block[field].(string)
			if value == "" {
				t.Errorf("%s agent_auth.%s is missing", path, field)
			}
		}

		if got := stringSlice(block["identity_types_supported"]); !containsString(got, "anonymous") {
			t.Errorf("%s agent_auth.identity_types_supported = %v, want it to contain %q", path, got, "anonymous")
		}

		anonymous, ok := block["anonymous"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s agent_auth has no anonymous registration method", path)
		}
		if got := stringSlice(anonymous["credential_types_supported"]); len(got) == 0 {
			t.Errorf("%s agent_auth.anonymous.credential_types_supported is empty", path)
		}
		if claimURI, _ := anonymous["claim_uri"].(string); claimURI == "" {
			t.Errorf("%s agent_auth.anonymous.claim_uri is missing", path)
		}
	}
}

// RFC 9728 Section 5.1: a rejected request points the client at the metadata.
func TestUserInfoChallengeAdvertisesResourceMetadata(t *testing.T) {
	server := newMetadataTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "https://as.example/oidc/userinfo", nil)
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}

	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") {
		t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", challenge)
	}
	wantParam := `resource_metadata="https://as.example/.well-known/oauth-protected-resource/oidc/userinfo"`
	if !strings.Contains(challenge, wantParam) {
		t.Errorf("WWW-Authenticate = %q, want it to contain %s", challenge, wantParam)
	}
}

func newMetadataTestServer(t *testing.T) *core.Server {
	t.Helper()

	keySet, err := internalcrypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	idp.SetIssuer("https://as.example")
	engine := lookingglass.NewEngine()
	registry := plugin.NewRegistry()
	oauthPlugin := oauth2.NewPlugin()
	if err := registry.Register(oauthPlugin); err != nil {
		t.Fatal(err)
	}
	oidcPlugin := oidc.NewPlugin(oauthPlugin)
	if err := registry.Register(oidcPlugin); err != nil {
		t.Fatal(err)
	}
	agentAuthPlugin := agentauth.NewPlugin()
	if err := registry.Register(agentAuthPlugin); err != nil {
		t.Fatal(err)
	}
	oidcPlugin.SetAgentAuthProvider(agentAuthPlugin)
	if err := registry.InitializeAll(context.Background(), plugin.PluginConfig{
		BaseURL:      "https://as.example",
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: engine,
	}); err != nil {
		t.Fatal(err)
	}

	return core.NewServer(&core.Config{
		BaseURL:     "https://as.example",
		CORSOrigins: []string{"https://client.example"},
	}, registry, engine, keySet)
}

func getJSON(t *testing.T, server *core.Server, path string) map[string]interface{} {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "https://as.example"+path, nil)
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, body = %s", path, response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("GET %s Content-Type = %q, want application/json", path, contentType)
	}

	var document map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return document
}

func stringSlice(value interface{}) []string {
	raw, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
