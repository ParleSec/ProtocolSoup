package core_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
)

func TestOAuth2AuthorizationServerMetadataUsesCanonicalPathIssuerRule(t *testing.T) {
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
	if err := registry.InitializeAll(context.Background(), plugin.PluginConfig{
		BaseURL:      "https://as.example",
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: engine,
	}); err != nil {
		t.Fatal(err)
	}

	server := core.NewServer(&core.Config{
		BaseURL:     "https://as.example",
		CORSOrigins: []string{"https://client.example"},
	}, registry, engine, keySet)
	request := httptest.NewRequest(
		http.MethodGet,
		"https://as.example/.well-known/oauth-authorization-server/oauth2",
		nil,
	)
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["issuer"] != "https://as.example/oauth2" {
		t.Fatalf("issuer = %#v", metadata["issuer"])
	}
}
