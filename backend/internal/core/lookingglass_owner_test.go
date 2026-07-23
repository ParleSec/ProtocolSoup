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
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
)

func TestLookingGlassOwnerAPIContract(t *testing.T) {
	keySet, err := internalcrypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	engine := lookingglass.NewEngine()
	registry := plugin.NewRegistry()
	if err := registry.Register(oauth2.NewPlugin()); err != nil {
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
	router := server.Router()

	startRequest := httptest.NewRequest(
		http.MethodPost,
		"https://as.example/api/protocols/oauth2/demo/client_credentials",
		nil,
	)
	startResponse := httptest.NewRecorder()
	router.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", startResponse.Code, startResponse.Body.String())
	}
	var started map[string]interface{}
	if err := json.Unmarshal(startResponse.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	sessionID, _ := started["session_id"].(string)
	ownerToken, _ := started["session_token"].(string)
	if sessionID == "" || len(ownerToken) != 43 {
		t.Fatalf("start response = %#v", started)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "https://as.example/api/lookingglass/sessions", nil)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d", listResponse.Code)
	}
	if strings.Contains(listResponse.Body.String(), "events") ||
		strings.Contains(listResponse.Body.String(), ownerToken) {
		t.Fatalf("list exposed owner-only data: %s", listResponse.Body.String())
	}

	sessionURL := "https://as.example/api/lookingglass/sessions/" + sessionID
	ownerlessRequest := httptest.NewRequest(http.MethodGet, sessionURL, nil)
	ownerlessResponse := httptest.NewRecorder()
	router.ServeHTTP(ownerlessResponse, ownerlessRequest)
	if ownerlessResponse.Code != http.StatusUnauthorized {
		t.Fatalf("ownerless GET status = %d", ownerlessResponse.Code)
	}

	ownedRequest := httptest.NewRequest(http.MethodGet, sessionURL, nil)
	ownedRequest.Header.Set(lookingglass.OwnerTokenHeader, ownerToken)
	ownedResponse := httptest.NewRecorder()
	router.ServeHTTP(ownedResponse, ownedRequest)
	if ownedResponse.Code != http.StatusOK ||
		!strings.Contains(ownedResponse.Body.String(), `"events"`) {
		t.Fatalf("owned GET status = %d, body = %s", ownedResponse.Code, ownedResponse.Body.String())
	}
}
