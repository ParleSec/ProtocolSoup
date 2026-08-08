package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

func TestHealthReportsDeployedCommit(t *testing.T) {
	server := NewServer(&Config{BuildCommit: "0123456789abcdef"}, plugin.NewRegistry(), nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	server.handleHealth(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", response.Code)
	}
	var payload HealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if payload.Commit != "0123456789abcdef" {
		t.Fatalf("health commit = %q", payload.Commit)
	}
}
