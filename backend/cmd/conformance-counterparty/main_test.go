package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	handler, err := newServer(config{baseURL: "http://counterparty.test", commit: "abc123"})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestEveryResponseCarriesTheCounterpartyNotice(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/", "/health", "/robots.txt", "/no-such-route"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("X-Conformance-Counterparty") != notice {
			t.Fatalf("GET %s: missing the counterparty notice header", path)
		}
		if resp.Header.Get("X-Robots-Tag") != "noindex, nofollow" {
			t.Fatalf("GET %s: missing X-Robots-Tag", path)
		}
	}
}

func TestHealthReportsTheBuildCommit(t *testing.T) {
	server := newTestServer(t)
	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	var health map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if resp.StatusCode != http.StatusOK || health["status"] != "ok" || health["commit"] != "abc123" {
		t.Fatalf("health = %d %v", resp.StatusCode, health)
	}
}

func TestIndexSaysWhatTheServiceIs(t *testing.T) {
	server := newTestServer(t)
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if !strings.HasPrefix(string(body), notice) {
		t.Fatalf("index does not start with the notice: %q", body)
	}
}

func TestLoadConfigAcceptsOnlyAnOriginAsTheBaseURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://protocolsoup-counterparty.fly.dev":  true,
		"https://protocolsoup-counterparty.fly.dev/": true,
		"http://localhost:8282":                      true,
		"https://counterparty.example/scenarios":     false,
		"https://user@counterparty.example":          false,
		"ftp://counterparty.example":                 false,
		"counterparty.example":                       false,
	} {
		t.Setenv("COUNTERPARTY_BASE_URL", raw)
		_, err := loadConfig()
		if (err == nil) != ok {
			t.Fatalf("loadConfig(%q) err = %v, want ok=%v", raw, err, ok)
		}
	}
}
