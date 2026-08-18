package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newDiscoveryTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := &walletHarnessServer{
		targetBaseURL: "https://protocolsoup.com",
	}
	mux := http.NewServeMux()
	server.registerRoutes(mux)
	return httptest.NewServer(mux)
}

func TestWalletAgentDiscoverySurfaces(t *testing.T) {
	ts := newDiscoveryTestServer(t)
	defer ts.Close()

	t.Run("llms.txt", func(t *testing.T) {
		resp, body := getDiscovery(t, ts, "/llms.txt")
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("content-type = %q", ct)
		}
		for _, needle := range []string{"Wallet Harness", "/llms-full.txt", "not an MCP server", "/health"} {
			if !strings.Contains(body, needle) {
				t.Fatalf("llms.txt missing %q\n%s", needle, body)
			}
		}
	})

	t.Run("robots.txt", func(t *testing.T) {
		_, body := getDiscovery(t, ts, "/robots.txt")
		if !strings.Contains(body, "Content-Signal: search=yes, ai-input=yes, ai-train=no") {
			t.Fatalf("robots.txt missing content signal\n%s", body)
		}
		if !strings.Contains(body, "Disallow: /api/") {
			t.Fatalf("robots.txt should keep API paths out of the index")
		}
	})

	t.Run("api-catalog", func(t *testing.T) {
		resp, body := getDiscovery(t, ts, "/.well-known/api-catalog")
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/linkset+json") {
			t.Fatalf("content-type = %q", ct)
		}
		var payload struct {
			Linkset []map[string]interface{} `json:"linkset"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("catalog json: %v\n%s", err, body)
		}
		if len(payload.Linkset) != 1 {
			t.Fatalf("linkset len = %d", len(payload.Linkset))
		}
	})

	t.Run("agent skill digest matches artifact", func(t *testing.T) {
		_, indexBody := getDiscovery(t, ts, "/.well-known/agent-skills/index.json")
		var index struct {
			Skills []struct {
				Name   string `json:"name"`
				URL    string `json:"url"`
				Digest string `json:"digest"`
			} `json:"skills"`
		}
		if err := json.Unmarshal([]byte(indexBody), &index); err != nil {
			t.Fatalf("index json: %v\n%s", err, indexBody)
		}
		if len(index.Skills) != 1 || index.Skills[0].Name != walletAgentSkillName {
			t.Fatalf("skills = %#v", index.Skills)
		}
		_, skillBody := getDiscovery(t, ts, "/.well-known/agent-skills/"+walletAgentSkillName+"/SKILL.md")
		wantDigest := "sha256:" + sha256Hex(skillBody)
		if index.Skills[0].Digest != wantDigest {
			t.Fatalf("digest %s != artifact %s", index.Skills[0].Digest, wantDigest)
		}
		if !strings.Contains(skillBody, "POST "+ts.URL+"/api/import") {
			t.Fatalf("skill missing import recipe\n%s", skillBody)
		}
		if !strings.Contains(skillBody, "backend/cmd/walletharness/agent-skills/use-wallet-harness.md") {
			t.Fatalf("skill missing pin URL\n%s", skillBody)
		}
	})

	t.Run("unknown skill is 404", func(t *testing.T) {
		resp, _ := getDiscovery(t, ts, "/.well-known/agent-skills/not-a-skill/SKILL.md")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
}

func TestWalletHomepageMarkdownNegotiation(t *testing.T) {
	ts := newDiscoveryTestServer(t)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/markdown")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(resp.Header.Get("Link"), `rel="api-catalog"`) {
		t.Fatalf("missing api-catalog link header: %q", resp.Header.Get("Link"))
	}
	if !strings.Contains(resp.Header.Get("Link"), `title="llms.txt"`) {
		t.Fatalf("missing llms.txt alternate link: %q", resp.Header.Get("Link"))
	}
	if !strings.Contains(resp.Header.Get("Vary"), "Accept") {
		t.Fatalf("missing Vary: Accept")
	}
	if !strings.Contains(string(body), "Use the ProtocolSoup Wallet Harness") {
		t.Fatalf("markdown body missing skill title\n%s", body)
	}
}

func TestPrefersMarkdown(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false},
		{"text/markdown", true},
		{"text/markdown, text/html", true},
		{"text/html, text/markdown;q=0.1", false},
		{"text/markdown;q=0, text/html", false},
	}
	for _, tc := range cases {
		if got := prefersMarkdown(tc.accept); got != tc.want {
			t.Fatalf("prefersMarkdown(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}

func getDiscovery(t *testing.T, ts *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/.well-known/agent-skills/not-a-skill/SKILL.md" && resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d body %s", path, resp.StatusCode, body)
	}
	return resp, string(body)
}
