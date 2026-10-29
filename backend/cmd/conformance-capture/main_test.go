package main

import "testing"

func TestParseOriginAcceptsOnlyBareOrigins(t *testing.T) {
	for raw, want := range map[string]string{
		"https://protocolsoup.com":  "https://protocolsoup.com",
		"https://protocolsoup.com/": "https://protocolsoup.com",
		" http://localhost:8181 ":   "http://localhost:8181",
	} {
		got, err := parseOrigin("-base", raw, true)
		if err != nil || got != want {
			t.Fatalf("parseOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"protocolsoup.com",
		"ftp://protocolsoup.com",
		"https://protocolsoup.com/api",
		"https://protocolsoup.com?x=1",
		"https://protocolsoup.com#health",
		"https://user@protocolsoup.com",
		"file:///etc/passwd",
	} {
		if got, err := parseOrigin("-base", raw, true); err == nil {
			t.Fatalf("parseOrigin(%q) = %q; want an error", raw, got)
		}
	}
	if _, err := parseOrigin("-base", "", true); err == nil {
		t.Fatal("an empty required origin must be refused")
	}
	if got, err := parseOrigin("-wallet", "", false); err != nil || got != "" {
		t.Fatalf("an empty optional origin = %q, %v; want empty", got, err)
	}
}
