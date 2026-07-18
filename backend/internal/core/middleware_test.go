package core

import (
	"net/http/httptest"
	"testing"
)

func TestResolveClientIPRejectsHeadersFromPublicPeer(t *testing.T) {
	request := httptest.NewRequest("GET", "https://example.test/api", nil)
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set("Fly-Client-IP", "198.51.100.20")
	request.Header.Set("X-Forwarded-For", "198.51.100.21")

	if got := resolveClientIP(request); got != "203.0.113.10" {
		t.Fatalf("resolveClientIP() = %q, want direct public peer", got)
	}
}

func TestResolveClientIPTrustsHeadersFromPrivateProxy(t *testing.T) {
	request := httptest.NewRequest("GET", "https://example.test/api", nil)
	request.RemoteAddr = "172.16.0.4:8080"
	request.Header.Set("Fly-Client-IP", "198.51.100.20")

	if got := resolveClientIP(request); got != "198.51.100.20" {
		t.Fatalf("resolveClientIP() = %q, want Fly client address", got)
	}
}

func TestResolveClientIPUsesFirstForwardedAddress(t *testing.T) {
	request := httptest.NewRequest("GET", "https://example.test/api", nil)
	request.RemoteAddr = "127.0.0.1:8080"
	request.Header.Set("X-Forwarded-For", "198.51.100.21, 172.16.0.4")

	if got := resolveClientIP(request); got != "198.51.100.21" {
		t.Fatalf("resolveClientIP() = %q, want first forwarded address", got)
	}
}

func TestResolveClientIPFallsBackFromMalformedProxyHeader(t *testing.T) {
	request := httptest.NewRequest("GET", "https://example.test/api", nil)
	request.RemoteAddr = "10.0.0.4:8080"
	request.Header.Set("Fly-Client-IP", "not-an-ip")

	if got := resolveClientIP(request); got != "10.0.0.4" {
		t.Fatalf("resolveClientIP() = %q, want direct proxy address", got)
	}
}
