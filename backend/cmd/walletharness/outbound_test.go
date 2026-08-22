package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func lookupPublicUnicastIPs(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{net.IPv4(8, 8, 8, 8)}, nil
}

func TestValidateExternalURLRejectsNonPublicDestinations(t *testing.T) {
	t.Parallel()
	server := &walletHarnessServer{
		allowExternal: true,
		lookupIPs: func(_ context.Context, host string) ([]net.IP, error) {
			switch host {
			case "loopback.example":
				return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
			case "private.example":
				return []net.IP{net.IPv4(10, 0, 0, 8)}, nil
			case "cgnat.example":
				return []net.IP{net.IPv4(100, 64, 0, 1)}, nil
			case "mixed.example":
				return []net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(127, 0, 0, 1)}, nil
			case "mapped.example":
				return []net.IP{net.ParseIP("::ffff:127.0.0.1")}, nil
			case "public.example":
				return []net.IP{net.IPv4(8, 8, 8, 8)}, nil
			default:
				return nil, fmt.Errorf("unexpected host %q", host)
			}
		},
	}

	cases := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "literal loopback", raw: "https://127.0.0.1/request", wantErr: "is not allowed"},
		{name: "literal private", raw: "https://10.0.0.8/request", wantErr: "is not allowed"},
		{name: "link local", raw: "https://169.254.169.254/request", wantErr: "is not allowed"},
		{name: "resolved loopback", raw: "https://loopback.example/request", wantErr: "is not allowed"},
		{name: "resolved private", raw: "https://private.example/request", wantErr: "is not allowed"},
		{name: "resolved shared address space", raw: "https://cgnat.example/request", wantErr: "is not allowed"},
		{name: "mixed public and loopback records", raw: "https://mixed.example/request", wantErr: "is not allowed"},
		{name: "ipv4 mapped loopback", raw: "https://mapped.example/request", wantErr: "is not allowed"},
		{name: "http scheme", raw: "http://public.example/request", wantErr: "scheme"},
		{name: "numeric prefix http", raw: "http://127.example.test/request", wantErr: "scheme"},
		{name: "localhost name", raw: "https://localhost/request", wantErr: "is not allowed"},
		{name: "internal suffix", raw: "https://service.internal/request", wantErr: "is not allowed"},
		{name: "userinfo", raw: "https://user:pass@public.example/request", wantErr: "userinfo"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := server.validateExternalURL(testCase.raw)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("validateExternalURL(%q) = %v, want substring %q", testCase.raw, err, testCase.wantErr)
			}
		})
	}

	got, err := server.validateExternalURL("https://public.example/oid4vp/request")
	if err != nil {
		t.Fatalf("public https destination rejected: %v", err)
	}
	if got != "https://public.example/oid4vp/request" {
		t.Fatalf("normalized URL = %q", got)
	}
}

func TestValidateExternalURLAllowsTrustedLoopback(t *testing.T) {
	t.Parallel()
	server := &walletHarnessServer{
		targetHost:    "127.0.0.1:8080",
		issuerBaseURL: "http://127.0.0.1:8080",
		allowExternal: false,
	}
	got, err := server.validateExternalURL("http://127.0.0.1:8080/oid4vp/request")
	if err != nil {
		t.Fatalf("trusted loopback rejected: %v", err)
	}
	if got != "http://127.0.0.1:8080/oid4vp/request" {
		t.Fatalf("normalized URL = %q", got)
	}
}

func TestFetchRequestObjectOmitsUpstreamBodyFromError(t *testing.T) {
	t.Parallel()
	const marker = "internal-only-body-must-not-leak"
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, marker, http.StatusForbidden)
	}))
	t.Cleanup(requestServer.Close)
	host, _ := url.Parse(requestServer.URL)
	server := &walletHarnessServer{httpClient: requestServer.Client(), targetHost: host.Host}
	_, _, err := server.fetchRequestObject(context.Background(), requestServer.URL, "get")
	if err == nil {
		t.Fatal("expected non-2xx request_uri to fail")
	}
	if !strings.Contains(err.Error(), "returned 403") {
		t.Fatalf("error = %v, want status 403", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("upstream body leaked in error: %v", err)
	}
}

func TestFetchRequestObjectRejectsRedirectToBlockedAddress(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	parsed, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatalf("parse redirector URL: %v", err)
	}

	var dialed []string
	server := &walletHarnessServer{
		allowExternal: true,
		targetHost:    parsed.Host,
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	server.httpClient = server.newOutboundHTTPClient(5 * time.Second)

	_, _, err = server.fetchRequestObject(context.Background(), redirector.URL, "get")
	if err == nil {
		t.Fatal("expected blocked redirect to be rejected")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %v, want destination rejection", err)
	}
	for _, address := range dialed {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			continue
		}
		if host == "169.254.169.254" {
			t.Fatalf("dialed blocked redirect target %q", address)
		}
	}
}

func TestSecureDialContextRefusesBlockedResolvedAddress(t *testing.T) {
	var dialed []string
	server := &walletHarnessServer{
		allowExternal: true,
		lookupIPs: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return nil, fmt.Errorf("dial should not run")
		},
	}
	_, err := server.secureDialContext(context.Background(), "tcp", net.JoinHostPort("verifier.example", "443"))
	if err == nil {
		t.Fatal("expected blocked resolved address to be refused")
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed %v", dialed)
	}
}

func TestAPIResolveRejectsAdvisorySSRFCases(t *testing.T) {
	const marker = "internal-only-body-must-not-leak"
	var internalHits int
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHits++
		http.Error(w, marker, http.StatusForbidden)
	}))
	t.Cleanup(internal.Close)
	internalURL, err := url.Parse(internal.URL)
	if err != nil {
		t.Fatalf("parse internal URL: %v", err)
	}

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/internal-secret", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	redirectorURL, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatalf("parse redirector URL: %v", err)
	}

	postResolve := func(t *testing.T, server *walletHarnessServer, requestURI string) (int, string) {
		t.Helper()
		mux := http.NewServeMux()
		server.registerRoutes(mux)
		wallet := httptest.NewServer(mux)
		t.Cleanup(wallet.Close)

		payload, err := json.Marshal(map[string]string{
			"request_uri":        requestURI,
			"request_uri_method": "get",
		})
		if err != nil {
			t.Fatalf("marshal resolve body: %v", err)
		}
		resp, err := http.Post(wallet.URL+"/api/resolve", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /api/resolve: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	t.Run("literal loopback is rejected", func(t *testing.T) {
		internalHits = 0
		server := &walletHarnessServer{allowExternal: true, targetHost: "protocolsoup.com"}
		server.httpClient = server.newOutboundHTTPClient(5 * time.Second)
		status, body := postResolve(t, server, internal.URL+"/internal-secret")
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d body = %s, want 400", status, body)
		}
		if !strings.Contains(body, "not allowed") {
			t.Fatalf("body = %s, want destination rejection", body)
		}
		if strings.Contains(body, marker) {
			t.Fatalf("internal body leaked: %s", body)
		}
		if internalHits != 0 {
			t.Fatalf("internal hits = %d, want 0", internalHits)
		}
	})

	t.Run("dns name resolving to loopback is rejected", func(t *testing.T) {
		internalHits = 0
		server := &walletHarnessServer{
			allowExternal: true,
			targetHost:    "protocolsoup.com",
			lookupIPs: func(_ context.Context, host string) ([]net.IP, error) {
				if host != "resolver-loopback.test" {
					t.Fatalf("unexpected lookup host %q", host)
				}
				return []net.IP{net.ParseIP(internalURL.Hostname())}, nil
			},
		}
		server.httpClient = server.newOutboundHTTPClient(5 * time.Second)
		status, body := postResolve(t, server, "https://resolver-loopback.test:"+internalURL.Port()+"/internal-secret")
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d body = %s, want 400", status, body)
		}
		if !strings.Contains(body, "not allowed") {
			t.Fatalf("body = %s, want destination rejection", body)
		}
		if strings.Contains(body, marker) {
			t.Fatalf("internal body leaked: %s", body)
		}
		if internalHits != 0 {
			t.Fatalf("internal hits = %d, want 0", internalHits)
		}
	})

	t.Run("redirect to loopback is rejected", func(t *testing.T) {
		internalHits = 0
		server := &walletHarnessServer{
			allowExternal: true,
			targetHost:    redirectorURL.Host,
		}
		server.httpClient = server.newOutboundHTTPClient(5 * time.Second)
		status, body := postResolve(t, server, redirector.URL+"/redirect")
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d body = %s, want 400", status, body)
		}
		if !strings.Contains(body, "not allowed") {
			t.Fatalf("body = %s, want destination rejection", body)
		}
		if strings.Contains(body, marker) {
			t.Fatalf("internal body leaked: %s", body)
		}
		if internalHits != 0 {
			t.Fatalf("internal hits = %d, want 0", internalHits)
		}
	})
}

func TestFetchRequestObjectLimitsResponseSize(t *testing.T) {
	t.Parallel()
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("a", maxRequestObjectBytes+8)))
	}))
	t.Cleanup(requestServer.Close)
	host, _ := url.Parse(requestServer.URL)
	server := &walletHarnessServer{httpClient: requestServer.Client(), targetHost: host.Host}
	_, _, err := server.fetchRequestObject(context.Background(), requestServer.URL, "get")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v, want body too large", err)
	}
}
