package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestStartProtectedResourceAuthorizationBuildsPARAuthorizeURL(t *testing.T) {
	t.Parallel()
	const (
		clientID = "protocolsoup-wallet"
		scope    = "accounts"
	)
	var sawPAR bool
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		if strings.Contains(r.URL.Path, "oauth-authorization-server") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                base + "/test",
				"authorization_endpoint":                base + "/authorize",
				"token_endpoint":                        base + "/token",
				"pushed_authorization_request_endpoint": base + "/par",
				"code_challenge_methods_supported":      []string{"S256"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
				"token_endpoint_auth_methods_supported": []string{"attest_jwt_client_auth"},
				"require_pushed_authorization_requests": true,
				"authorization_response_iss_parameter_supported": true,
			})
			return
		}
		if r.URL.Path == "/par" {
			sawPAR = true
			if r.Header.Get(headerOAuthClientAttestation) == "" || r.Header.Get(headerOAuthClientAttestationPoP) == "" {
				http.Error(w, "missing attestation", http.StatusUnauthorized)
				return
			}
			_ = r.ParseForm()
			if got := r.Form.Get("scope"); got != scope {
				http.Error(w, "bad scope "+got, http.StatusBadRequest)
				return
			}
			if r.Form.Get("authorization_details") != "" {
				http.Error(w, "unexpected authorization_details", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:resource","expires_in":60}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer as.Close()
	discoveryURL := as.URL + "/.well-known/oauth-authorization-server/test"
	resourceURL := as.URL + "/open-banking/v1.1/accounts"

	asURL, _ := url.Parse(as.URL)
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	server := &walletHarnessServer{
		httpClient:           as.Client(),
		targetHost:           asURL.Host,
		allowExternal:        true,
		haipAttestedClientID: clientID,
		haipClientAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused"},
		},
		haipKeyAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused"},
		},
		walletSessionTTL:  10 * time.Minute,
		wallets:           make(map[string]*walletMaterial),
		oid4vciAuthStates: make(map[string]*pendingOID4VCIAuthState),
	}
	wallet, err := server.getOrCreateWallet("req:resource", "did:example:wallet:resource", "https://wallet.example")
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}
	result, err := server.startProtectedResourceAuthorization(
		context.Background(),
		wallet,
		discoveryURL,
		resourceURL,
		scope,
		"https://wallet.example",
		"",
	)
	if err != nil {
		t.Fatalf("startProtectedResourceAuthorization: %v", err)
	}
	if !sawPAR {
		t.Fatal("expected PAR request")
	}
	if result == nil || !result.AuthorizationRequired {
		t.Fatal("expected authorization_required result")
	}
	parsed, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization_url: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != clientID {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("request_uri") != "urn:ietf:params:oauth:request_uri:resource" {
		t.Fatalf("request_uri = %q", query.Get("request_uri"))
	}
	if len(query) != 2 {
		t.Fatalf("authorize query = %#v, want only client_id and request_uri", query)
	}
	if len(server.oid4vciAuthStates) != 1 {
		t.Fatalf("pending states = %d", len(server.oid4vciAuthStates))
	}
	for _, pending := range server.oid4vciAuthStates {
		if pending.ResourceEndpoint != resourceURL {
			t.Fatalf("ResourceEndpoint = %q, want %q", pending.ResourceEndpoint, resourceURL)
		}
		if !pending.UseHAIP {
			t.Fatal("expected UseHAIP")
		}
	}
}

func TestOID4VCICallbackFetchesProtectedResourceEndpoint(t *testing.T) {
	t.Parallel()
	const (
		walletBaseURL    = "https://wallet.example"
		attestedClientID = "protocolsoup-wallet"
	)
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	haipSession, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}

	var (
		resourceHits     int
		credentialHits   int
		sawInteractionID bool
		sawDPoP          bool
	)
	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()
	issuer := testServer.URL + "/as"

	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "resource-access-token",
			"token_type":   "DPoP",
		})
	})
	mux.HandleFunc("/as/credential", func(w http.ResponseWriter, r *http.Request) {
		credentialHits++
		http.Error(w, "credential endpoint must not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		resourceHits++
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "DPoP ") {
			http.Error(w, "missing dpop authz", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") == "" {
			http.Error(w, "missing dpop", http.StatusUnauthorized)
			return
		}
		sawDPoP = true
		if id := strings.TrimSpace(r.Header.Get("x-fapi-interaction-id")); id != "" {
			sawInteractionID = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accounts":[]}`))
	})

	serverURL, _ := url.Parse(testServer.URL)
	server := &walletHarnessServer{
		httpClient:           testServer.Client(),
		targetHost:           serverURL.Host,
		allowExternal:        true,
		haipAttestedClientID: attestedClientID,
		haipClientAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused"},
		},
		haipKeyAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused"},
		},
		walletSessionTTL:  10 * time.Minute,
		wallets:           make(map[string]*walletMaterial),
		oid4vciAuthStates: make(map[string]*pendingOID4VCIAuthState),
	}
	wallet, err := server.getOrCreateWallet("req:resource-cb", "did:example:wallet:resource", walletBaseURL)
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}
	state := "resource-state-1"
	server.oid4vciAuthStates[state] = &pendingOID4VCIAuthState{
		State:         state,
		ScopeKey:      wallet.ScopeKey,
		WalletSubject: wallet.Subject,
		WalletBaseURL: walletBaseURL,
		ClientID:      attestedClientID,
		RedirectURI:   walletBaseURL + "/api/oid4vci/callback",
		CodeVerifier:  "verifier",
		AuthorizationServerMetadata: &resolvedAuthorizationServerMetadata{
			Issuer:        issuer,
			TokenEndpoint: issuer + "/token",
		},
		HAIPSession:      haipSession,
		ExpectedIss:      issuer,
		PopAudience:      issuer,
		UseHAIP:          true,
		ResourceEndpoint: testServer.URL + "/accounts",
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(5 * time.Minute),
	}

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		walletBaseURL+"/api/oid4vci/callback?code=auth-code&state="+url.QueryEscape(state)+"&iss="+url.QueryEscape(issuer),
		nil,
	)
	callbackRequest.Host = "wallet.example"
	callbackRecorder := httptest.NewRecorder()
	server.handleAPIOID4VCICallback(callbackRecorder, callbackRequest)
	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("unexpected callback status %d: %s", callbackRecorder.Code, callbackRecorder.Body.String())
	}
	location, err := url.Parse(callbackRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := location.Query().Get("oid4vci_status"); got != "success" {
		t.Fatalf("callback status = %q message = %q", got, location.Query().Get("oid4vci_message"))
	}
	if resourceHits != 1 {
		t.Fatalf("resourceHits = %d, want 1", resourceHits)
	}
	if credentialHits != 0 {
		t.Fatalf("credentialHits = %d, want 0", credentialHits)
	}
	if !sawDPoP || !sawInteractionID {
		t.Fatalf("sawDPoP=%v sawInteractionID=%v", sawDPoP, sawInteractionID)
	}
	if strings.TrimSpace(wallet.CredentialJWT) != "" {
		t.Fatal("protected resource authorization must not bind a credential")
	}
}

func TestIssuerIdentifierFromWellKnownDiscoveryURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{
			in:   "https://issuer.example/.well-known/openid-configuration/test/a/alias/",
			want: "https://issuer.example/test/a/alias",
			ok:   true,
		},
		{
			in:   "https://issuer.example/.well-known/oauth-authorization-server/test/a/alias",
			want: "https://issuer.example/test/a/alias",
			ok:   true,
		},
		{
			in:   "https://as.example/test/a/alias/.well-known/openid-configuration",
			want: "https://as.example/test/a/alias",
			ok:   true,
		},
		{
			in: "https://as.example/par",
			ok: false,
		},
	}
	for _, tc := range cases {
		got, ok := issuerIdentifierFromWellKnownDiscoveryURL(tc.in)
		if ok != tc.ok {
			t.Fatalf("%s: ok=%v want %v", tc.in, ok, tc.ok)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestPreferOIDCDiscoveryURLRewritesAppendOAuthAS(t *testing.T) {
	t.Parallel()
	got := preferOIDCDiscoveryURL("https://issuer.example/test/a/alias/.well-known/oauth-authorization-server")
	want := "https://issuer.example/test/a/alias/.well-known/openid-configuration"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	insertion := "https://issuer.example/.well-known/oauth-authorization-server/test/a/alias"
	if preferOIDCDiscoveryURL(insertion) != insertion {
		t.Fatalf("RFC 8414 insertion URL must be unchanged")
	}
	oidc := "https://issuer.example/test/a/alias/.well-known/openid-configuration"
	if preferOIDCDiscoveryURL(oidc) != oidc {
		t.Fatalf("openid-configuration URL must be unchanged")
	}
}

func TestResolveDiscoveryURLFetchesOpenIDConfigurationNotAppendOAuthAS(t *testing.T) {
	t.Parallel()
	var openidHits, oauthAppendHits int
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			openidHits++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         base + "/testINVALID",
				"token_endpoint": base + "/token",
			})
		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			oauthAppendHits++
			http.Error(w, "unexpected oauth-authorization-server append", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer as.Close()
	asURL, _ := url.Parse(as.URL)
	server := &walletHarnessServer{
		httpClient:    as.Client(),
		targetHost:    asURL.Host,
		allowExternal: true,
	}
	_, err := server.resolveAuthorizationServerMetadataFromDiscoveryURL(
		context.Background(),
		as.URL+"/test/.well-known/oauth-authorization-server",
		"",
	)
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	var apiErr *walletAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != "discovery_issuer_mismatch" {
		t.Fatalf("error = %v", err)
	}
	if openidHits != 1 {
		t.Fatalf("openidHits = %d, want 1", openidHits)
	}
	if oauthAppendHits != 0 {
		t.Fatalf("oauthAppendHits = %d, want 0", oauthAppendHits)
	}
}

func TestResolveDiscoveryURLStopsOnIssuerMismatch(t *testing.T) {
	t.Parallel()
	var parHits int
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		if strings.Contains(r.URL.Path, "openid-configuration") || strings.Contains(r.URL.Path, "oauth-authorization-server") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                base + "/testINVALID",
				"authorization_endpoint":                base + "/authorize",
				"token_endpoint":                        base + "/token",
				"pushed_authorization_request_endpoint": base + "/par",
			})
			return
		}
		if r.URL.Path == "/par" {
			parHits++
			http.Error(w, "should not call par", http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer as.Close()
	asURL, _ := url.Parse(as.URL)
	server := &walletHarnessServer{
		httpClient:    as.Client(),
		targetHost:    asURL.Host,
		allowExternal: true,
	}
	_, err := server.resolveAuthorizationServerMetadataFromDiscoveryURL(
		context.Background(),
		as.URL+"/.well-known/openid-configuration/test",
		"",
	)
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	var apiErr *walletAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != "discovery_issuer_mismatch" {
		t.Fatalf("error = %v", err)
	}
	if parHits != 0 {
		t.Fatalf("parHits = %d, want 0", parHits)
	}
}

func TestFetchProtectedResourceRetriesDPoPNonce(t *testing.T) {
	t.Parallel()
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	var attempt int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("DPoP-Nonce", "resource-nonce-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") == "" {
			http.Error(w, "missing dpop", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	host, _ := url.Parse(upstream.URL)
	server := &walletHarnessServer{
		httpClient:    upstream.Client(),
		targetHost:    host.Host,
		allowExternal: true,
	}
	if err := server.fetchProtectedResource(context.Background(), upstream.URL+"/accounts", "token", "DPoP", session, ""); err != nil {
		t.Fatalf("fetchProtectedResource: %v", err)
	}
	if attempt != 2 {
		t.Fatalf("attempt = %d, want 2", attempt)
	}
}
