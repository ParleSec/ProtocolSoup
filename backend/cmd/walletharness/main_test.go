package main

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestResolveWalletScopeKeyPrecedence(t *testing.T) {
	server := &walletHarnessServer{strictIsolation: true}

	scope, err := server.resolveWalletScopeKey(walletSubmitRequest{
		LookingGlassSessionID: "lg-123",
		RequestID:             "req-ignored",
	})
	if err != nil {
		t.Fatalf("resolveWalletScopeKey with looking glass session: %v", err)
	}
	if scope != "lg:lg-123" {
		t.Fatalf("unexpected scope %q", scope)
	}

	scope, err = server.resolveWalletScopeKey(walletSubmitRequest{
		RequestID: "req-123",
	})
	if err != nil {
		t.Fatalf("resolveWalletScopeKey with request id: %v", err)
	}
	if scope != "req:req-123" {
		t.Fatalf("unexpected scope %q", scope)
	}
}

func TestResolveWalletScopeKeyStrictIsolation(t *testing.T) {
	strictServer := &walletHarnessServer{strictIsolation: true}
	if _, err := strictServer.resolveWalletScopeKey(walletSubmitRequest{}); err == nil {
		t.Fatalf("expected strict isolation to reject empty scope key")
	}

	legacyServer := &walletHarnessServer{strictIsolation: false}
	scope, err := legacyServer.resolveWalletScopeKey(walletSubmitRequest{})
	if err != nil {
		t.Fatalf("expected legacy fallback scope without error, got %v", err)
	}
	if scope != "legacy:shared" {
		t.Fatalf("unexpected legacy scope %q", scope)
	}
}

func TestScopedWalletSubjectUsesScopeFingerprint(t *testing.T) {
	base := "did:example:wallet:alice"
	scopeA := scopedWalletSubject(base, "req:a")
	scopeB := scopedWalletSubject(base, "req:b")
	if scopeA == base || scopeB == base {
		t.Fatalf("scoped subject must not equal base subject")
	}
	if scopeA == scopeB {
		t.Fatalf("scoped subject must differ across scope keys")
	}
}

func TestGetOrCreateWalletIsolatesByScope(t *testing.T) {
	server := &walletHarnessServer{
		strictIsolation:  true,
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	subject := "did:example:wallet:alice"

	walletA1, err := server.getOrCreateWallet("req:a", subject)
	if err != nil {
		t.Fatalf("getOrCreateWallet A1: %v", err)
	}
	walletA2, err := server.getOrCreateWallet("req:a", subject)
	if err != nil {
		t.Fatalf("getOrCreateWallet A2: %v", err)
	}
	if walletA1 != walletA2 {
		t.Fatalf("expected same wallet for same scope and subject")
	}

	walletB, err := server.getOrCreateWallet("req:b", subject)
	if err != nil {
		t.Fatalf("getOrCreateWallet B: %v", err)
	}
	if walletB == walletA1 {
		t.Fatalf("expected different wallet for different scope")
	}
}

func TestGetOrCreateWalletPrunesExpiredEntries(t *testing.T) {
	server := &walletHarnessServer{
		strictIsolation:  true,
		walletSessionTTL: 1 * time.Second,
		wallets:          make(map[string]*walletMaterial),
	}

	wallet, err := server.getOrCreateWallet("req:old", "did:example:wallet:old")
	if err != nil {
		t.Fatalf("getOrCreateWallet old: %v", err)
	}
	wallet.LastAccess = time.Now().UTC().Add(-2 * time.Second)

	if _, err := server.getOrCreateWallet("req:new", "did:example:wallet:new"); err != nil {
		t.Fatalf("getOrCreateWallet new: %v", err)
	}

	server.mu.Lock()
	_, stillExists := server.wallets["req:old|did:example:wallet:old"]
	server.mu.Unlock()
	if stillExists {
		t.Fatalf("expected expired wallet entry to be pruned")
	}
}

func TestParseOpenID4VPURIExtractsRequestURI(t *testing.T) {
	requestURI, requestJWT, err := parseOpenID4VPURI("openid4vp://authorize?request_uri=https%3A%2F%2Fprotocolsoup.com%2Foid4vp%2Frequest%2Fabc123")
	if err != nil {
		t.Fatalf("parseOpenID4VPURI: %v", err)
	}
	if requestJWT != "" {
		t.Fatalf("expected empty request JWT, got %q", requestJWT)
	}
	if requestURI != "https://protocolsoup.com/oid4vp/request/abc123" {
		t.Fatalf("unexpected requestURI %q", requestURI)
	}
}

func TestResolveRequestContextWithOptionsRejectsExternalByDefault(t *testing.T) {
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: "https://protocolsoup.com/oid4vp/response",
		allowExternal:     false,
	}
	requestJWT := buildTestRequestJWT(t, "https://wallet.example.org/oid4vp/response")
	if _, err := server.resolveRequestContextWithOptions("req-123", requestJWT, false); err == nil {
		t.Fatalf("expected external response_uri to be rejected when allowExternal=false")
	}
}

func TestResolveRequestContextWithOptionsAllowsExternalWhenEnabled(t *testing.T) {
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: "https://protocolsoup.com/oid4vp/response",
		allowExternal:     true,
	}
	requestJWT := buildTestRequestJWT(t, "https://wallet.example.org/oid4vp/response")
	context, err := server.resolveRequestContextWithOptions("req-123", requestJWT, true)
	if err != nil {
		t.Fatalf("resolveRequestContextWithOptions external: %v", err)
	}
	if context.Trusted {
		t.Fatalf("expected external context to be untrusted")
	}
	if context.ResponseURI != "https://wallet.example.org/oid4vp/response" {
		t.Fatalf("unexpected response URI %q", context.ResponseURI)
	}
}

func TestWalletCredentialSelectionMismatch(t *testing.T) {
	testCases := []struct {
		name        string
		wallet      *walletMaterial
		configID    string
		format      string
		hasMismatch bool
	}{
		{
			name: "no_selection_constraints",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredential",
				CredentialFormat:          "dc+sd-jwt",
			},
			configID:    "",
			format:      "",
			hasMismatch: false,
		},
		{
			name: "empty_wallet_requires_issue",
			wallet: &walletMaterial{
				CredentialJWT: "",
			},
			configID:    "UniversityDegreeCredential",
			format:      "dc+sd-jwt",
			hasMismatch: true,
		},
		{
			name: "matching_active_selection",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredential",
				CredentialFormat:          "dc+sd-jwt",
			},
			configID:    "UniversityDegreeCredential",
			format:      "dc+sd-jwt",
			hasMismatch: false,
		},
		{
			name: "format_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "ldp_vc",
			},
			configID:    "UniversityDegreeCredentialLDP",
			format:      "dc+sd-jwt",
			hasMismatch: true,
		},
		{
			name: "config_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "ldp_vc",
			},
			configID:    "UniversityDegreeCredential",
			format:      "ldp_vc",
			hasMismatch: true,
		},
		{
			name: "empty_active_format_with_constraints_is_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "",
			},
			configID:    "UniversityDegreeCredentialLDP",
			format:      "ldp_vc",
			hasMismatch: true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			hasMismatch := walletCredentialSelectionMismatch(testCase.wallet, testCase.configID, testCase.format)
			if hasMismatch != testCase.hasMismatch {
				t.Fatalf("walletCredentialSelectionMismatch() = %v, want %v", hasMismatch, testCase.hasMismatch)
			}
		})
	}
}

func buildTestRequestJWT(t *testing.T, responseURI string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti":           "req-123",
		"state":         "state-123",
		"nonce":         "nonce-123",
		"client_id":     "did:example:verifier",
		"response_mode": "direct_post",
		"response_uri":  responseURI,
	})
	token.Header["typ"] = "oauth-authz-req+jwt"
	signed, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request jwt: %v", err)
	}
	return signed
}
