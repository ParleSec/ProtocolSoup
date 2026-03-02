package main

import (
	"testing"
	"time"
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
