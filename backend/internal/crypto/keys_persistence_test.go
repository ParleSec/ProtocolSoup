package crypto

import (
	"path/filepath"
	"testing"
	"time"
)

// TestLoadOrCreateKeySetIsStableAcrossReload encodes the normative requirement
// that a certified OP keeps stable signing keys across restarts (OpenID Connect
// Core 1.0 Section 10.1.1). LoadOrCreateKeySet against the same directory must
// return identical key IDs and key material on the second call.
func TestLoadOrCreateKeySetIsStableAcrossReload(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateKeySet: %v", err)
	}
	second, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateKeySet: %v", err)
	}

	if first.RSAKeyID() != second.RSAKeyID() {
		t.Fatalf("RSA kid changed across reload: %s vs %s", first.RSAKeyID(), second.RSAKeyID())
	}
	if first.ECKeyID() != second.ECKeyID() {
		t.Fatalf("EC kid changed across reload: %s vs %s", first.ECKeyID(), second.ECKeyID())
	}
	if first.Ed25519KeyID() != second.Ed25519KeyID() {
		t.Fatalf("Ed25519 kid changed across reload")
	}
	if first.RSAPublicKey().N.Cmp(second.RSAPublicKey().N) != 0 {
		t.Fatalf("RSA modulus changed across reload")
	}
}

// TestEphemeralKeySetWhenNoPath confirms an empty path yields an in-memory key
// set (development behaviour) with exactly the three active keys.
func TestEphemeralKeySetWhenNoPath(t *testing.T) {
	ks, err := LoadOrCreateKeySet("")
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet(\"\"): %v", err)
	}
	if got := len(ks.PublicJWKS().Keys); got != 3 {
		t.Fatalf("ephemeral PublicJWKS returned %d keys, want 3", got)
	}
	if ks.storePath != "" {
		t.Fatalf("ephemeral key set should have no store path")
	}
}

// TestRotateRetainsRetiredKeysAndPersists encodes the historical-JWKS retention
// requirement: after a rotation the previous public keys remain published and
// resolvable by kid, and the retained set survives a reload from disk.
func TestRotateRetainsRetiredKeysAndPersists(t *testing.T) {
	dir := t.TempDir()

	ks, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet: %v", err)
	}

	oldRSAKid := ks.RSAKeyID()
	oldECKid := ks.ECKeyID()
	oldEdKid := ks.Ed25519KeyID()

	if err := ks.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if ks.RSAKeyID() == oldRSAKid {
		t.Fatalf("RSA kid did not change after rotation")
	}

	// Old public keys must still be resolvable for historical token validation.
	for _, kid := range []string{oldRSAKid, oldECKid, oldEdKid} {
		if _, ok := ks.GetJWKByID(kid); !ok {
			t.Fatalf("retired kid %s no longer resolvable after rotation", kid)
		}
	}

	// JWKS now contains the three active keys plus the three retired ones.
	if got := len(ks.PublicJWKS().Keys); got != 6 {
		t.Fatalf("post-rotation PublicJWKS returned %d keys, want 6", got)
	}

	// Retention must survive a reload from disk.
	reloaded, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	if got := len(reloaded.PublicJWKS().Keys); got != 6 {
		t.Fatalf("reloaded PublicJWKS returned %d keys, want 6", got)
	}
	if _, ok := reloaded.GetJWKByID(oldRSAKid); !ok {
		t.Fatalf("retired RSA kid %s not retained across reload", oldRSAKid)
	}
}

// TestPersistedKeySetSignsVerifiably ensures a reloaded key set still produces
// tokens that validate, proving the private material round-trips correctly.
func TestPersistedKeySetSignsVerifiably(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet: %v", err)
	}
	svc := NewJWTService(first, "https://op.example.com")
	token, err := svc.CreateAccessToken("alice", "demo-app", "openid", time.Hour, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	reloaded, err := LoadOrCreateKeySet(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	reloadedSvc := NewJWTService(reloaded, "https://op.example.com")
	if _, err := reloadedSvc.ValidateToken(token); err != nil {
		t.Fatalf("token signed by first key set failed to validate against reloaded key set: %v", err)
	}

	_ = filepath.Join(dir, keyStoreFile)
}
