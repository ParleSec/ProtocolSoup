package vc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

func TestWalletCredentialStoreEncryptedPersistenceRoundTrip(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	snapshotPath := filepath.Join(tempDir, "wallet.json")

	store := NewWalletCredentialStore()
	store.SetEncryptionKey("test-wallet-secret")
	if err := store.EnablePersistence(snapshotPath); err != nil {
		t.Fatalf("EnablePersistence(write): %v", err)
	}

	record := WalletCredentialRecord{
		Subject:       "did:key:test",
		Format:        "jwt_vc_json",
		VCT:           "UniversityDegreeCredential",
		CredentialJWT: "eyJhbGciOiJSUzI1NiJ9.payload.signature",
		Issuer:        "https://issuer.example",
		IssuerJWK:     crypto.JWK{Kty: "RSA", N: "AQAB", E: "AQAB"},
	}
	if ok := store.Put(record); !ok {
		t.Fatalf("Put: expected success")
	}

	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, record.CredentialJWT) || strings.Contains(content, record.Subject) {
		t.Fatalf("expected encrypted snapshot, got plaintext content: %s", content)
	}

	restored := NewWalletCredentialStore()
	restored.SetEncryptionKey("test-wallet-secret")
	if err := restored.EnablePersistence(snapshotPath); err != nil {
		t.Fatalf("EnablePersistence(read): %v", err)
	}

	got, ok := restored.Get(record.Subject, record.VCT)
	if !ok {
		t.Fatalf("expected restored credential record")
	}
	if got.CredentialJWT != record.CredentialJWT {
		t.Fatalf("restored credential mismatch: got %q want %q", got.CredentialJWT, record.CredentialJWT)
	}
}

func TestWalletCredentialStoreEncryptedSnapshotRequiresKey(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	snapshotPath := filepath.Join(tempDir, "wallet.json")

	store := NewWalletCredentialStore()
	store.SetEncryptionKey("test-wallet-secret")
	if err := store.EnablePersistence(snapshotPath); err != nil {
		t.Fatalf("EnablePersistence(write): %v", err)
	}
	if ok := store.Put(WalletCredentialRecord{
		Subject:       "did:key:test",
		Format:        "jwt_vc_json",
		VCT:           "UniversityDegreeCredential",
		CredentialJWT: "encrypted",
	}); !ok {
		t.Fatalf("Put: expected success")
	}

	restored := NewWalletCredentialStore()
	if err := restored.EnablePersistence(snapshotPath); err == nil {
		t.Fatalf("expected encrypted snapshot to require a key")
	}
}

func TestWalletCredentialStorePlaintextSnapshotStillLoads(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	snapshotPath := filepath.Join(tempDir, "wallet.json")

	store := NewWalletCredentialStore()
	if err := store.EnablePersistence(snapshotPath); err != nil {
		t.Fatalf("EnablePersistence(write): %v", err)
	}
	if ok := store.Put(WalletCredentialRecord{
		Subject:       "did:key:test",
		Format:        "jwt_vc_json",
		VCT:           "UniversityDegreeCredential",
		CredentialJWT: "plaintext",
	}); !ok {
		t.Fatalf("Put: expected success")
	}

	restored := NewWalletCredentialStore()
	restored.SetEncryptionKey("test-wallet-secret")
	if err := restored.EnablePersistence(snapshotPath); err != nil {
		t.Fatalf("EnablePersistence(read): %v", err)
	}

	got, ok := restored.Get("did:key:test", "UniversityDegreeCredential")
	if !ok || got.CredentialJWT != "plaintext" {
		t.Fatalf("unexpected restored plaintext snapshot: %+v ok=%v", got, ok)
	}
}
