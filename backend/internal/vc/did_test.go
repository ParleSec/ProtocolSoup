package vc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDIDKeyFromEd25519PublicKeyRoundTrip(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	did, err := DIDKeyFromEd25519PublicKey(publicKey)
	if err != nil {
		t.Fatalf("DIDKeyFromEd25519PublicKey: %v", err)
	}
	if !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("unexpected did:key value %q", did)
	}

	decodedKey, keyType, err := DecodeMultibaseMulticodecKey(strings.TrimPrefix(did, "did:key:"))
	if err != nil {
		t.Fatalf("DecodeMultibaseMulticodecKey: %v", err)
	}
	if keyType != "OKP" {
		t.Fatalf("unexpected key type %q", keyType)
	}

	decodedPublicKey, ok := decodedKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("decoded key has type %T, want ed25519.PublicKey", decodedKey)
	}
	if !bytes.Equal(decodedPublicKey, publicKey) {
		t.Fatalf("decoded Ed25519 public key mismatch")
	}
}
