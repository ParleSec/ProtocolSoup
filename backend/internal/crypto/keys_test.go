package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestKeySetExposesEd25519JWK(t *testing.T) {
	keySet, err := NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	jwks := keySet.PublicJWKS()
	if len(jwks.Keys) != 3 {
		t.Fatalf("PublicJWKS() returned %d keys, want 3", len(jwks.Keys))
	}

	jwk, found := keySet.GetJWKByID(keySet.Ed25519KeyID())
	if !found {
		t.Fatalf("Ed25519 JWK not found")
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" {
		t.Fatalf("unexpected Ed25519 JWK %+v", jwk)
	}
	if err := ValidateJWK(jwk); err != nil {
		t.Fatalf("ValidateJWK(OKP): %v", err)
	}
	if jwk.Thumbprint() == "" {
		t.Fatalf("expected OKP thumbprint")
	}
}

func TestEd25519JWKRoundTripAndVerifySignature(t *testing.T) {
	keySet, err := NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	jwk, found := keySet.GetJWKByID(keySet.Ed25519KeyID())
	if !found {
		t.Fatalf("Ed25519 JWK not found")
	}

	publicKeyAny, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey(): %v", err)
	}
	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("ToPublicKey() returned %T, want ed25519.PublicKey", publicKeyAny)
	}
	if !bytes.Equal(publicKey, keySet.Ed25519PublicKey()) {
		t.Fatalf("round-tripped Ed25519 public key mismatch")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub": "did:key:test",
		"iat": float64(1),
	})
	token.Header["kid"] = keySet.Ed25519KeyID()
	signed, err := token.SignedString(keySet.Ed25519PrivateKey())
	if err != nil {
		t.Fatalf("SignedString(EdDSA): %v", err)
	}

	valid, err := VerifySignatureWithKey(signed, publicKey)
	if err != nil {
		t.Fatalf("VerifySignatureWithKey(EdDSA): %v", err)
	}
	if !valid {
		t.Fatalf("expected EdDSA signature to verify")
	}
}
