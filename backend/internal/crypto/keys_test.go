package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestThumbprintBytesSpecVector pins ThumbprintBytes to the OID4VP 1.0 Appendix
// B.2.6.1 example: the RFC 7638 SHA-256 thumbprint (raw bytes) of the example
// verifier encryption JWK must equal the spec's published value. This is the
// authoritative pin for the jwkThumbprint embedded in the mdoc handover.
func TestThumbprintBytesSpecVector(t *testing.T) {
	jwk := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
		Y:   "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
		Use: "enc",
		Alg: "ECDH-ES",
		Kid: "1",
	}
	const want = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"

	got, err := jwk.ThumbprintBytes()
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("thumbprint mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("RFC 7638 SHA-256 thumbprint must be 32 bytes, got %d", len(got))
	}
}

// TestThumbprintSpecVectors pins Thumbprint() (the base64url string form,
// distinct from ThumbprintBytes above) against RFC 7638/7515/8037 known-
// answer vectors for all three key types this codebase mints: RSA, EC, and
// OKP. frontend/scripts/verify-jwk-thumbprint.mjs pins its jwkThumbprint()
// TypeScript port against the identical three vectors and identical
// expected constants, so this test and that script keep the Go and
// TypeScript implementations pinned to the same answers rather than each
// silently drifting to a self-consistent-but-wrong value. If either
// implementation's canonicalization or encoding regresses, only the vector
// for the affected key type fails -- not the other two -- pointing
// directly at which kty branch broke.
func TestThumbprintSpecVectors(t *testing.T) {
	tests := []struct {
		name string
		jwk  JWK
		want string
	}{
		{
			// RFC 7638 Section 3.1's own worked example; want is the value
			// the RFC itself publishes for this exact key.
			name: "RSA (RFC 7638 §3.1)",
			jwk: JWK{
				Kty: "RSA",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "AQAB",
			},
			want: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		},
		{
			name: "EC P-256 (RFC 7515 Appendix A.3 public key)",
			jwk: JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
			want: "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
		},
		{
			name: "OKP Ed25519 (RFC 8037 Appendix A.1 public key)",
			jwk: JWK{
				Kty: "OKP",
				Crv: "Ed25519",
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			want: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.jwk.Thumbprint(); got != tt.want {
				t.Fatalf("Thumbprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestThumbprintUnsupportedKtyReturnsEmptyString pins the "cannot compute"
// contract jwkThumbprint in crypto.ts is documented to mirror: an
// unsupported kty must return "" rather than guess or panic, so a caller
// can render "cannot compute for this key type" as its own state distinct
// from mismatch.
func TestThumbprintUnsupportedKtyReturnsEmptyString(t *testing.T) {
	jwk := JWK{Kty: "oct", K: "GawgguFyGrWKav7AX4VKUg"}
	if got := jwk.Thumbprint(); got != "" {
		t.Fatalf("Thumbprint() for unsupported kty %q = %q, want empty string", jwk.Kty, got)
	}
}

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
