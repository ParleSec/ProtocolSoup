package dpop

import "testing"

func TestWithCnfJKTAddsCnfWithoutMutatingOriginal(t *testing.T) {
	original := map[string]interface{}{"sub": "alice"}
	merged := WithCnfJKT(original, "thumbprint-value")

	if _, exists := original["cnf"]; exists {
		t.Fatal("WithCnfJKT must not mutate the original map")
	}
	cnf, ok := merged["cnf"].(map[string]interface{})
	if !ok {
		t.Fatalf("merged[cnf] type = %T", merged["cnf"])
	}
	if cnf["jkt"] != "thumbprint-value" {
		t.Fatalf("cnf.jkt = %v", cnf["jkt"])
	}
	if merged["sub"] != "alice" {
		t.Fatalf("merged is missing pre-existing claims: %#v", merged)
	}
}

func TestWithCnfJKTHandlesNilClaims(t *testing.T) {
	merged := WithCnfJKT(nil, "thumbprint-value")
	cnf, ok := merged["cnf"].(map[string]interface{})
	if !ok || cnf["jkt"] != "thumbprint-value" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestTokenType(t *testing.T) {
	if TokenType("") != "Bearer" {
		t.Fatalf("TokenType(empty) = %q, want Bearer", TokenType(""))
	}
	if TokenType("some-thumbprint") != "DPoP" {
		t.Fatalf("TokenType(non-empty) = %q, want DPoP", TokenType("some-thumbprint"))
	}
}
