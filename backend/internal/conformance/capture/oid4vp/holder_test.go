package oid4vp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// The VP-006 passing scenario relies on the verifier selecting the request by
// the kid in the JWE protected header, so encryptResponse must put it there.
func TestEncryptResponseCopiesKidIntoProtectedHeader(t *testing.T) {
	key, err := capture.NewHolderKey()
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := key.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	jwk["kid"] = "verifier-ephemeral"
	object := &requestObject{claims: map[string]any{
		"client_metadata": map[string]any{
			"jwks": map[string]any{"keys": []any{jwk}},
			"encrypted_response_enc_values_supported": []any{"A256GCM"},
		},
	}}
	compact, err := encryptResponse(object, map[string]any{"state": "s"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("not a compact JWE: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "verifier-ephemeral" || header["alg"] != "ECDH-ES" || header["enc"] != "A256GCM" {
		t.Fatalf("protected header = %v", header)
	}
}
