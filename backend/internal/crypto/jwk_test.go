package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestValidateJWKEnforcesRSAParameterStrength(t *testing.T) {
	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	strongJWK := JWKFromRSAPublicKey(&strongKey.PublicKey, "strong")
	if err := ValidateJWK(strongJWK); err != nil {
		t.Fatalf("2048-bit RSA key rejected: %v", err)
	}

	weakModulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	weakModulus.SetBit(weakModulus, 0, 1)
	weakJWK := JWK{
		Kty: "RSA",
		Kid: "weak",
		N:   base64.RawURLEncoding.EncodeToString(weakModulus.Bytes()),
		E:   "AQAB",
	}
	if err := ValidateJWK(weakJWK); err == nil ||
		!strings.Contains(err.Error(), "at least 2048") {
		t.Fatalf("weak RSA error = %v", err)
	}

	evenModulus := strongJWK
	modulusBytes, err := base64.RawURLEncoding.DecodeString(evenModulus.N)
	if err != nil {
		t.Fatal(err)
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	modulus.SetBit(modulus, 0, 0)
	evenModulus.N = base64.RawURLEncoding.EncodeToString(modulus.Bytes())
	if err := ValidateJWK(evenModulus); err == nil || !strings.Contains(err.Error(), "odd") {
		t.Fatalf("even modulus error = %v", err)
	}

	for name, exponent := range map[string][]byte{
		"less_than_three": {1},
		"even":            {4},
		"overflow":        {1, 0, 0, 0, 0, 0, 0, 0, 0},
		"leading_zero":    {0, 3},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := strongJWK
			candidate.E = base64.RawURLEncoding.EncodeToString(exponent)
			if err := ValidateJWK(candidate); err == nil {
				t.Fatal("invalid RSA exponent was accepted")
			}
		})
	}
}

func TestPrivateJWKMembersDetectsEveryPrivateMemberByPresence(t *testing.T) {
	privateMembers := []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
	key := map[string]interface{}{
		"kty": "RSA",
		"n":   "public",
		"e":   "AQAB",
	}
	for _, member := range privateMembers {
		key[member] = nil
	}
	raw, err := json.Marshal(map[string]interface{}{"keys": []interface{}{key}})
	if err != nil {
		t.Fatal(err)
	}
	found, err := PrivateJWKMembers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(found, ",") != "d,dp,dq,k,oth,p,q,qi" {
		t.Fatalf("private members = %#v", found)
	}
}
