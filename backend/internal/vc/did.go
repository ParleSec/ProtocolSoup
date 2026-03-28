package vc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// DIDKeyFromECPublicKey derives a did:key identifier from a P-256 ECDSA public key.
// Uses multicodec 0x1200 (P-256 public key) with compressed 33-byte point form
// and multibase base58btc encoding (z prefix).
func DIDKeyFromECPublicKey(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("EC public key is required")
	}
	if pub.Curve != elliptic.P256() {
		return "", fmt.Errorf("only P-256 curve is supported for did:key derivation")
	}
	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	// Multicodec 0x1200 as unsigned varint: [0x80, 0x24]
	payload := make([]byte, 0, 2+len(compressed))
	payload = append(payload, 0x80, 0x24)
	payload = append(payload, compressed...)
	return "did:key:z" + base58btcEncode(payload), nil
}

// DIDKeyFromRSAPublicKey derives a did:key identifier from an RSA public key.
// Uses multicodec 0x1205 (RSA public key) with PKCS#1 DER encoding.
func DIDKeyFromRSAPublicKey(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("RSA public key is required")
	}
	derBytes := x509.MarshalPKCS1PublicKey(pub)
	// Multicodec 0x1205 as unsigned varint: [0x85, 0x24]
	payload := make([]byte, 0, 2+len(derBytes))
	payload = append(payload, 0x85, 0x24)
	payload = append(payload, derBytes...)
	return "did:key:z" + base58btcEncode(payload), nil
}

// DIDKeyFromEd25519PublicKey derives a did:key identifier from an Ed25519 public key.
// Uses multicodec 0xed (ed25519-pub) with unsigned varint [0xed, 0x01]
// and multibase base58btc encoding (z prefix).
func DIDKeyFromEd25519PublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) == 0 {
		return "", fmt.Errorf("Ed25519 public key is required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	payload := make([]byte, 0, 2+len(pub))
	payload = append(payload, 0xed, 0x01)
	payload = append(payload, pub...)
	return "did:key:z" + base58btcEncode(payload), nil
}

// DIDJWKFromJSON derives a did:jwk identifier by base64url-encoding a JWK.
func DIDJWKFromJSON(jwk interface{}) (string, error) {
	raw, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK for did:jwk: %w", err)
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeMultibaseMulticodecKey decodes a multibase+multicodec public key to a Go crypto key.
// Returns the Go public key and a key type hint ("EC", "RSA", or "OKP").
// Supports base58btc (z prefix) with P-256 (0x1200), RSA (0x1205), and Ed25519 (0xed) multicodec prefixes.
func DecodeMultibaseMulticodecKey(encoded string) (interface{}, string, error) {
	if len(encoded) < 2 {
		return nil, "", fmt.Errorf("multibase value too short")
	}
	if encoded[0] != 'z' {
		return nil, "", fmt.Errorf("unsupported multibase prefix %q, only base58btc (z) is supported", string(encoded[0]))
	}
	raw, err := base58btcDecode(encoded[1:])
	if err != nil {
		return nil, "", fmt.Errorf("base58btc decode: %w", err)
	}
	if len(raw) < 3 {
		return nil, "", fmt.Errorf("multicodec payload too short")
	}
	// P-256 compressed public key: varint [0x80, 0x24] + 33 bytes
	if raw[0] == 0x80 && raw[1] == 0x24 {
		keyBytes := raw[2:]
		if len(keyBytes) != 33 {
			return nil, "", fmt.Errorf("P-256 compressed key must be 33 bytes, got %d", len(keyBytes))
		}
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
		if x == nil {
			return nil, "", fmt.Errorf("invalid P-256 compressed point")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, "EC", nil
	}
	// RSA PKCS#1 public key: varint [0x85, 0x24] + DER bytes
	if raw[0] == 0x85 && raw[1] == 0x24 {
		pub, err := x509.ParsePKCS1PublicKey(raw[2:])
		if err != nil {
			return nil, "", fmt.Errorf("parse RSA PKCS1 public key: %w", err)
		}
		return pub, "RSA", nil
	}
	// Ed25519 public key: varint [0xed, 0x01] + 32 bytes
	if raw[0] == 0xed && raw[1] == 0x01 {
		keyBytes := raw[2:]
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
		}
		return ed25519.PublicKey(append([]byte(nil), keyBytes...)), "OKP", nil
	}
	return nil, "", fmt.Errorf("unsupported multicodec prefix 0x%02x 0x%02x", raw[0], raw[1])
}

func base58btcDecode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	result := new(big.Int)
	base := big.NewInt(58)
	for _, c := range input {
		idx := -1
		for i, a := range base58btcAlphabet {
			if a == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}
	leadingZeros := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingZeros++
	}
	decoded := result.Bytes()
	output := make([]byte, leadingZeros+len(decoded))
	copy(output[leadingZeros:], decoded)
	return output, nil
}

func base58btcEncode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	var result []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58btcAlphabet[mod.Int64()])
	}
	for i := 0; i < leadingZeros; i++ {
		result = append(result, base58btcAlphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}
