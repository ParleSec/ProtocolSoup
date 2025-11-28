package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// KeySet manages cryptographic keys for the showcase
type KeySet struct {
	rsaKey    *rsa.PrivateKey
	ecKey     *ecdsa.PrivateKey
	rsaKeyID  string
	ecKeyID   string
	createdAt time.Time
	mu        sync.RWMutex
}

// NewKeySet generates a new key set with RSA and EC keys
func NewKeySet() (*KeySet, error) {
	// Generate RSA key (2048 bits for demo purposes)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate EC key (P-256)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}

	// Generate key IDs
	rsaKeyID := generateKeyID("rsa")
	ecKeyID := generateKeyID("ec")

	return &KeySet{
		rsaKey:    rsaKey,
		ecKey:     ecKey,
		rsaKeyID:  rsaKeyID,
		ecKeyID:   ecKeyID,
		createdAt: time.Now(),
	}, nil
}

// generateKeyID creates a unique key identifier
func generateKeyID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

// RSAPrivateKey returns the RSA private key
func (ks *KeySet) RSAPrivateKey() *rsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.rsaKey
}

// RSAPublicKey returns the RSA public key
func (ks *KeySet) RSAPublicKey() *rsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return &ks.rsaKey.PublicKey
}

// RSAKeyID returns the RSA key ID
func (ks *KeySet) RSAKeyID() string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.rsaKeyID
}

// ECPrivateKey returns the EC private key
func (ks *KeySet) ECPrivateKey() *ecdsa.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.ecKey
}

// ECPublicKey returns the EC public key
func (ks *KeySet) ECPublicKey() *ecdsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return &ks.ecKey.PublicKey
}

// ECKeyID returns the EC key ID
func (ks *KeySet) ECKeyID() string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.ecKeyID
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm

	// RSA specific
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC specific
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X Coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWKS returns the public keys in JWKS format
func (ks *KeySet) PublicJWKS() JWKS {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return JWKS{
		Keys: []JWK{
			ks.rsaPublicJWK(),
			ks.ecPublicJWK(),
		},
	}
}

// rsaPublicJWK creates a JWK from the RSA public key
func (ks *KeySet) rsaPublicJWK() JWK {
	pub := &ks.rsaKey.PublicKey
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: ks.rsaKeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ecPublicJWK creates a JWK from the EC public key
func (ks *KeySet) ecPublicJWK() JWK {
	pub := &ks.ecKey.PublicKey
	return JWK{
		Kty: "EC",
		Use: "sig",
		Kid: ks.ecKeyID,
		Alg: "ES256",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
}

// GetJWKByID returns a specific JWK by key ID
func (ks *KeySet) GetJWKByID(kid string) (JWK, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	switch kid {
	case ks.rsaKeyID:
		return ks.rsaPublicJWK(), true
	case ks.ecKeyID:
		return ks.ecPublicJWK(), true
	default:
		return JWK{}, false
	}
}

// Rotate generates new keys (useful for demonstrating key rotation)
func (ks *KeySet) Rotate() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Generate new RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate new EC key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate EC key: %w", err)
	}

	ks.rsaKey = rsaKey
	ks.ecKey = ecKey
	ks.rsaKeyID = generateKeyID("rsa")
	ks.ecKeyID = generateKeyID("ec")
	ks.createdAt = time.Now()

	return nil
}

// CreatedAt returns when the keys were created
func (ks *KeySet) CreatedAt() time.Time {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.createdAt
}

// Thumbprint calculates the JWK thumbprint (RFC 7638)
func (jwk JWK) Thumbprint() string {
	var canonical map[string]string

	switch jwk.Kty {
	case "RSA":
		canonical = map[string]string{
			"e":   jwk.E,
			"kty": jwk.Kty,
			"n":   jwk.N,
		}
	case "EC":
		canonical = map[string]string{
			"crv": jwk.Crv,
			"kty": jwk.Kty,
			"x":   jwk.X,
			"y":   jwk.Y,
		}
	default:
		return ""
	}

	data, _ := json.Marshal(canonical)
	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

