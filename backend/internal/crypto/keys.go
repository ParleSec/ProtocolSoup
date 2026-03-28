package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

// KeySet manages RSA, EC, and Ed25519 keys for the showcase.
type KeySet struct {
	rsaKey       *rsa.PrivateKey
	ecKey        *ecdsa.PrivateKey
	ed25519Key   ed25519.PrivateKey
	rsaKeyID     string
	ecKeyID      string
	ed25519KeyID string
	createdAt    time.Time
	mu           sync.RWMutex
}

// NewKeySet generates a new key set with RSA, EC, and Ed25519 keys.
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

	// Generate Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Generate key IDs
	rsaKeyID := generateKeyID("rsa")
	ecKeyID := generateKeyID("ec")
	ed25519KeyID := generateKeyID("okp")

	return &KeySet{
		rsaKey:       rsaKey,
		ecKey:        ecKey,
		ed25519Key:   ed25519Key,
		rsaKeyID:     rsaKeyID,
		ecKeyID:      ecKeyID,
		ed25519KeyID: ed25519KeyID,
		createdAt:    time.Now(),
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

// Ed25519PrivateKey returns the Ed25519 private key.
func (ks *KeySet) Ed25519PrivateKey() ed25519.PrivateKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.ed25519Key
}

// Ed25519PublicKey returns the Ed25519 public key.
func (ks *KeySet) Ed25519PublicKey() ed25519.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	publicKey, _ := ks.ed25519Key.Public().(ed25519.PublicKey)
	return publicKey
}

// Ed25519KeyID returns the Ed25519 key ID.
func (ks *KeySet) Ed25519KeyID() string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.ed25519KeyID
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

	// EC / OKP specific
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // Public key value / X coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate for EC keys
	D   string `json:"d,omitempty"`   // Private key value for private JWKs
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
			ks.ed25519PublicJWK(),
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

// ed25519PublicJWK creates a JWK from the Ed25519 public key.
func (ks *KeySet) ed25519PublicJWK() JWK {
	pub := ks.Ed25519PublicKey()
	return JWK{
		Kty: "OKP",
		Use: "sig",
		Kid: ks.ed25519KeyID,
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
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
	case ks.ed25519KeyID:
		return ks.ed25519PublicJWK(), true
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

	// Generate new Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	ks.rsaKey = rsaKey
	ks.ecKey = ecKey
	ks.ed25519Key = ed25519Key
	ks.rsaKeyID = generateKeyID("rsa")
	ks.ecKeyID = generateKeyID("ec")
	ks.ed25519KeyID = generateKeyID("okp")
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
	case "OKP":
		canonical = map[string]string{
			"crv": jwk.Crv,
			"kty": jwk.Kty,
			"x":   jwk.X,
		}
	default:
		return ""
	}

	data, _ := json.Marshal(canonical)
	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
