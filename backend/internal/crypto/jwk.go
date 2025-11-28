package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKSFetcher fetches and caches JWKS from remote endpoints
type JWKSFetcher struct {
	cache      map[string]*cachedJWKS
	mu         sync.RWMutex
	httpClient *http.Client
	cacheTTL   time.Duration
}

type cachedJWKS struct {
	jwks      JWKS
	fetchedAt time.Time
}

// NewJWKSFetcher creates a new JWKS fetcher with caching
func NewJWKSFetcher(cacheTTL time.Duration) *JWKSFetcher {
	return &JWKSFetcher{
		cache: make(map[string]*cachedJWKS),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheTTL: cacheTTL,
	}
}

// Fetch retrieves JWKS from a URL with caching
func (f *JWKSFetcher) Fetch(jwksURL string) (*JWKS, error) {
	// Check cache first
	f.mu.RLock()
	if cached, exists := f.cache[jwksURL]; exists {
		if time.Since(cached.fetchedAt) < f.cacheTTL {
			f.mu.RUnlock()
			return &cached.jwks, nil
		}
	}
	f.mu.RUnlock()

	// Fetch from remote
	resp, err := f.httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Update cache
	f.mu.Lock()
	f.cache[jwksURL] = &cachedJWKS{
		jwks:      jwks,
		fetchedAt: time.Now(),
	}
	f.mu.Unlock()

	return &jwks, nil
}

// GetKeyByID finds a key in JWKS by key ID
func (jwks *JWKS) GetKeyByID(kid string) (*JWK, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("key with id %s not found", kid)
}

// GetKeyByAlg finds a key in JWKS by algorithm
func (jwks *JWKS) GetKeyByAlg(alg string) (*JWK, error) {
	for _, key := range jwks.Keys {
		if key.Alg == alg {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("key with algorithm %s not found", alg)
}

// ToPublicKey converts a JWK to a Go public key
func (jwk *JWK) ToPublicKey() (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return jwk.toRSAPublicKey()
	case "EC":
		return jwk.toECPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func (jwk *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, errors.New("missing RSA key parameters")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func (jwk *JWK) toECPublicKey() (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, errors.New("missing EC key parameters")
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// JWKFromRSAPublicKey creates a JWK from an RSA public key
func JWKFromRSAPublicKey(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// JWKFromECPublicKey creates a JWK from an EC public key
func JWKFromECPublicKey(pub *ecdsa.PublicKey, kid string) JWK {
	var crv, alg string
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
		alg = "ES256"
	case elliptic.P384():
		crv = "P-384"
		alg = "ES384"
	case elliptic.P521():
		crv = "P-521"
		alg = "ES512"
	}

	return JWK{
		Kty: "EC",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
	}
}

// ValidateJWK performs basic validation on a JWK
func ValidateJWK(jwk JWK) error {
	if jwk.Kty == "" {
		return errors.New("missing key type (kty)")
	}

	switch jwk.Kty {
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return errors.New("RSA key missing n or e parameter")
		}
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return errors.New("EC key missing crv, x, or y parameter")
		}
	default:
		return fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	return nil
}

// JWKInfo provides human-readable information about a JWK
type JWKInfo struct {
	KeyType    string `json:"key_type"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	Use        string `json:"use"`
	KeySize    int    `json:"key_size,omitempty"` // Bits for RSA, 0 for EC
	Curve      string `json:"curve,omitempty"`    // For EC keys
	Thumbprint string `json:"thumbprint"`
}

// GetInfo returns human-readable information about a JWK
func (jwk *JWK) GetInfo() JWKInfo {
	info := JWKInfo{
		KeyType:    jwk.Kty,
		Algorithm:  jwk.Alg,
		KeyID:      jwk.Kid,
		Use:        jwk.Use,
		Thumbprint: jwk.Thumbprint(),
	}

	if jwk.Kty == "RSA" && jwk.N != "" {
		nBytes, _ := base64.RawURLEncoding.DecodeString(jwk.N)
		info.KeySize = len(nBytes) * 8
	}

	if jwk.Kty == "EC" {
		info.Curve = jwk.Crv
	}

	return info
}

