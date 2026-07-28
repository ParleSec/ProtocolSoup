package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"sort"
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
	case "OKP":
		return jwk.toOKPPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func (jwk *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	return parseRSAPublicKeyParameters(jwk.N, jwk.E)
}

func parseRSAPublicKeyParameters(encodedModulus, encodedExponent string) (*rsa.PublicKey, error) {
	if encodedModulus == "" || encodedExponent == "" {
		return nil, errors.New("missing RSA key parameters")
	}
	modulusBytes, err := base64.RawURLEncoding.DecodeString(encodedModulus)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	if len(modulusBytes) == 0 || modulusBytes[0] == 0 {
		return nil, errors.New("RSA modulus must be a minimally encoded positive integer")
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if modulus.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA modulus is %d bits; at least 2048 bits are required", modulus.BitLen())
	}
	if modulus.Bit(0) == 0 {
		return nil, errors.New("RSA modulus must be odd")
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(encodedExponent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	if len(exponentBytes) == 0 || exponentBytes[0] == 0 {
		return nil, errors.New("RSA exponent must be a minimally encoded positive integer")
	}
	exponent := new(big.Int).SetBytes(exponentBytes)
	if !exponent.IsInt64() ||
		exponent.Int64() > int64(math.MaxInt) ||
		exponent.Int64() < 3 ||
		exponent.Bit(0) == 0 {
		return nil, errors.New("RSA exponent must be an odd integer of at least 3 that fits in an int")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
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

	return parseECPublicKeyCoordinates(curve, xBytes, yBytes)
}

func (jwk *JWK) toOKPPublicKey() (ed25519.PublicKey, error) {
	if jwk.Crv == "" || jwk.X == "" {
		return nil, errors.New("missing OKP key parameters")
	}
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode okp x coordinate: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
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

// JWKFromECPublicKey creates a JWK from a validated EC public key. It panics
// only if the caller violates that invariant; all protocol call sites pass keys
// returned by the standard library's generation or parsing APIs.
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
	x, y, err := ecPublicKeyCoordinates(pub)
	if err != nil {
		panic(fmt.Sprintf("crypto: encode EC public key as JWK: %v", err))
	}

	return JWK{
		Kty: "EC",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

// ecPublicKeyCoordinates extracts fixed-width affine coordinates from the SEC 1
// uncompressed encoding returned by Go's validated ECDSA API. RFC 7518
// Sections 6.2.1.2 and 6.2.1.3 require these exact-width octet sequences for
// the JWK x and y members.
func ecPublicKeyCoordinates(pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	if pub == nil || pub.Curve == nil {
		return nil, nil, errors.New("EC public key is required")
	}
	encoded, err := pub.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("encode EC public key: %w", err)
	}
	coordinateSize := (pub.Curve.Params().BitSize + 7) / 8
	if len(encoded) != 1+2*coordinateSize || encoded[0] != 0x04 {
		return nil, nil, fmt.Errorf("unexpected SEC 1 public key length %d", len(encoded))
	}
	x := append([]byte(nil), encoded[1:1+coordinateSize]...)
	y := append([]byte(nil), encoded[1+coordinateSize:]...)
	return x, y, nil
}

// parseECPublicKeyCoordinates validates fixed-width JWK/COSE coordinates and
// reconstructs the key through Go's SEC 1 parser rather than mutable big.Int
// fields.
func parseECPublicKeyCoordinates(curve elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	if curve == nil {
		return nil, errors.New("EC curve is required")
	}
	coordinateSize := (curve.Params().BitSize + 7) / 8
	if len(x) != coordinateSize || len(y) != coordinateSize {
		return nil, fmt.Errorf(
			"invalid EC coordinate lengths x=%d y=%d, expected %d",
			len(x),
			len(y),
			coordinateSize,
		)
	}
	encoded := make([]byte, 1+2*coordinateSize)
	encoded[0] = 0x04
	copy(encoded[1:1+coordinateSize], x)
	copy(encoded[1+coordinateSize:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, encoded)
	if err != nil {
		return nil, fmt.Errorf("parse EC public key: %w", err)
	}
	return pub, nil
}

// JWKFromEd25519PublicKey creates a JWK from an Ed25519 public key.
func JWKFromEd25519PublicKey(pub ed25519.PublicKey, kid string) JWK {
	return JWK{
		Kty: "OKP",
		Use: "sig",
		Kid: kid,
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// ValidateJWK validates supported public-key parameters.
func ValidateJWK(jwk JWK) error {
	if jwk.Kty == "" {
		return errors.New("missing key type (kty)")
	}

	switch jwk.Kty {
	case "RSA":
		_, err := jwk.toRSAPublicKey()
		return err
	case "EC":
		_, err := jwk.toECPublicKey()
		return err
	case "OKP":
		_, err := jwk.toOKPPublicKey()
		return err
	default:
		return fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

var privateJWKMemberNames = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// PrivateJWKMembers returns every private-key member present in raw JWKS JSON,
// including members with empty, null, or structurally invalid values.
func PrivateJWKMembers(raw []byte) ([]string, error) {
	var document struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	found := make(map[string]struct{})
	for _, key := range document.Keys {
		for _, member := range privateJWKMemberNames {
			if _, present := key[member]; present {
				found[member] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(found))
	for member := range found {
		result = append(result, member)
	}
	sort.Strings(result)
	return result, nil
}

// JWKContainsPrivateMaterial detects private members retained in a typed JWK.
func JWKContainsPrivateMaterial(jwk JWK) bool {
	return jwk.D != "" ||
		jwk.P != "" ||
		jwk.Q != "" ||
		jwk.DP != "" ||
		jwk.DQ != "" ||
		jwk.QI != "" ||
		len(jwk.Oth) != 0 ||
		jwk.K != ""
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
	if jwk.Kty == "OKP" {
		info.Curve = jwk.Crv
	}

	return info
}

// ParseOKPPublicKeyFromJWK parses an OKP public key from JWK.
func ParseOKPPublicKeyFromJWK(jwk JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" {
		return nil, errors.New("not an OKP key")
	}
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode okp x coordinate: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}
