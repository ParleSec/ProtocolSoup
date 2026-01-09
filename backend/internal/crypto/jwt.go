package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT creation and validation
type JWTService struct {
	keySet *KeySet
	issuer string
}

// NewJWTService creates a new JWT service
func NewJWTService(keySet *KeySet, issuer string) *JWTService {
	return &JWTService{
		keySet: keySet,
		issuer: issuer,
	}
}

// StandardClaims represents standard JWT claims
type StandardClaims struct {
	jwt.RegisteredClaims
	// Custom claims can be added via map
	Custom map[string]interface{} `json:"-"`
}

// CreateAccessToken creates a new access token
func (s *JWTService) CreateAccessToken(subject string, audience string, scope string, duration time.Duration, customClaims map[string]interface{}) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"sub":   subject,
		"aud":   audience,
		"exp":   now.Add(duration).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"scope": scope,
		"jti":   generateKeyID("jti"),
	}

	// Add custom claims
	for k, v := range customClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySet.RSAKeyID()

	return token.SignedString(s.keySet.RSAPrivateKey())
}

// IDTokenOptions contains optional parameters for ID token creation per OIDC Core 1.0
type IDTokenOptions struct {
	// AccessToken is used to compute at_hash (OIDC Core 1.0 Section 3.3.2.11)
	// Required for implicit/hybrid flows that return access_token
	AccessToken string

	// AuthorizationCode is used to compute c_hash (OIDC Core 1.0 Section 3.3.2.11)
	// Required for hybrid flow when code is returned
	AuthorizationCode string

	// AdditionalAudiences for multi-audience scenarios (triggers azp claim)
	AdditionalAudiences []string
}

// CreateIDToken creates an OIDC ID token
func (s *JWTService) CreateIDToken(subject string, audience string, nonce string, authTime time.Time, duration time.Duration, userClaims map[string]interface{}) (string, error) {
	return s.CreateIDTokenWithOptions(subject, audience, nonce, authTime, duration, userClaims, nil)
}

// CreateIDTokenWithOptions creates an OIDC ID token with additional options per OIDC Core 1.0
// Supports at_hash, c_hash, and azp claims for hybrid/implicit flows
func (s *JWTService) CreateIDTokenWithOptions(subject string, audience string, nonce string, authTime time.Time, duration time.Duration, userClaims map[string]interface{}, options *IDTokenOptions) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       subject,
		"exp":       now.Add(duration).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
	}

	// Handle audience and azp per OIDC Core 1.0 Section 2
	// "azp" SHOULD be present when the ID Token has a single audience value and that audience
	// is different from the authorized party, or when the ID Token has multiple audience values
	if options != nil && len(options.AdditionalAudiences) > 0 {
		// Multiple audiences - set aud as array and azp as the primary client
		allAudiences := append([]string{audience}, options.AdditionalAudiences...)
		claims["aud"] = allAudiences
		claims["azp"] = audience // Per OIDC Core 1.0 Section 2: azp is the party the token was issued to
	} else {
		claims["aud"] = audience
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Add at_hash if access token is provided (OIDC Core 1.0 Section 3.3.2.11)
	// Required when access_token is returned from authorization endpoint
	if options != nil && options.AccessToken != "" {
		atHash := computeHashClaim(options.AccessToken, "RS256")
		claims["at_hash"] = atHash
	}

	// Add c_hash if authorization code is provided (OIDC Core 1.0 Section 3.3.2.11)
	// Required for hybrid flow when code is returned with id_token
	if options != nil && options.AuthorizationCode != "" {
		cHash := computeHashClaim(options.AuthorizationCode, "RS256")
		claims["c_hash"] = cHash
	}

	// Add user claims
	for k, v := range userClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySet.RSAKeyID()

	return token.SignedString(s.keySet.RSAPrivateKey())
}

// computeHashClaim computes at_hash or c_hash per OIDC Core 1.0 Section 3.3.2.11
// The hash is computed as: base64url(left-half(hash(value)))
// For RS256 (SHA-256): take left 128 bits (16 bytes) of SHA-256 hash
func computeHashClaim(value string, alg string) string {
	// Determine hash algorithm based on signing algorithm
	// RS256/ES256 -> SHA-256 -> left 128 bits
	// RS384/ES384 -> SHA-384 -> left 192 bits
	// RS512/ES512 -> SHA-512 -> left 256 bits
	var hashBytes []byte
	var leftBits int

	switch alg {
	case "RS256", "ES256":
		hash := sha256.Sum256([]byte(value))
		hashBytes = hash[:]
		leftBits = 16 // 128 bits = 16 bytes
	case "RS384", "ES384":
		// For SHA-384, we'd need crypto/sha512.Sum384
		// For now, fall back to SHA-256 approach
		hash := sha256.Sum256([]byte(value))
		hashBytes = hash[:]
		leftBits = 16
	case "RS512", "ES512":
		// For SHA-512, we'd need crypto/sha512.Sum512
		// For now, fall back to SHA-256 approach
		hash := sha256.Sum256([]byte(value))
		hashBytes = hash[:]
		leftBits = 16
	default:
		// Default to SHA-256
		hash := sha256.Sum256([]byte(value))
		hashBytes = hash[:]
		leftBits = 16
	}

	// Take left half of hash
	leftHalf := hashBytes[:leftBits]

	// Base64url encode without padding
	return base64.RawURLEncoding.EncodeToString(leftHalf)
}

// CreateRefreshToken creates a refresh token (can be opaque or JWT)
func (s *JWTService) CreateRefreshToken(subject string, clientID string, scope string, duration time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       subject,
		"client_id": clientID,
		"exp":       now.Add(duration).Unix(),
		"iat":       now.Unix(),
		"scope":     scope,
		"jti":       generateKeyID("refresh"),
		"type":      "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySet.RSAKeyID()

	return token.SignedString(s.keySet.RSAPrivateKey())
}

// ValidateToken validates a JWT and returns its claims
func (s *JWTService) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return s.keySet.RSAPublicKey(), nil
		case *jwt.SigningMethodECDSA:
			return s.keySet.ECPublicKey(), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	return claims, nil
}

// DecodeTokenWithoutValidation decodes a JWT without validating signature
// Used for looking glass inspection
func DecodeTokenWithoutValidation(tokenString string) (*DecodedToken, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format: expected 3 parts")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	return &DecodedToken{
		Header:       header,
		Payload:      payload,
		Signature:    parts[2],
		HeaderRaw:    parts[0],
		PayloadRaw:   parts[1],
		SignatureRaw: parts[2],
	}, nil
}

// DecodedToken represents a decoded JWT for inspection
type DecodedToken struct {
	Header       map[string]interface{} `json:"header"`
	Payload      map[string]interface{} `json:"payload"`
	Signature    string                 `json:"signature"`
	HeaderRaw    string                 `json:"header_raw"`
	PayloadRaw   string                 `json:"payload_raw"`
	SignatureRaw string                 `json:"signature_raw"`
}

// VerifySignatureWithKey verifies a token signature with a given key
func VerifySignatureWithKey(tokenString string, key interface{}) (bool, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid token format")
	}

	// Decode header to get algorithm
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, err
	}

	alg, ok := header["alg"].(string)
	if !ok {
		return false, errors.New("missing algorithm in header")
	}

	// Select signing method
	var method jwt.SigningMethod
	switch alg {
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512
	case "ES256":
		method = jwt.SigningMethodES256
	case "ES384":
		method = jwt.SigningMethodES384
	case "ES512":
		method = jwt.SigningMethodES512
	default:
		return false, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}

	err = method.Verify(signingInput, signature, key)
	return err == nil, nil
}

// GetPublicKeyForToken returns the appropriate public key for verifying a token
func (s *JWTService) GetPublicKeyForToken(tokenString string) (interface{}, string, error) {
	decoded, err := DecodeTokenWithoutValidation(tokenString)
	if err != nil {
		return nil, "", err
	}

	kid, _ := decoded.Header["kid"].(string)
	alg, _ := decoded.Header["alg"].(string)

	if kid == s.keySet.RSAKeyID() {
		return s.keySet.RSAPublicKey(), alg, nil
	}
	if kid == s.keySet.ECKeyID() {
		return s.keySet.ECPublicKey(), alg, nil
	}

	// Fallback based on algorithm
	if strings.HasPrefix(alg, "RS") {
		return s.keySet.RSAPublicKey(), alg, nil
	}
	if strings.HasPrefix(alg, "ES") {
		return s.keySet.ECPublicKey(), alg, nil
	}

	return nil, alg, errors.New("unable to determine key for token")
}

// ParseRSAPublicKeyFromJWK parses an RSA public key from JWK
func ParseRSAPublicKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("not an RSA key")
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

// ParseECPublicKeyFromJWK parses an EC public key from JWK
func ParseECPublicKeyFromJWK(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, errors.New("not an EC key")
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
