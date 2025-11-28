package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
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

// CreateIDToken creates an OIDC ID token
func (s *JWTService) CreateIDToken(subject string, audience string, nonce string, authTime time.Time, duration time.Duration, userClaims map[string]interface{}) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       subject,
		"aud":       audience,
		"exp":       now.Add(duration).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Add user claims
	for k, v := range userClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySet.RSAKeyID()

	return token.SignedString(s.keySet.RSAPrivateKey())
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
