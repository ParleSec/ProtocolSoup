package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT creation and validation
type JWTService struct {
	keySet *KeySet
	issuer string

	// unprofiledAccessTokens holds the jti and expiry of each live access
	// token CreateUnprofiledAccessToken minted. Such a token declares no type
	// (its "typ" is "JWT", like an ID Token's), so this record is the only
	// thing that tells it from the other JWTs the key set signs.
	unprofiledMu           sync.Mutex
	unprofiledAccessTokens map[string]time.Time
}

// NewJWTService creates a new JWT service
func NewJWTService(keySet *KeySet, issuer string) *JWTService {
	return &JWTService{
		keySet:                 keySet,
		issuer:                 issuer,
		unprofiledAccessTokens: make(map[string]time.Time),
	}
}

// StandardClaims represents standard JWT claims
type StandardClaims struct {
	jwt.RegisteredClaims
	// Custom claims can be added via map
	Custom map[string]interface{} `json:"-"`
}

// SignClaimsRS256 signs an arbitrary claim set as a compact JWS using the OP's
// current RSA signing key (RS256). Used for signed UserInfo responses
// (OpenID Connect Core 1.0 Section 5.3.2).
func (s *JWTService) SignClaimsRS256(claims map[string]interface{}) (string, error) {
	if claims == nil {
		claims = map[string]interface{}{}
	}
	copied := make(jwt.MapClaims, len(claims))
	for k, v := range claims {
		copied[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, copied)
	token.Header["kid"] = s.keySet.RSAKeyID()
	return token.SignedString(s.keySet.RSAPrivateKey())
}

// AccessTokenType is the "typ" header value of a JWT access token. RFC 9068
// Section 2.1: "JWT access tokens MUST include this media type in the "typ"
// header parameter to explicitly declare that the JWT represents an access
// token complying with this profile. Per the definition of "typ" in Section
// 4.1.9 of [RFC7515], it is RECOMMENDED that the "application/" prefix be
// omitted. Therefore, the "typ" value used SHOULD be "at+jwt"."
const AccessTokenType = "at+jwt"

// AccessToken holds what an authorization server puts in a JWT access token.
type AccessToken struct {
	// Issuer is the issuer identifier of the authorization server that issues
	// the token, as its metadata publishes it. Empty means the issuer the
	// JWTService was built with.
	Issuer string
	// Subject is the resource owner, or the client when no resource owner
	// takes part in the grant (RFC 9068 Section 2.2).
	Subject string
	// Audience is the resource indicator of the protected resource the token
	// is for. RFC 7519 Section 4.1.3: "Each principal intended to process the
	// JWT MUST identify itself with a value in the audience claim."
	Audience string
	// ClientID is the client that requested the token. RFC 8693 Section 4.3:
	// 'The "client_id" claim carries the client identifier of the OAuth 2.0
	// [RFC6749] client that requested the token.'
	ClientID string
	Scope    string
	Lifetime time.Duration
	// Claims are added to the token. They never replace a claim this type
	// sets itself.
	Claims map[string]interface{}
}

// CreateAccessToken signs a JWT access token that follows the JWT Profile for
// OAuth 2.0 Access Tokens (RFC 9068). Section 2.2 makes iss, exp, aud, sub,
// client_id, iat and jti REQUIRED, so a token with no audience, subject or
// client is refused.
func (s *JWTService) CreateAccessToken(token AccessToken) (string, error) {
	if token.ClientID == "" {
		return "", errors.New("an RFC 9068 access token requires the client_id claim (Section 2.2)")
	}
	signed, _, _, err := s.signAccessToken(token, AccessTokenType)
	return signed, err
}

// CreateUnprofiledAccessToken signs a JWT access token that does not claim
// the RFC 9068 profile, so its "typ" stays "JWT". It is for an authorization
// server that cannot meet the profile: RFC 9068 Section 2.2 makes client_id
// REQUIRED, and an OID4VCI Pre-Authorized Code Token Request may be sent
// without a client_id (pre-authorized_grant_anonymous_access_supported,
// OID4VCI 1.0 Section 12.3). client_id is carried when the request had one.
func (s *JWTService) CreateUnprofiledAccessToken(token AccessToken) (string, error) {
	signed, jti, expiresAt, err := s.signAccessToken(token, "JWT")
	if err != nil {
		return "", err
	}

	s.unprofiledMu.Lock()
	defer s.unprofiledMu.Unlock()
	now := time.Now()
	for recorded, expiry := range s.unprofiledAccessTokens {
		if !expiry.After(now) {
			delete(s.unprofiledAccessTokens, recorded)
		}
	}
	s.unprofiledAccessTokens[jti] = expiresAt
	return signed, nil
}

// IssuedAccessToken verifies tokenString against this service's key set and
// its time claims, and reports whether it is an access token this service
// minted. An RFC 9068 access token says so itself: Section 2.1, "JWT access
// tokens MUST include this media type in the "typ" header parameter to
// explicitly declare that the JWT represents an access token complying with
// this profile." An unprofiled access token declares nothing, so it is one
// only when CreateUnprofiledAccessToken recorded its jti. Every other JWT the
// key set signed (an ID Token, a signed UserInfo response, a JWT another
// component signed with the same key) is not an access token of this service.
//
// The error is non-nil when tokenString is not a currently valid JWT of this
// key set at all.
func (s *JWTService) IssuedAccessToken(tokenString string) (claims jwt.MapClaims, isAccessToken bool, err error) {
	token, err := s.parse(tokenString)
	if err != nil {
		return nil, false, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false, errors.New("invalid claims format")
	}

	typ, _ := token.Header["typ"].(string)
	if strings.EqualFold(typ, AccessTokenType) || strings.EqualFold(typ, "application/"+AccessTokenType) {
		return claims, true, nil
	}
	jti, _ := claims["jti"].(string)
	s.unprofiledMu.Lock()
	defer s.unprofiledMu.Unlock()
	_, recorded := s.unprofiledAccessTokens[jti]
	return claims, recorded, nil
}

func (s *JWTService) signAccessToken(token AccessToken, typ string) (signedToken, jti string, expiresAt time.Time, err error) {
	if token.Subject == "" {
		return "", "", time.Time{}, errors.New("an access token requires the sub claim")
	}
	if token.Audience == "" {
		return "", "", time.Time{}, errors.New("an access token requires the aud claim: the protected resource it is for")
	}
	issuer := token.Issuer
	if issuer == "" {
		issuer = s.issuer
	}
	now := time.Now()

	claims := jwt.MapClaims{}
	for k, v := range token.Claims {
		claims[k] = v
	}
	jti = generateKeyID("jti")
	expiresAt = time.Unix(now.Add(token.Lifetime).Unix(), 0)
	claims["iss"] = issuer
	claims["sub"] = token.Subject
	claims["aud"] = token.Audience
	claims["exp"] = expiresAt.Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["scope"] = token.Scope
	claims["jti"] = jti
	if token.ClientID != "" {
		claims["client_id"] = token.ClientID
	}

	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed.Header["typ"] = typ
	signed.Header["kid"] = s.keySet.RSAKeyID()

	signedToken, err = signed.SignedString(s.keySet.RSAPrivateKey())
	return signedToken, jti, expiresAt, err
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

	// ACR is the Authentication Context Class Reference actually satisfied by the
	// End-User authentication (OIDC Core 1.0 Section 2). It is set only when a
	// genuine authentication context applies and reflects the authentication that
	// was performed, never a requested value the OP did not satisfy.
	ACR string

	// AMR lists the Authentication Methods References used in the authentication
	// (RFC 8176). For example ["pwd"] for a password login.
	AMR []string
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

	// Add acr/amr describing the authentication context that was actually
	// performed (OIDC Core 1.0 Section 2, RFC 8176). These reflect the real
	// authentication and are never set to an unsatisfied requested value.
	if options != nil && options.ACR != "" {
		claims["acr"] = options.ACR
	}
	if options != nil && len(options.AMR) > 0 {
		claims["amr"] = options.AMR
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
		hash := sha512.Sum384([]byte(value))
		hashBytes = hash[:]
		leftBits = 24 // 192 bits = 24 bytes
	case "RS512", "ES512":
		hash := sha512.Sum512([]byte(value))
		hashBytes = hash[:]
		leftBits = 32 // 256 bits = 32 bytes
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

// AccessTokenError reports which RFC 9068 Section 4 validation step refused a
// JWT access token.
type AccessTokenError struct {
	// Check is "signature", "typ", "iss" or "aud".
	Check string
	// Reason says what was wrong, for the error_description and Looking Glass.
	Reason string
}

func (e *AccessTokenError) Error() string { return e.Reason }

// ValidateAccessToken is the resource server validation of RFC 9068 Section
// 4: "Resource servers receiving a JWT access token MUST validate it in the
// following manner." issuer is the issuer identifier of the authorization
// server the resource server trusts, and audience is the identifier the
// resource server expects for itself.
//
// A failure is an *AccessTokenError. When the signature and expiry checked
// out and a later step failed, the claims are returned with the error so the
// caller can tell a DPoP-bound token from a bearer token in its challenge.
func (s *JWTService) ValidateAccessToken(tokenString, issuer, audience string) (jwt.MapClaims, error) {
	// "The resource server MUST validate the signature of all incoming JWT
	// access tokens according to [RFC7515] using the algorithm specified in
	// the JWT "alg" Header Parameter. The resource server MUST reject any JWT
	// in which the value of "alg" is "none"." and "The current time MUST be
	// before the time represented by the "exp" claim."
	token, err := s.parse(tokenString, jwt.WithExpirationRequired())
	if err != nil {
		return nil, &AccessTokenError{Check: "signature", Reason: err.Error()}
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &AccessTokenError{Check: "signature", Reason: "invalid claims format"}
	}

	// "The resource server MUST verify that the "typ" header value is
	// "at+jwt" or "application/at+jwt" and reject tokens carrying any other
	// value." Media type names are not case sensitive (RFC 7515 Section
	// 4.1.9); RFC 9068 Figure 2 itself writes "at+JWT".
	typ, _ := token.Header["typ"].(string)
	if !strings.EqualFold(typ, AccessTokenType) && !strings.EqualFold(typ, "application/"+AccessTokenType) {
		return claims, &AccessTokenError{Check: "typ", Reason: fmt.Sprintf("the \"typ\" header value is %q, not \"at+jwt\" or \"application/at+jwt\"", typ)}
	}

	// "The issuer identifier for the authorization server (which is typically
	// obtained during discovery) MUST exactly match the value of the "iss"
	// claim."
	if iss, _ := claims["iss"].(string); iss != issuer {
		return claims, &AccessTokenError{Check: "iss", Reason: fmt.Sprintf("the \"iss\" claim %q is not the issuer identifier %q of this resource's authorization server", iss, issuer)}
	}

	// "The resource server MUST validate that the "aud" claim contains a
	// resource indicator value corresponding to an identifier the resource
	// server expects for itself. The JWT access token MUST be rejected if
	// "aud" does not contain a resource indicator of the current resource
	// server as a valid audience."
	if !AudienceContains(claims["aud"], audience) {
		return claims, &AccessTokenError{Check: "aud", Reason: fmt.Sprintf("the \"aud\" claim does not contain this resource's identifier %q", audience)}
	}

	return claims, nil
}

// AudienceContains reports whether an "aud" claim value names expected. RFC
// 7519 Section 4.1.3: "In the general case, the "aud" value is an array of
// case-sensitive strings, each containing a StringOrURI value. In the special
// case when the JWT has one audience, the "aud" value MAY be a single
// case-sensitive string containing a StringOrURI value."
func AudienceContains(aud interface{}, expected string) bool {
	if expected == "" {
		return false
	}
	switch value := aud.(type) {
	case string:
		return value == expected
	case []string:
		for _, item := range value {
			if item == expected {
				return true
			}
		}
	case []interface{}:
		for _, item := range value {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// ValidateToken validates a JWT and returns its claims
func (s *JWTService) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := s.parse(tokenString)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	return claims, nil
}

// parse verifies a JWT's signature against this service's key set and checks
// its time claims.
func (s *JWTService) parse(tokenString string, options ...jwt.ParserOption) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if err := RejectCriticalHeader(token.Header); err != nil {
			return nil, err
		}
		// Check signing method
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return s.keySet.RSAPublicKey(), nil
		case *jwt.SigningMethodECDSA:
			return s.keySet.ECPublicKey(), nil
		case *jwt.SigningMethodEd25519:
			return s.keySet.Ed25519PublicKey(), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	}, options...)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
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

// RejectCriticalHeader reports a JOSE Header that carries the "crit" Header
// Parameter. RFC 7515 Section 4.1.11: "If any of the listed extension Header
// Parameters are not understood and supported by the recipient, then the JWS
// is invalid." ProtocolSoup understands and supports no JWS extension, so
// every "crit" value makes the JWS invalid. Section 5.2 step 5 puts the check
// in signature validation, so every JWS verifier calls this before trusting
// the signature.
func RejectCriticalHeader(header map[string]interface{}) error {
	critical, present := header["crit"]
	if !present {
		return nil
	}
	return fmt.Errorf("JWS is invalid: \"crit\" Header Parameter %v lists extensions that are not understood and supported (RFC 7515 Section 4.1.11)", critical)
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
	if err := RejectCriticalHeader(header); err != nil {
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
	case "EdDSA":
		method = jwt.SigningMethodEdDSA
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
	if kid == s.keySet.Ed25519KeyID() {
		return s.keySet.Ed25519PublicKey(), alg, nil
	}

	// Fallback based on algorithm
	if strings.HasPrefix(alg, "RS") {
		return s.keySet.RSAPublicKey(), alg, nil
	}
	if strings.HasPrefix(alg, "ES") {
		return s.keySet.ECPublicKey(), alg, nil
	}
	if alg == "EdDSA" {
		return s.keySet.Ed25519PublicKey(), alg, nil
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

	return parseECPublicKeyCoordinates(curve, xBytes, yBytes)
}

// ParseEd25519PublicKeyFromJWK parses an Ed25519 public key from JWK.
func ParseEd25519PublicKeyFromJWK(jwk JWK) (ed25519.PublicKey, error) {
	return ParseOKPPublicKeyFromJWK(jwk)
}
