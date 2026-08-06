// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449) proof validation and the JWK thumbprint key-binding it relies
// on. It is a general OAuth 2.0 capability shared by the authorization
// server (internal/protocols/oauth2) and any resource server that accepts
// DPoP-bound tokens (internal/protocols/oid4vci) -- both directions of that
// relationship must be able to import this package, so it deliberately
// imports nothing from internal/protocols/* to avoid a dependency cycle.
package dpop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// HeaderName is the HTTP request header that carries a DPoP proof JWT
	// (RFC 9449 Section 4), and, per Section 7.1, also the Authorization
	// scheme a client uses to present a DPoP-bound access token
	// ("Authorization: DPoP <token>"). Both uses share the same literal
	// string in the spec, so a single constant is correct for both.
	HeaderName = "DPoP"

	// NonceHeaderName is the response header carrying a server-supplied
	// nonce (RFC 9449 Section 8).
	NonceHeaderName = "DPoP-Nonce"

	// ProofTyp is the required JOSE "typ" header value for a DPoP proof
	// (RFC 9449 Section 4.2).
	ProofTyp = "dpop+jwt"

	// ErrorUseDPoPNonce is the error code an AS/RS returns to request a
	// fresh server-provided nonce (RFC 9449 Section 8).
	ErrorUseDPoPNonce = "use_dpop_nonce"

	// ErrorInvalidDPoPProof is the token-endpoint error code for a
	// structurally or cryptographically invalid proof (RFC 9449 Section 5).
	ErrorInvalidDPoPProof = "invalid_dpop_proof"

	// IatFreshnessWindow bounds how far from "now" a DPoP proof's iat may
	// be, applied symmetrically for clock skew in both directions (RFC 9449
	// Section 11.1: proofs should only be accepted for a short time after
	// creation to limit the replay window). This is deliberately tighter
	// than the 5-minute clientAttestationPoPSkew used for Client
	// Attestation PoP (internal/protocols/oid4vci/client_attestation.go): a
	// DPoP proof is minted per-request against a live endpoint, so it has
	// no legitimate reason to be minutes old, whereas an attestation PoP
	// may be reused across a session.
	IatFreshnessWindow = 60 * time.Second
)

// AllowedAlgorithms is the explicit asymmetric-algorithm allowlist for DPoP
// proof signatures (RFC 9449 Section 4.2). "none" and any MAC/symmetric
// algorithm are rejected by omission -- the header's own "alg" claim is
// never trusted on its own, mirroring the allowlist discipline already used
// elsewhere in the JOSE paths of this codebase.
var AllowedAlgorithms = map[string]bool{
	"RS256": true,
	"ES256": true,
	"EdDSA": true,
}

// AllowedAlgorithmsList is AllowedAlgorithms in a fixed, deterministic
// order, for exposing via authorization server metadata (RFC 9449 Section
// 5.1 dpop_signing_alg_values_supported) where map iteration order would
// otherwise be nondeterministic across responses.
var AllowedAlgorithmsList = []string{"RS256", "ES256", "EdDSA"}

// Proof is the validated result of a DPoP proof JWT.
type Proof struct {
	// JTI is the proof's unique identifier (RFC 9449 Section 4.2), used for
	// replay detection.
	JTI string
	// JKT is the RFC 7638 JWK SHA-256 thumbprint of the proof's public key
	// (the header's "jwk" member). This is the value that gets bound into
	// an access token's cnf.jkt claim.
	JKT string
	// JWK is the parsed public key carried in the proof header.
	JWK internalcrypto.JWK
	// IAT is the proof's issued-at time.
	IAT time.Time
	// Nonce is the proof's nonce claim, if any (RFC 9449 Section 8).
	Nonce string
}

// ValidateOptions parameterizes ValidateProof against the request it is
// meant to be bound to.
type ValidateOptions struct {
	// Method is the HTTP method of the request carrying the proof, compared
	// against the proof's htm claim (case-sensitively, against the
	// uppercased method).
	Method string
	// URI is the request's target URI (RFC 9449 Section 4.3 htu), compared
	// against the proof's htu claim after normalization on both sides.
	URI string
	// AccessToken, when non-empty, makes the ath claim mandatory and checks
	// it against base64url(SHA-256(AccessToken)) in constant time.
	AccessToken string
	// RequiredNonce, when non-empty, makes the proof's nonce claim
	// mandatory and checks it in constant time (RFC 9449 Section 8).
	RequiredNonce string
	// Now overrides the current time for freshness checks. Zero means
	// time.Now().UTC().
	Now time.Time
}

// ExtractHeader picks the single DPoP proof value out of the raw values of
// a request's DPoP header field (e.g. http.Request.Header.Values("DPoP")).
// An empty slice returns "", nil -- DPoP is opt-in, so an absent header is
// not itself an error. More than one value is a hard reject per RFC 9449
// Section 4.3 check 1 ("There is not more than one DPoP HTTP request
// header field"): silently taking the first and ignoring the rest (as
// http.Header.Get would) would let a smuggled second header go unnoticed.
func ExtractHeader(values []string) (string, error) {
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return strings.TrimSpace(values[0]), nil
	default:
		return "", errors.New("dpop: more than one DPoP header field was present")
	}
}

// ValidateProof validates a DPoP proof JWT per RFC 9449 Section 4.3. Every
// check is a hard failure -- there is no strip-and-continue path anywhere in
// this function.
func ValidateProof(compact string, opts ValidateOptions) (*Proof, error) {
	compact = strings.TrimSpace(compact)
	if compact == "" {
		return nil, errors.New("dpop: proof is required")
	}

	decoded, err := internalcrypto.DecodeTokenWithoutValidation(compact)
	if err != nil {
		return nil, fmt.Errorf("dpop: decode proof: %w", err)
	}

	// RFC 9449 Section 4.2: "typ: REQUIRED. Type header parameter. It MUST
	// have the value dpop+jwt".
	typ, _ := decoded.Header["typ"].(string)
	if typ != ProofTyp {
		return nil, fmt.Errorf("dpop: typ header must be %q", ProofTyp)
	}

	// RFC 9449 Section 4.2: "alg: REQUIRED. ... MUST NOT be none or an
	// identifier for a symmetric algorithm". Checked against an explicit
	// allowlist, never against the header's own claim of asymmetry.
	algHeader, _ := decoded.Header["alg"].(string)
	if !AllowedAlgorithms[algHeader] {
		return nil, fmt.Errorf("dpop: alg %q is not permitted", algHeader)
	}

	// RFC 9449 Section 4.2: "jwk: REQUIRED. ... MUST NOT contain a private
	// key". A private-key-bearing jwk is a hard reject, not a
	// strip-and-continue.
	jwkRaw, ok := decoded.Header["jwk"]
	if !ok {
		return nil, errors.New("dpop: jwk header is required")
	}
	jwk, err := parseHeaderJWK(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("dpop: jwk header: %w", err)
	}
	if internalcrypto.JWKContainsPrivateMaterial(jwk) {
		return nil, errors.New("dpop: jwk header must be a public key only")
	}
	if err := internalcrypto.ValidateJWK(jwk); err != nil {
		return nil, fmt.Errorf("dpop: jwk header is invalid: %w", err)
	}
	if err := algMatchesKeyType(algHeader, jwk); err != nil {
		return nil, err
	}

	publicKey, err := jwk.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("dpop: resolve jwk public key: %w", err)
	}

	parsed, err := jwt.Parse(compact, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != algHeader {
			return nil, errors.New("dpop: signature algorithm does not match the header alg")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("dpop: signature validation failed: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("dpop: signature validation failed")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("dpop: claims are invalid")
	}

	jti, _ := claims["jti"].(string)
	if strings.TrimSpace(jti) == "" {
		return nil, errors.New("dpop: jti claim is required")
	}

	htm, _ := claims["htm"].(string)
	expectedMethod := strings.ToUpper(strings.TrimSpace(opts.Method))
	if htm != expectedMethod {
		return nil, fmt.Errorf("dpop: htm %q does not match request method %q", htm, expectedMethod)
	}

	htu, _ := claims["htu"].(string)
	normalizedProofHTU, err := NormalizeHTU(htu)
	if err != nil {
		return nil, fmt.Errorf("dpop: htu claim is invalid: %w", err)
	}
	normalizedRequestURI, err := NormalizeHTU(opts.URI)
	if err != nil {
		return nil, fmt.Errorf("dpop: request uri is invalid: %w", err)
	}
	if normalizedProofHTU != normalizedRequestURI {
		return nil, fmt.Errorf("dpop: htu %q does not match the request URI", htu)
	}

	iatUnix, err := numericDateToInt64(claims["iat"])
	if err != nil {
		return nil, errors.New("dpop: iat claim is required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	iat := time.Unix(iatUnix, 0).UTC()
	if iat.Before(now.Add(-IatFreshnessWindow)) || iat.After(now.Add(IatFreshnessWindow)) {
		return nil, fmt.Errorf("dpop: iat is outside the %s freshness window", IatFreshnessWindow)
	}

	if opts.AccessToken != "" {
		ath, _ := claims["ath"].(string)
		if !constantTimeEqual(ath, computeATH(opts.AccessToken)) {
			return nil, errors.New("dpop: ath does not match the presented access token")
		}
	}

	nonce, _ := claims["nonce"].(string)
	if opts.RequiredNonce != "" && !constantTimeEqual(nonce, opts.RequiredNonce) {
		return nil, errors.New("dpop: nonce does not match the required server nonce")
	}

	jkt := jwk.Thumbprint()
	if jkt == "" {
		return nil, errors.New("dpop: unable to compute a thumbprint for the jwk header")
	}

	return &Proof{JTI: jti, JKT: jkt, JWK: jwk, IAT: iat, Nonce: nonce}, nil
}

// NonceRequiredError signals that a proof was otherwise fully valid but did
// not carry the nonce value currently in force at this endpoint (RFC 9449
// Section 8). It is distinct from a plain validation failure because the
// caller must respond with the use_dpop_nonce error code and a DPoP-Nonce
// response header carrying Nonce, not a bare invalid_dpop_proof/invalid_token
// rejection -- the client is expected to retry with a fresh proof that
// echoes this value in its nonce claim, not to treat this as a hard error.
type NonceRequiredError struct {
	// Nonce is the freshly issued value the caller must surface to the
	// client via a DPoP-Nonce response header.
	Nonce string
}

func (e *NonceRequiredError) Error() string {
	return "dpop: a fresh server-provided nonce is required"
}

// NormalizeHTU normalizes a URI for the RFC 9449 Section 4.3 step 9 htu
// comparison: scheme and host lowercased, default port elided, query and
// fragment removed. Both the proof's htu claim and the server's own
// request URI must be passed through this before comparison.
func NormalizeHTU(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("uri is empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("uri must be absolute")
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	defaultPorts := map[string]string{"http": "80", "https": "443"}
	authority := host
	if port != "" && port != defaultPorts[scheme] {
		authority = host + ":" + port
	}
	return scheme + "://" + authority + parsed.EscapedPath(), nil
}

// algMatchesKeyType rejects an algorithm/key-type mismatch (the same
// algorithm-confusion defence already applied to client assertions in
// internal/protocols/oauth2/clientauth_jwt.go): RS256 requires an RSA key,
// ES256 requires an EC P-256 key, EdDSA requires an OKP Ed25519 key.
func algMatchesKeyType(alg string, jwk internalcrypto.JWK) error {
	switch alg {
	case "RS256":
		if jwk.Kty != "RSA" {
			return fmt.Errorf("dpop: alg %q requires an RSA key, got %q", alg, jwk.Kty)
		}
	case "ES256":
		if jwk.Kty != "EC" || jwk.Crv != "P-256" {
			return fmt.Errorf("dpop: alg %q requires an EC P-256 key", alg)
		}
	case "EdDSA":
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			return fmt.Errorf("dpop: alg %q requires an OKP Ed25519 key", alg)
		}
	default:
		return fmt.Errorf("dpop: alg %q is not permitted", alg)
	}
	return nil
}

func parseHeaderJWK(raw interface{}) (internalcrypto.JWK, error) {
	jwkBytes, err := json.Marshal(raw)
	if err != nil {
		return internalcrypto.JWK{}, fmt.Errorf("jwk is invalid JSON: %w", err)
	}
	var jwk internalcrypto.JWK
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return internalcrypto.JWK{}, fmt.Errorf("jwk parse failed: %w", err)
	}
	if strings.TrimSpace(jwk.Kty) == "" {
		return internalcrypto.JWK{}, errors.New("jwk kty is required")
	}
	return jwk, nil
}

// computeATH computes the RFC 9449 Section 4.2 "ath" value:
// base64url(SHA-256(access token)).
func computeATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func numericDateToInt64(raw interface{}) (int64, error) {
	switch value := raw.(type) {
	case float64:
		return int64(value), nil
	case json.Number:
		return value.Int64()
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	default:
		return 0, fmt.Errorf("unsupported numeric date type %T", raw)
	}
}
