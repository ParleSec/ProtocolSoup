package oid4vci

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// OAuth 2.0 Attestation-Based Client Authentication
// (draft-ietf-oauth-attestation-based-client-auth-09) header names and JOSE
// "typ" values. HAIP requires attestation-based client authentication.
const (
	headerClientAttestation    = "OAuth-Client-Attestation"
	headerClientAttestationPoP = "OAuth-Client-Attestation-PoP"

	typClientAttestationJWT    = "oauth-client-attestation+jwt"
	typClientAttestationPoPJWT = "oauth-client-attestation-pop+jwt"

	// clientAttestationPoPSkew bounds how far from "now" a Client Attestation
	// PoP JWT's iat may be (draft-09 §7.2: the receiving server "may reject
	// JWTs with an iat claim value that is unreasonably far in the past");
	// applied symmetrically since clocks can also run fast.
	clientAttestationPoPSkew = 5 * time.Minute
)

// clientAttestationAuth is the authenticated result of validating an OAuth
// 2.0 Attestation-Based Client Authentication pair at the token endpoint.
type clientAttestationAuth struct {
	// ClientID is the sub claim of the Client Attestation JWT (draft-09 §4.2:
	// "sub: REQUIRED. ... MUST specify client_id value of the OAuth Client").
	ClientID string
}

// initClientAttestationTrust loads the CA trust anchor used to validate the
// x5c chain on incoming Client Attestation JWTs. Unset by default:
// OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM opts the issuer into accepting
// attestation-based client authentication, matching the "no trust anchor
// configured, no acceptance" discipline already used for the mso_mdoc IACA
// root -- a client attestation is never accepted on good faith.
func (p *Plugin) initClientAttestationTrust() error {
	pool, err := loadTrustAnchorPool("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM")
	if err != nil {
		return err
	}
	p.clientAttestationTrustAnchors = pool
	return nil
}

// authenticateClientAttestation validates an OAuth-Client-Attestation +
// OAuth-Client-Attestation-PoP header pair on a token request, per
// draft-ietf-oauth-attestation-based-client-auth-09 §§4-7. attempted reports
// whether the request presented (or partially presented) attestation headers
// at all: when true, the caller MUST use (auth, err) as the authentication
// verdict and must not fall back to legacy client_secret / public-client
// authentication, even on error -- silently downgrading a failed attestation
// to a weaker method would defeat the mechanism.
func (p *Plugin) authenticateClientAttestation(r *http.Request) (auth clientAttestationAuth, attempted bool, err error) {
	attestationRaw := strings.TrimSpace(r.Header.Get(headerClientAttestation))
	popRaw := strings.TrimSpace(r.Header.Get(headerClientAttestationPoP))
	if attestationRaw == "" && popRaw == "" {
		return clientAttestationAuth{}, false, nil
	}
	if attestationRaw == "" || popRaw == "" {
		return clientAttestationAuth{}, true, fmt.Errorf("both %s and %s headers are required", headerClientAttestation, headerClientAttestationPoP)
	}
	if p.clientAttestationTrustAnchors == nil {
		return clientAttestationAuth{}, true, fmt.Errorf("issuer does not trust any client attestation issuer (OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM is not configured)")
	}

	clientID, cnfJWK, err := validateClientAttestationJWT(attestationRaw, p.clientAttestationTrustAnchors)
	if err != nil {
		return clientAttestationAuth{}, true, fmt.Errorf("client attestation: %w", err)
	}
	jti, err := validateClientAttestationPoPJWT(popRaw, cnfJWK, p.issuerID())
	if err != nil {
		return clientAttestationAuth{}, true, fmt.Errorf("client attestation pop: %w", err)
	}
	if !p.recordAttestationPoPJTI(jti) {
		return clientAttestationAuth{}, true, fmt.Errorf("client attestation pop: jti has already been used (replay)")
	}
	return clientAttestationAuth{ClientID: clientID}, true, nil
}

// validateClientAttestationJWT validates the Client Attestation JWT (draft-09
// §4.2): typ, an x5c chain anchored to roots, signature, sub, exp, and
// cnf.jwk. It returns the authenticated client_id and the Client Instance Key
// the caller must use to verify the accompanying PoP JWT.
func validateClientAttestationJWT(compact string, roots *x509.CertPool) (string, crypto.JWK, error) {
	emptyJWK := crypto.JWK{}
	decoded, err := crypto.DecodeTokenWithoutValidation(compact)
	if err != nil {
		return "", emptyJWK, fmt.Errorf("decode failed: %w", err)
	}
	if typ, _ := decoded.Header["typ"].(string); typ != typClientAttestationJWT {
		return "", emptyJWK, fmt.Errorf("typ header must be %q", typClientAttestationJWT)
	}
	x5cRaw, ok := decoded.Header["x5c"]
	if !ok {
		return "", emptyJWK, fmt.Errorf("x5c header is required to establish the attester's trust chain")
	}
	chain, err := crypto.ParseX5CCertificateChain(x5cRaw)
	if err != nil {
		return "", emptyJWK, err
	}
	leaf, err := validateChainAgainstRoots(chain, roots, time.Now().UTC())
	if err != nil {
		return "", emptyJWK, fmt.Errorf("attester trust chain: %w", err)
	}

	parsed, err := jwt.Parse(compact, func(token *jwt.Token) (interface{}, error) {
		return leaf.PublicKey, nil
	})
	if err != nil {
		return "", emptyJWK, fmt.Errorf("signature validation failed: %w", err)
	}
	if !parsed.Valid {
		return "", emptyJWK, fmt.Errorf("signature validation failed")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", emptyJWK, fmt.Errorf("claims are invalid")
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return "", emptyJWK, fmt.Errorf("sub (client_id) claim is required")
	}
	expUnix, err := numericDateToInt64(claims["exp"])
	if err != nil {
		return "", emptyJWK, fmt.Errorf("exp claim is required")
	}
	if time.Now().UTC().Unix() >= expUnix {
		return "", emptyJWK, fmt.Errorf("attestation is expired")
	}
	cnfMap, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return "", emptyJWK, fmt.Errorf("cnf claim is required")
	}
	jwkRaw, exists := cnfMap["jwk"]
	if !exists {
		return "", emptyJWK, fmt.Errorf("cnf.jwk claim is required")
	}
	cnfJWK, err := parseProofJWK(jwkRaw)
	if err != nil {
		return "", emptyJWK, fmt.Errorf("cnf.jwk: %w", err)
	}
	return strings.TrimSpace(sub), cnfJWK, nil
}

// validateClientAttestationPoPJWT validates the Client Attestation PoP JWT
// (draft-09 §5.1): typ, signature against the Client Instance Key from the
// attestation's cnf.jwk, aud (must equal this AS's issuer identifier per
// RFC 8414), and iat freshness. It returns jti for replay detection. Per the
// draft-09 changelog, neither exp nor iss is present on this JWT.
func validateClientAttestationPoPJWT(compact string, cnfJWK crypto.JWK, expectedAudience string) (string, error) {
	decoded, err := crypto.DecodeTokenWithoutValidation(compact)
	if err != nil {
		return "", fmt.Errorf("decode failed: %w", err)
	}
	if typ, _ := decoded.Header["typ"].(string); typ != typClientAttestationPoPJWT {
		return "", fmt.Errorf("typ header must be %q", typClientAttestationPoPJWT)
	}
	verificationKey, expectedAlgPrefix, err := verificationKeyFromJWK(cnfJWK)
	if err != nil {
		return "", fmt.Errorf("client instance key: %w", err)
	}
	parsed, err := jwt.Parse(compact, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), expectedAlgPrefix) {
			return nil, fmt.Errorf("pop jwt uses unexpected algorithm")
		}
		return verificationKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("signature validation failed: %w", err)
	}
	if !parsed.Valid {
		return "", fmt.Errorf("signature validation failed")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("claims are invalid")
	}
	aud, _ := claims["aud"].(string)
	if strings.TrimSpace(aud) != strings.TrimSpace(expectedAudience) {
		return "", fmt.Errorf("aud must equal the authorization server issuer identifier %q", expectedAudience)
	}
	jtiValue, _ := claims["jti"].(string)
	if strings.TrimSpace(jtiValue) == "" {
		return "", fmt.Errorf("jti claim is required")
	}
	iatUnix, err := numericDateToInt64(claims["iat"])
	if err != nil {
		return "", fmt.Errorf("iat claim is required")
	}
	now := time.Now().UTC().Unix()
	skewSeconds := int64(clientAttestationPoPSkew.Seconds())
	if iatUnix < now-skewSeconds || iatUnix > now+skewSeconds {
		return "", fmt.Errorf("iat is outside the acceptable window")
	}
	return jtiValue, nil
}

// recordAttestationPoPJTI enforces single-use of a Client Attestation PoP jti
// (draft-09 §11.1). It returns false when the jti has already been witnessed
// within its validity window.
func (p *Plugin) recordAttestationPoPJTI(jti string) bool {
	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.usedAttestationPoPJTIs == nil {
		p.usedAttestationPoPJTIs = make(map[string]time.Time)
	}
	if expiry, seen := p.usedAttestationPoPJTIs[jti]; seen && now.Before(expiry) {
		return false
	}
	p.usedAttestationPoPJTIs[jti] = now.Add(clientAttestationPoPSkew * 2)
	return true
}

// verificationKeyFromJWK resolves a bare JWK (no cnf wrapper) to a
// crypto/*.PublicKey and the JWT algorithm family prefix expected to sign
// with it. Shared by the Client Attestation PoP (cnf.jwk) and, via
// proofVerificationKeyFromClaims, the OID4VCI proof JWT (also cnf.jwk).
func verificationKeyFromJWK(jwk crypto.JWK) (interface{}, string, error) {
	switch strings.ToUpper(strings.TrimSpace(jwk.Kty)) {
	case "RSA":
		key, err := crypto.ParseRSAPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, "", fmt.Errorf("RSA parse failed: %w", err)
		}
		return key, "RS", nil
	case "EC":
		key, err := crypto.ParseECPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, "", fmt.Errorf("EC parse failed: %w", err)
		}
		return key, "ES", nil
	default:
		return nil, "", fmt.Errorf("unsupported kty %q", jwk.Kty)
	}
}
