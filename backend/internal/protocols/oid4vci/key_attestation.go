package oid4vci

import (
	"fmt"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// typKeyAttestationJWT is the required typ header value for an OID4VCI 1.0
// Appendix D.1 Key Attestation JWT ("MUST be key-attestation+jwt").
const typKeyAttestationJWT = "key-attestation+jwt"

// keyAttestation is the validated content of a Key Attestation JWT (OID4VCI
// 1.0 Appendix D.1), carried in the jwt proof's key_attestation JOSE header
// (Appendix F.1) for credential configurations that set
// key_attestations_required (registry.go).
type keyAttestation struct {
	AttestedKeys       []crypto.JWK
	KeyStorage         []string
	UserAuthentication []string
}

// initKeyAttestationTrust loads the CA trust anchor used to validate the x5c
// chain on incoming Key Attestation JWTs. Unset by default:
// OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM opts the issuer into requiring/
// accepting key attestations.
func (p *Plugin) initKeyAttestationTrust() error {
	pool, err := loadTrustAnchorPool("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM")
	if err != nil {
		return err
	}
	p.keyAttestationTrustAnchors = pool
	return nil
}

// validateKeyAttestationJWT validates a raw Key Attestation JWT (OID4VCI 1.0
// Appendix D.1): typ, an x5c chain anchored to roots, signature, iat, exp (if
// present), and attested_keys. When expectedNonce is non-empty and the
// attestation carries a nonce claim, it must match -- OID4VCI 1.0 Appendix
// F.1 / the WG errata clarify the c_nonce match is only enforced when the
// claim is present, since pre-generated attestations may omit it.
func (p *Plugin) validateKeyAttestationJWT(compact string, expectedNonce string) (*keyAttestation, error) {
	if p.keyAttestationTrustAnchors == nil {
		return nil, fmt.Errorf("issuer does not trust any key attestation issuer (OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM is not configured)")
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(compact)
	if err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}
	if typ, _ := decoded.Header["typ"].(string); typ != typKeyAttestationJWT {
		return nil, fmt.Errorf("typ header must be %q", typKeyAttestationJWT)
	}
	x5cRaw, ok := decoded.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("x5c header is required to establish the key storage component's trust chain")
	}
	chain, err := crypto.ParseX5CCertificateChain(x5cRaw)
	if err != nil {
		return nil, err
	}
	leaf, err := validateChainAgainstRoots(chain, p.keyAttestationTrustAnchors, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("key attestation trust chain: %w", err)
	}

	parsed, err := jwt.Parse(compact, func(token *jwt.Token) (interface{}, error) {
		return leaf.PublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("signature validation failed: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("signature validation failed")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("claims are invalid")
	}
	if _, err := numericDateToInt64(claims["iat"]); err != nil {
		return nil, fmt.Errorf("iat claim is required")
	}
	if expRaw, exists := claims["exp"]; exists {
		expUnix, err := numericDateToInt64(expRaw)
		if err != nil {
			return nil, fmt.Errorf("exp claim is invalid")
		}
		if time.Now().UTC().Unix() >= expUnix {
			return nil, fmt.Errorf("key attestation is expired")
		}
	}
	attestedKeysRaw, ok := claims["attested_keys"].([]interface{})
	if !ok || len(attestedKeysRaw) == 0 {
		return nil, fmt.Errorf("attested_keys claim is required and must be non-empty")
	}
	attestedKeys := make([]crypto.JWK, 0, len(attestedKeysRaw))
	for idx, raw := range attestedKeysRaw {
		jwkValue, err := parseProofJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("attested_keys[%d]: %w", idx, err)
		}
		attestedKeys = append(attestedKeys, jwkValue)
	}
	if nonceValue, exists := claims["nonce"].(string); exists && strings.TrimSpace(nonceValue) != "" {
		if strings.TrimSpace(expectedNonce) == "" || nonceValue != expectedNonce {
			return nil, fmt.Errorf("nonce claim does not match the active c_nonce")
		}
	}
	return &keyAttestation{
		AttestedKeys:       attestedKeys,
		KeyStorage:         stringSliceClaim(claims["key_storage"]),
		UserAuthentication: stringSliceClaim(claims["user_authentication"]),
	}, nil
}

func stringSliceClaim(raw interface{}) []string {
	values, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// keyAttestationSatisfiesRequirement checks that at least one attested key
// matches the proof's cnf.jwk holder key and that any issuer-required
// key_storage / user_authentication attack-potential levels are present
// (OID4VCI 1.0 Appendix D.1/D.2; key_attestations_required in registry.go).
func keyAttestationSatisfiesRequirement(attestation *keyAttestation, holderJWK crypto.JWK, requiredKeyStorage []string, requiredUserAuth []string) error {
	if attestation == nil {
		return fmt.Errorf("key_attestation is required for this credential configuration")
	}
	holderThumbprint := holderJWK.Thumbprint()
	matched := false
	for _, attestedKey := range attestation.AttestedKeys {
		if holderThumbprint != "" && attestedKey.Thumbprint() == holderThumbprint {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("proof key is not among the key attestation's attested_keys")
	}
	if len(requiredKeyStorage) > 0 && !anyStringMatches(attestation.KeyStorage, requiredKeyStorage) {
		return fmt.Errorf("key attestation key_storage does not satisfy the required level")
	}
	if len(requiredUserAuth) > 0 && !anyStringMatches(attestation.UserAuthentication, requiredUserAuth) {
		return fmt.Errorf("key attestation user_authentication does not satisfy the required level")
	}
	return nil
}

func anyStringMatches(have []string, want []string) bool {
	for _, wantValue := range want {
		for _, haveValue := range have {
			if strings.EqualFold(wantValue, haveValue) {
				return true
			}
		}
	}
	return false
}
