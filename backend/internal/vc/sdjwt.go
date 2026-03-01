package vc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SDJWTEnvelope is the parsed structure for an SD-JWT VC serialization.
type SDJWTEnvelope struct {
	IssuerSignedJWT string   `json:"issuer_signed_jwt"`
	Disclosures     []string `json:"disclosures,omitempty"`
	KeyBindingJWT   string   `json:"key_binding_jwt,omitempty"`
}

// SDJWTDisclosure is a decoded SD-JWT disclosure tuple.
type SDJWTDisclosure struct {
	Salt      string      `json:"salt"`
	ClaimName string      `json:"claim_name"`
	ClaimValue interface{} `json:"claim_value"`
	Encoded   string      `json:"encoded"`
	Digest    string      `json:"digest"`
}

// ParseSDJWTEnvelope parses "~" separated SD-JWT serialization into structured parts.
func ParseSDJWTEnvelope(raw string) (*SDJWTEnvelope, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("sd-jwt value is required")
	}

	parts := strings.Split(trimmed, "~")
	issuerSignedJWT := strings.TrimSpace(parts[0])
	if issuerSignedJWT == "" {
		return nil, fmt.Errorf("issuer-signed JWT segment is required")
	}

	envelope := &SDJWTEnvelope{
		IssuerSignedJWT: issuerSignedJWT,
	}

	for idx := 1; idx < len(parts); idx++ {
		segment := strings.TrimSpace(parts[idx])
		if segment == "" {
			continue
		}

		if idx == len(parts)-1 && isJWTLike(segment) {
			envelope.KeyBindingJWT = segment
			continue
		}
		envelope.Disclosures = append(envelope.Disclosures, segment)
	}

	return envelope, nil
}

// HasKeyBindingJWT indicates whether the envelope includes a holder-binding JWT.
func (e *SDJWTEnvelope) HasKeyBindingJWT() bool {
	if e == nil {
		return false
	}
	return strings.TrimSpace(e.KeyBindingJWT) != ""
}

// BuildSDJWTSerialization joins issuer-signed JWT and optional disclosures into compact SD-JWT form.
func BuildSDJWTSerialization(issuerSignedJWT string, disclosures []string, keyBindingJWT string) string {
	parts := make([]string, 0, len(disclosures)+2)
	head := strings.TrimSpace(issuerSignedJWT)
	if head != "" {
		parts = append(parts, head)
	}
	for _, disclosure := range disclosures {
		normalized := strings.TrimSpace(disclosure)
		if normalized == "" {
			continue
		}
		parts = append(parts, normalized)
	}
	kb := strings.TrimSpace(keyBindingJWT)
	if kb != "" {
		parts = append(parts, kb)
	}
	return strings.Join(parts, "~")
}

// CreateSDJWTDisclosure builds a disclosure tuple and digest for a claim.
func CreateSDJWTDisclosure(claimName string, claimValue interface{}, salt string) (*SDJWTDisclosure, error) {
	normalizedClaim := strings.TrimSpace(claimName)
	if normalizedClaim == "" {
		return nil, fmt.Errorf("disclosure claim_name is required")
	}
	normalizedSalt := strings.TrimSpace(salt)
	if normalizedSalt == "" {
		var err error
		normalizedSalt, err = randomDisclosureSalt()
		if err != nil {
			return nil, err
		}
	}
	payload := []interface{}{normalizedSalt, normalizedClaim, claimValue}
	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal disclosure payload: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(serialized)
	return &SDJWTDisclosure{
		Salt:       normalizedSalt,
		ClaimName:  normalizedClaim,
		ClaimValue: claimValue,
		Encoded:    encoded,
		Digest:     SDJWTDisclosureDigest(encoded),
	}, nil
}

// DecodeSDJWTDisclosure decodes one disclosure and computes its digest.
func DecodeSDJWTDisclosure(encoded string) (*SDJWTDisclosure, error) {
	normalized := strings.TrimSpace(encoded)
	if normalized == "" {
		return nil, fmt.Errorf("disclosure value is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("decode disclosure base64url: %w", err)
	}
	var parts []interface{}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("parse disclosure JSON: %w", err)
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("disclosure must contain [salt, claim_name, claim_value]")
	}
	salt, _ := parts[0].(string)
	claimName, _ := parts[1].(string)
	salt = strings.TrimSpace(salt)
	claimName = strings.TrimSpace(claimName)
	if salt == "" || claimName == "" {
		return nil, fmt.Errorf("disclosure salt and claim_name are required")
	}
	return &SDJWTDisclosure{
		Salt:       salt,
		ClaimName:  claimName,
		ClaimValue: parts[2],
		Encoded:    normalized,
		Digest:     SDJWTDisclosureDigest(normalized),
	}, nil
}

// SDJWTDisclosureDigest computes the SHA-256 base64url disclosure digest.
func SDJWTDisclosureDigest(encodedDisclosure string) string {
	normalized := strings.TrimSpace(encodedDisclosure)
	sum := sha256.Sum256([]byte(normalized))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DecodeAndVerifyDisclosures decodes disclosures and validates they match issuer digest commitments.
func DecodeAndVerifyDisclosures(disclosures []string, digestAllowList []string) ([]SDJWTDisclosure, error) {
	allowed := make(map[string]struct{}, len(digestAllowList))
	for _, digest := range digestAllowList {
		normalized := strings.TrimSpace(digest)
		if normalized == "" {
			continue
		}
		allowed[normalized] = struct{}{}
	}
	seenClaims := make(map[string]struct{}, len(disclosures))
	decoded := make([]SDJWTDisclosure, 0, len(disclosures))
	for _, rawDisclosure := range disclosures {
		disclosure, err := DecodeSDJWTDisclosure(rawDisclosure)
		if err != nil {
			return nil, err
		}
		if len(allowed) > 0 {
			if _, ok := allowed[disclosure.Digest]; !ok {
				return nil, fmt.Errorf("disclosure digest for claim %q is not committed in issuer payload", disclosure.ClaimName)
			}
		}
		claimName := strings.TrimSpace(disclosure.ClaimName)
		if _, exists := seenClaims[claimName]; exists {
			return nil, fmt.Errorf("duplicate disclosure for claim %q", claimName)
		}
		seenClaims[claimName] = struct{}{}
		decoded = append(decoded, *disclosure)
	}
	return decoded, nil
}

// DisclosedClaimMap converts decoded disclosures to claim-name map.
func DisclosedClaimMap(disclosures []SDJWTDisclosure) map[string]interface{} {
	claims := make(map[string]interface{}, len(disclosures))
	for _, disclosure := range disclosures {
		claimName := strings.TrimSpace(disclosure.ClaimName)
		if claimName == "" {
			continue
		}
		claims[claimName] = disclosure.ClaimValue
	}
	return claims
}

func randomDisclosureSalt() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate disclosure salt: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func isJWTLike(value string) bool {
	return strings.Count(value, ".") == 2
}
