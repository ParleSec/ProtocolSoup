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
	Salt           string      `json:"salt"`
	ClaimName      string      `json:"claim_name,omitempty"`
	ClaimValue     interface{} `json:"claim_value"`
	IsArrayElement bool        `json:"is_array_element,omitempty"`
	Encoded        string      `json:"encoded"`
	Digest         string      `json:"digest"`
}

// ParseSDJWTEnvelope parses "~" separated SD-JWT serialization into structured parts.
func ParseSDJWTEnvelope(raw string) (*SDJWTEnvelope, error) {
	if raw == "" {
		return nil, fmt.Errorf("sd-jwt value is required")
	}
	if raw != strings.TrimSpace(raw) {
		return nil, fmt.Errorf("sd-jwt compact serialization must not contain surrounding whitespace")
	}
	if !strings.Contains(raw, "~") {
		return nil, fmt.Errorf("sd-jwt compact serialization must contain a tilde separator")
	}

	parts := strings.Split(raw, "~")
	issuerSignedJWT := parts[0]
	if issuerSignedJWT == "" {
		return nil, fmt.Errorf("issuer-signed JWT segment is required")
	}

	envelope := &SDJWTEnvelope{
		IssuerSignedJWT: issuerSignedJWT,
	}

	for idx := 1; idx < len(parts); idx++ {
		segment := parts[idx]
		if segment == "" {
			if idx != len(parts)-1 {
				return nil, fmt.Errorf("sd-jwt compact serialization contains an empty disclosure segment")
			}
			continue
		}
		if segment != strings.TrimSpace(segment) {
			return nil, fmt.Errorf("sd-jwt compact serialization segments must not contain surrounding whitespace")
		}

		if idx == len(parts)-1 && isJWTLike(segment) {
			envelope.KeyBindingJWT = segment
			continue
		}
		if idx == len(parts)-1 {
			return nil, fmt.Errorf("sd-jwt compact serialization without a key binding jwt must end with a tilde")
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
	serialized := strings.Join(parts, "~")
	if serialized != "" && kb == "" {
		serialized += "~"
	}
	return serialized
}

// CreateSDJWTDisclosure builds a disclosure tuple and digest for a claim.
func CreateSDJWTDisclosure(claimName string, claimValue interface{}, salt string) (*SDJWTDisclosure, error) {
	normalizedClaim := strings.TrimSpace(claimName)
	if normalizedClaim == "" {
		return nil, fmt.Errorf("disclosure claim_name is required")
	}
	if normalizedClaim == "_sd" || normalizedClaim == "..." {
		return nil, fmt.Errorf("disclosure claim_name %q is reserved", normalizedClaim)
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

// CreateSDJWTArrayDisclosure builds the RFC 9901 Section 4.2.2 two-element
// Disclosure used for a selectively disclosable array element.
func CreateSDJWTArrayDisclosure(claimValue interface{}, salt string) (*SDJWTDisclosure, error) {
	normalizedSalt := strings.TrimSpace(salt)
	if normalizedSalt == "" {
		var err error
		normalizedSalt, err = randomDisclosureSalt()
		if err != nil {
			return nil, err
		}
	}
	payload := []interface{}{normalizedSalt, claimValue}
	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal array disclosure payload: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(serialized)
	return &SDJWTDisclosure{
		Salt:           normalizedSalt,
		ClaimValue:     claimValue,
		IsArrayElement: true,
		Encoded:        encoded,
		Digest:         SDJWTDisclosureDigest(encoded),
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
	if len(parts) != 2 && len(parts) != 3 {
		return nil, fmt.Errorf("disclosure must contain [salt, claim_name, claim_value] or [salt, array_element]")
	}
	salt, _ := parts[0].(string)
	salt = strings.TrimSpace(salt)
	if salt == "" {
		return nil, fmt.Errorf("disclosure salt is required")
	}
	disclosure := &SDJWTDisclosure{
		Salt:           salt,
		IsArrayElement: len(parts) == 2,
		Encoded:        normalized,
		Digest:         SDJWTDisclosureDigest(normalized),
	}
	if len(parts) == 2 {
		disclosure.ClaimValue = parts[1]
		return disclosure, nil
	}
	claimName, _ := parts[1].(string)
	claimName = strings.TrimSpace(claimName)
	if claimName == "" {
		return nil, fmt.Errorf("disclosure claim_name is required")
	}
	if claimName == "_sd" || claimName == "..." {
		return nil, fmt.Errorf("disclosure claim_name %q is reserved", claimName)
	}
	disclosure.ClaimName = claimName
	disclosure.ClaimValue = parts[2]
	return disclosure, nil
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
	if len(disclosures) > 0 && len(allowed) == 0 {
		return nil, fmt.Errorf("issuer payload contains no digest commitment for presented disclosures")
	}
	seenDigests := make(map[string]struct{}, len(disclosures))
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
		if _, exists := seenDigests[disclosure.Digest]; exists {
			return nil, fmt.Errorf("duplicate disclosure digest %q", disclosure.Digest)
		}
		seenDigests[disclosure.Digest] = struct{}{}
		decoded = append(decoded, *disclosure)
	}
	return decoded, nil
}

// SDJWTDisclosureDigests extracts object-property and array-element
// commitments recursively while validating the RFC 9901 reserved structures.
func SDJWTDisclosureDigests(payload map[string]interface{}) ([]string, error) {
	if _, err := sdJWTHashAlgorithm(payload); err != nil {
		return nil, err
	}

	digests := make([]string, 0)
	seen := make(map[string]struct{})
	addDigest := func(raw interface{}) error {
		digest, ok := raw.(string)
		if !ok || strings.TrimSpace(digest) == "" || digest != strings.TrimSpace(digest) {
			return fmt.Errorf("sd-jwt digest commitments must be non-empty strings")
		}
		if _, duplicate := seen[digest]; duplicate {
			return fmt.Errorf("duplicate sd-jwt digest %q", digest)
		}
		seen[digest] = struct{}{}
		digests = append(digests, digest)
		return nil
	}
	var walk func(interface{}, int) error
	walk = func(value interface{}, depth int) error {
		switch typed := value.(type) {
		case map[string]interface{}:
			if depth > 0 {
				if _, exists := typed["_sd_alg"]; exists {
					return fmt.Errorf("_sd_alg must appear only at the top level of the sd-jwt payload")
				}
			}
			if _, exists := typed["..."]; exists {
				return fmt.Errorf("reserved claim \"...\" is only valid as a single-key array digest marker")
			}
			for key, nested := range typed {
				if key == "_sd_alg" {
					continue
				}
				if key == "_sd" {
					rawDigests, ok := nested.([]interface{})
					if !ok {
						return fmt.Errorf("_sd must be an array of digest strings")
					}
					for _, rawDigest := range rawDigests {
						if err := addDigest(rawDigest); err != nil {
							return err
						}
					}
					continue
				}
				if err := walk(nested, depth+1); err != nil {
					return err
				}
			}
		case []interface{}:
			for _, nested := range typed {
				if marker, ok := nested.(map[string]interface{}); ok {
					if digest, exists := marker["..."]; exists {
						if len(marker) != 1 {
							return fmt.Errorf("array digest marker must contain only the \"...\" key")
						}
						if err := addDigest(digest); err != nil {
							return err
						}
						continue
					}
				}
				if err := walk(nested, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(payload, 0); err != nil {
		return nil, err
	}
	return digests, nil
}

// ProcessSDJWTDisclosures applies RFC 9901 Section 7.1 at the exact object or
// array position of each digest and returns the Processed SD-JWT Payload.
// Issuer-signature verification intentionally remains the caller's separate,
// mandatory responsibility.
func ProcessSDJWTDisclosures(payload map[string]interface{}, disclosures []string) (map[string]interface{}, []SDJWTDisclosure, error) {
	if _, err := sdJWTHashAlgorithm(payload); err != nil {
		return nil, nil, err
	}

	byDigest := make(map[string]SDJWTDisclosure, len(disclosures))
	decoded := make([]SDJWTDisclosure, 0, len(disclosures))
	for _, encoded := range disclosures {
		disclosure, err := DecodeSDJWTDisclosure(encoded)
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := byDigest[disclosure.Digest]; duplicate {
			return nil, nil, fmt.Errorf("duplicate disclosure digest %q", disclosure.Digest)
		}
		byDigest[disclosure.Digest] = *disclosure
		decoded = append(decoded, *disclosure)
	}

	encounteredDigests := make(map[string]struct{})
	usedDisclosures := make(map[string]struct{})
	var process func(interface{}, int) (interface{}, error)
	process = func(value interface{}, depth int) (interface{}, error) {
		switch typed := value.(type) {
		case map[string]interface{}:
			if depth > 0 {
				if _, exists := typed["_sd_alg"]; exists {
					return nil, fmt.Errorf("_sd_alg must appear only at the top level of the sd-jwt payload")
				}
			}
			if _, exists := typed["..."]; exists {
				return nil, fmt.Errorf("reserved claim \"...\" is only valid as a single-key array digest marker")
			}
			result := make(map[string]interface{}, len(typed))
			for key, nested := range typed {
				if key == "_sd" || key == "_sd_alg" {
					continue
				}
				processed, err := process(nested, depth+1)
				if err != nil {
					return nil, err
				}
				result[key] = processed
			}
			if rawSD, exists := typed["_sd"]; exists {
				digests, ok := rawSD.([]interface{})
				if !ok {
					return nil, fmt.Errorf("_sd must be an array of digest strings")
				}
				for _, rawDigest := range digests {
					digest, ok := rawDigest.(string)
					if !ok || strings.TrimSpace(digest) == "" || digest != strings.TrimSpace(digest) {
						return nil, fmt.Errorf("_sd must contain only non-empty digest strings")
					}
					if _, duplicate := encounteredDigests[digest]; duplicate {
						return nil, fmt.Errorf("duplicate sd-jwt digest %q", digest)
					}
					encounteredDigests[digest] = struct{}{}
					disclosure, presented := byDigest[digest]
					if !presented {
						continue
					}
					if disclosure.IsArrayElement {
						return nil, fmt.Errorf("array-element disclosure used for object-property digest")
					}
					if _, collision := result[disclosure.ClaimName]; collision {
						return nil, fmt.Errorf("disclosed claim %q collides with a permanently disclosed claim", disclosure.ClaimName)
					}
					if depth == 0 && isSDJWTVCAlwaysDisclosedClaim(disclosure.ClaimName) {
						return nil, fmt.Errorf("sd-jwt vc claim %q must not be selectively disclosed", disclosure.ClaimName)
					}
					processed, err := process(disclosure.ClaimValue, depth+1)
					if err != nil {
						return nil, err
					}
					result[disclosure.ClaimName] = processed
					usedDisclosures[digest] = struct{}{}
				}
			}
			return result, nil
		case []interface{}:
			result := make([]interface{}, 0, len(typed))
			for _, nested := range typed {
				if marker, ok := nested.(map[string]interface{}); ok {
					if rawDigest, exists := marker["..."]; exists {
						if len(marker) != 1 {
							return nil, fmt.Errorf("array digest marker must contain only the \"...\" key")
						}
						digest, ok := rawDigest.(string)
						if !ok || strings.TrimSpace(digest) == "" || digest != strings.TrimSpace(digest) {
							return nil, fmt.Errorf("array digest marker must contain a non-empty digest string")
						}
						if _, duplicate := encounteredDigests[digest]; duplicate {
							return nil, fmt.Errorf("duplicate sd-jwt digest %q", digest)
						}
						encounteredDigests[digest] = struct{}{}
						disclosure, presented := byDigest[digest]
						if !presented {
							continue
						}
						if !disclosure.IsArrayElement {
							return nil, fmt.Errorf("object-property disclosure used for array-element digest")
						}
						processed, err := process(disclosure.ClaimValue, depth+1)
						if err != nil {
							return nil, err
						}
						result = append(result, processed)
						usedDisclosures[digest] = struct{}{}
						continue
					}
				}
				processed, err := process(nested, depth+1)
				if err != nil {
					return nil, err
				}
				result = append(result, processed)
			}
			return result, nil
		default:
			return typed, nil
		}
	}

	processed, err := process(payload, 0)
	if err != nil {
		return nil, nil, err
	}
	for digest, disclosure := range byDigest {
		if _, used := usedDisclosures[digest]; !used {
			return nil, nil, fmt.Errorf("disclosure digest for claim %q is not referenced by the issuer payload", disclosure.ClaimName)
		}
	}
	processedPayload, ok := processed.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("processed sd-jwt payload is not an object")
	}
	return processedPayload, decoded, nil
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

func sdJWTHashAlgorithm(payload map[string]interface{}) (string, error) {
	algorithm := "sha-256"
	if rawAlgorithm, exists := payload["_sd_alg"]; exists {
		value, ok := rawAlgorithm.(string)
		if !ok || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return "", fmt.Errorf("_sd_alg must be a non-empty string")
		}
		algorithm = value
	}
	if algorithm != "sha-256" {
		return "", fmt.Errorf("unsupported _sd_alg %q", algorithm)
	}
	return algorithm, nil
}

func isSDJWTVCAlwaysDisclosedClaim(claimName string) bool {
	switch claimName {
	case "iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status":
		return true
	default:
		return false
	}
}
