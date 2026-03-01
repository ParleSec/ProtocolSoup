package vc

import (
	"fmt"
	"strings"
)

// SDJWTEnvelope is the parsed structure for an SD-JWT VC serialization.
type SDJWTEnvelope struct {
	IssuerSignedJWT string   `json:"issuer_signed_jwt"`
	Disclosures     []string `json:"disclosures,omitempty"`
	KeyBindingJWT   string   `json:"key_binding_jwt,omitempty"`
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

func isJWTLike(value string) bool {
	return strings.Count(value, ".") == 2
}
