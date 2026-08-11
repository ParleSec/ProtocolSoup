package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// handleRotateKeys performs an operator-triggered OP signing-key rotation so
// clients can observe a new kid while retired keys remain published
// (OIDC Core 1.0 Section 10.1.1). Disabled unless configured.
func (p *Plugin) handleRotateKeys(w http.ResponseWriter, r *http.Request) {
	if p.keyRotationToken == "" {
		writeOIDCError(w, http.StatusNotFound, "not_found", "Key rotation is not enabled")
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok || !subtleConstantTimeEqual(token, p.keyRotationToken) {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Valid operator token required")
		return
	}
	if p.keySet == nil {
		writeOIDCError(w, http.StatusServiceUnavailable, "server_error", "Key set unavailable")
		return
	}

	before := p.keySet.RSAKeyID()
	if err := p.keySet.Rotate(); err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "Key rotation failed")
		return
	}
	after := p.keySet.RSAKeyID()

	p.emitEvent(p.getSessionFromRequest(r), lookingglass.EventTypeSecurityWarning, "OP Signing Keys Rotated", map[string]interface{}{
		"previous_rsa_kid": before,
		"current_rsa_kid":  after,
		"jwks_uri":         strings.TrimRight(p.mockIdP.GetIssuer(), "/") + "/oidc/.well-known/jwks.json",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OP Signing Key Rotation",
		Description: "New signing keys were generated. Previously published public keys remain in JWKS so tokens signed before rotation stay verifiable.",
		Reference:   "OpenID Connect Core 1.0 Section 10.1.1",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"rotated":          true,
		"previous_rsa_kid": before,
		"current_rsa_kid":  after,
	})
}
