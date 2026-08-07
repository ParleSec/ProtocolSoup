package oauth2

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// resourceURL is the htu comparison target for a DPoP proof presented to
// this endpoint (RFC 9449 Section 4.3 check 9), mirroring
// Plugin.tokenEndpointURL for the resource-server role.
func (p *Plugin) resourceURL() string {
	return p.baseURL + "/oauth2/resource"
}

// parseAuthorizedToken extracts the access token from the Authorization
// header, accepting both the Bearer and DPoP presentation schemes (RFC 9449
// Section 7.1 reuses the proof header's name as the auth scheme too).
func parseAuthorizedToken(r *http.Request) (scheme, token string, err error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return "", "", errors.New("missing Authorization header")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 {
		return "", "", errors.New("malformed Authorization header")
	}
	token = strings.TrimSpace(parts[1])
	if token == "" {
		return "", "", errors.New("missing access token")
	}
	switch {
	case strings.EqualFold(parts[0], dpop.HeaderName):
		return "DPoP", token, nil
	case strings.EqualFold(parts[0], "Bearer"):
		return "Bearer", token, nil
	default:
		return "", "", errors.New("unsupported Authorization scheme (expected Bearer or DPoP)")
	}
}

// writeResourceAuthError writes an RFC 6750/RFC 9449 WWW-Authenticate
// challenge alongside a JSON error body. scheme is "Bearer" unless the
// rejected token is known to be DPoP-bound, in which case it is "DPoP" --
// per RFC 9449 Section 7.1 a bound token must never be told Bearer is an
// acceptable presentation, even in the error path.
func writeResourceAuthError(w http.ResponseWriter, status int, scheme, code, description string, nonce string) {
	if nonce != "" {
		w.Header().Set(dpop.NonceHeaderName, nonce)
	}
	if code != "" {
		w.Header().Set("WWW-Authenticate", scheme+` error="`+code+`"`)
	} else {
		w.Header().Set("WWW-Authenticate", scheme)
	}
	writeOAuth2ErrorStatus(w, status, code, description, "")
}

// handleProtectedResource is a minimal RFC 6750 / RFC 9449 protected
// resource endpoint that gives the client_credentials Looking Glass flow a
// real resource-server leg to call with the access token it just received,
// instead of only describing that step (RFC 9449 Section 7). Authorization
// accepts Bearer <token> for an unbound token, or DPoP <token> plus a
// matching DPoP proof carrying ath for a token whose cnf.jkt binds it to a
// key. Presenting a DPoP-bound token as bare Bearer is rejected outright,
// never silently downgraded to unauthenticated access.
func (p *Plugin) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	scheme, token, err := parseAuthorizedToken(r)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Protected Resource Request Rejected", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   err.Error(),
		})
		writeResourceAuthError(w, http.StatusUnauthorized, "Bearer", "invalid_token", err.Error(), "")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Protected Resource Request", map[string]interface{}{
		"endpoint":           "/oauth2/resource",
		"authorization_type": scheme,
		"has_dpop_header":    r.Header.Get(dpop.HeaderName) != "",
	}, p.oauth2Annotation("dpop_ath")...)

	claims, err := p.mockIdP.JWTService().ValidateToken(token)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Protected Resource Access Denied", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   err.Error(),
		})
		writeResourceAuthError(w, http.StatusUnauthorized, "Bearer", "invalid_token", "invalid or expired access token", "")
		return
	}
	if p.mockIdP.IsTokenRevoked(token) {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Protected Resource Access Denied", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   "token has been revoked",
		})
		writeResourceAuthError(w, http.StatusUnauthorized, "Bearer", "invalid_token", "access token has been revoked", "")
		return
	}

	jkt := accessTokenJKT(claims)
	dpopBound := jkt != ""

	if !dpopBound {
		p.respondProtectedResource(w, sessionID, claims, "", false)
		return
	}

	if scheme != "DPoP" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Bound Token Presented As Bearer", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   "this access token is bound to a DPoP key and must be presented with a DPoP proof",
		}, p.oauth2Annotation("dpop_cnf_jkt")...)
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token",
			"this access token is bound to a DPoP key and must be presented with a DPoP proof (RFC 9449 Section 7)", "")
		return
	}

	proofHeader, err := dpop.ExtractHeader(r.Header.Values(dpop.HeaderName))
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Rejected", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   err.Error(),
		})
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token", err.Error(), "")
		return
	}
	if proofHeader == "" {
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token", "missing DPoP proof", "")
		return
	}

	proof, err := dpop.ValidateProof(proofHeader, dpop.ValidateOptions{
		Method:      r.Method,
		URI:         p.resourceURL(),
		AccessToken: token,
		Now:         p.now(),
	})
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Rejected", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   err.Error(),
		}, p.oauth2Annotation("dpop_ath")...)
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token", "invalid DPoP proof: "+err.Error(), "")
		return
	}
	if proof.JKT != jkt {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Key Mismatch", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   "proof key does not match the token's bound cnf.jkt",
		}, p.oauth2Annotation("dpop_cnf_jkt")...)
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token", "DPoP proof key does not match the token's bound key", "")
		return
	}

	// RFC 9449 Section 8, RS role: independent of the AS-role nonce space
	// (Section 8.2) even though both roles are served by this plugin.
	if p.dpopRSNonceIssuer != nil && !p.dpopRSNonceIssuer.Valid(proof.Nonce) {
		nonce := p.dpopRSNonceIssuer.Issue()
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Nonce Challenge", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"error":    dpop.ErrorUseDPoPNonce,
		}, p.oauth2Annotation("dpop_nonce")...)
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, dpop.ErrorUseDPoPNonce,
			"a fresh DPoP proof nonce is required; retry with the nonce from the DPoP-Nonce response header", nonce)
		return
	}

	now := p.now()
	reserved, reserveErr := p.dpopReplay.Reserve(r.Context(), proof.JKT, proof.JTI, proof.IAT.Add(dpop.IatFreshnessWindow), now)
	if reserveErr != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Replay Store Unavailable", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"error":    "server_error",
		})
		writeResourceAuthError(w, http.StatusInternalServerError, dpop.HeaderName, "server_error", "DPoP validation is temporarily unavailable", "")
		return
	}
	if !reserved {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Replayed", map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"reason":   "jti has already been used",
		})
		writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, "invalid_token", "DPoP proof jti has already been used", "")
		return
	}

	p.respondProtectedResource(w, sessionID, claims, proof.JTI, true)
}

// respondProtectedResource writes the resource payload once authorization
// has succeeded, and emits the matching Looking Glass event.
func (p *Plugin) respondProtectedResource(w http.ResponseWriter, sessionID string, claims map[string]interface{}, proofJTI string, dpopBound bool) {
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	tokenType := "Bearer"
	if dpopBound {
		tokenType = "DPoP"
	}
	eventData := map[string]interface{}{
		"endpoint":    "/oauth2/resource",
		"sub":         sub,
		"scope":       scope,
		"token_type":  tokenType,
		"dpop_bound":  dpopBound,
		"data":        "protected resource payload",
		"accessed_at": time.Now().UTC().Format(time.RFC3339),
	}
	if proofJTI != "" {
		eventData["dpop_proof_jti"] = proofJTI
	}
	p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Protected Resource Response", eventData,
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Resource Server Validated Before Responding",
			Description: "The resource server checked the token's signature and expiry, and -- for a DPoP-bound token -- the accompanying proof's key and ath, before returning any data.",
			Reference:   "RFC 6750 Section 2.1; RFC 9449 Section 7.1",
		},
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":       "protected resource payload",
		"sub":        sub,
		"scope":      scope,
		"token_type": tokenType,
		"dpop_bound": dpopBound,
	})
}

// accessTokenJKT extracts the RFC 7800 cnf.jkt claim from decoded access
// token claims, or "" if the token is not DPoP-bound.
func accessTokenJKT(claims map[string]interface{}) string {
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}
