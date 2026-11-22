package oauth2

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// resourceURL is the htu comparison target for a DPoP proof presented to
// this endpoint (RFC 9449 Section 4.3 check 9), mirroring
// Plugin.tokenEndpointURL for the resource-server role.
func (p *Plugin) resourceURL() string {
	return p.baseURL + "/oauth2/resource"
}

// issuer is this authorization server's issuer identifier, the value its RFC
// 8414 metadata publishes and the "iss" of every access token it signs. RFC
// 9068 Section 4: "Authorization servers SHOULD use OAuth 2.0 Authorization
// Server Metadata [RFC8414] to advertise to resource servers their signing
// keys via "jwks_uri" and what "iss" claim value to expect via the "issuer"
// metadata value."
func (p *Plugin) issuer() string {
	return strings.TrimRight(p.baseURL, "/") + "/oauth2"
}

// targetError is a refused "resource" or "scope" combination: the OAuth error
// code and its description.
type targetError struct {
	code        string
	description string
}

// defaultResource is the resource indicator a scope value implies. RFC 9068
// Section 3: "If the request does not include a "resource" parameter, the
// authorization server MUST use a default resource indicator in the "aud"
// claim. If a "scope" parameter is present in the request, the authorization
// server SHOULD use it to infer the value of the default resource indicator
// to be used in the "aud" claim." ssf.read and ssf.manage have meaning only
// at the SSF Transmitter; every other scope this server grants belongs to
// /oauth2/resource.
func (p *Plugin) defaultResource(scope string) (string, *targetError) {
	ssf, other := false, false
	for _, item := range strings.Fields(scope) {
		if item == "ssf.read" || item == "ssf.manage" {
			ssf = true
		} else {
			other = true
		}
	}
	switch {
	case ssf && other:
		// RFC 9068 Section 3: "If the values in the "scope" parameter refer
		// to different default resource indicator values, the authorization
		// server SHOULD reject the request with "invalid_scope" as described
		// in Section 4.1.2.1 of [RFC6749]."
		return "", &targetError{
			code:        "invalid_scope",
			description: "the requested scope values belong to different resources; request ssf.read and ssf.manage separately from the other scopes",
		}
	case ssf:
		return p.ssfResourceAudience(), nil
	default:
		return p.resourceURL(), nil
	}
}

// tokenAudience decides the "aud" of an access token from the request's
// "resource" parameter values (RFC 8707 Section 2) and the granted scope.
// This server issues each access token for exactly one resource, because RFC
// 9068 Section 3 says "The authorization server MUST NOT issue a JWT access
// token if the authorization granted by the token would be ambiguous."
func (p *Plugin) tokenAudience(resources []string, scope string) (string, *targetError) {
	if len(resources) == 0 {
		return p.defaultResource(scope)
	}

	requested := ""
	for _, value := range resources {
		// RFC 8707 Section 2: "Its value MUST be an absolute URI, as
		// specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a
		// fragment component."
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || strings.Contains(value, "#") {
			return "", &targetError{code: "invalid_target", description: "resource must be an absolute URI with no fragment component (RFC 8707 Section 2)"}
		}
		if value != p.resourceURL() && value != p.ssfResourceAudience() {
			return "", &targetError{code: "invalid_target", description: "resource does not name a protected resource this authorization server issues access tokens for"}
		}
		if requested != "" && requested != value {
			return "", &targetError{code: "invalid_target", description: "this authorization server issues each access token for one resource; send one resource value per request"}
		}
		requested = value
	}

	// RFC 9068 Section 2.2.3: "All the individual scope strings in the
	// "scope" claim MUST have meaning for the resources indicated in the
	// "aud" claim." RFC 8707 Section 2 gives invalid_target for "an invalid
	// combination of resource and scope".
	if implied, scopeErr := p.defaultResource(scope); scopeErr != nil || implied != requested {
		return "", &targetError{code: "invalid_target", description: "the requested scope has no meaning at the requested resource"}
	}
	return requested, nil
}

// emitTargetRejected records a refused resource indicator in Looking Glass.
func (p *Plugin) emitTargetRejected(sessionID, endpoint string, resources []string, scope string, rejected *targetError) {
	reference := "RFC 8707 Section 2"
	if rejected.code == "invalid_scope" {
		reference = "RFC 9068 Section 3"
	}
	p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Resource Indicator Rejected", map[string]interface{}{
		"endpoint":          endpoint,
		"error":             rejected.code,
		"error_description": rejected.description,
		"resource":          resources,
		"scope":             scope,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "One Resource Per Access Token",
		Description: "The authorization server audience-restricts each access token to one protected resource. It refuses a resource it does not issue tokens for, and a scope that has no meaning at the requested resource.",
		Severity:    "warning",
		Reference:   reference,
	})
}

// tokenAudienceOrError resolves the audience for a token endpoint request and
// writes the RFC 6749 Section 5.2 error response when it is refused.
func (p *Plugin) tokenAudienceOrError(w http.ResponseWriter, sessionID string, resources []string, scope string) (string, bool) {
	audience, rejected := p.tokenAudience(resources, scope)
	if rejected != nil {
		p.emitTargetRejected(sessionID, "/oauth2/token", resources, scope, rejected)
		writeOAuth2Error(w, rejected.code, rejected.description, "")
		return "", false
	}
	return audience, true
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

	// RFC 9068 Section 4: "Resource servers receiving a JWT access token
	// MUST validate it in the following manner." This resource trusts the
	// OAuth 2.0 authorization server at /oauth2 and identifies itself by its
	// own URL. "In particular, in case of any failure in the validation
	// checks listed above, the authorization server response MUST include
	// the error code "invalid_token"."
	claims, err := p.mockIdP.JWTService().ValidateAccessToken(token, p.issuer(), p.resourceURL())
	if err != nil {
		challenge := "Bearer"
		if accessTokenJKT(claims) != "" {
			challenge = dpop.HeaderName
		}
		description := "invalid or expired access token"
		eventData := map[string]interface{}{
			"endpoint": "/oauth2/resource",
			"error":    "invalid_token",
			"reason":   err.Error(),
		}
		var tokenErr *crypto.AccessTokenError
		if errors.As(err, &tokenErr) && tokenErr.Check != "signature" {
			description = tokenErr.Reason
			eventData["failed_check"] = tokenErr.Check
			eventData["expected_issuer"] = p.issuer()
			eventData["expected_audience"] = p.resourceURL()
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Protected Resource Access Denied", eventData, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "JWT Access Token Validation",
			Description: "A resource server accepts a JWT only when its typ header says at+jwt, its iss is the authorization server the resource trusts, its aud names the resource, its signature verifies and it has not expired. An ID Token, a refresh token or a token issued for another resource fails one of these checks.",
			Severity:    "warning",
			Reference:   "RFC 9068 Section 4",
		})
		writeResourceAuthError(w, http.StatusUnauthorized, challenge, "invalid_token", description, "")
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
	if p.dpopRSNonceIssuer != nil {
		valid, nonceErr := p.dpopRSNonceIssuer.Valid(proof.Nonce)
		if nonceErr != nil {
			writeResourceAuthError(w, http.StatusInternalServerError, dpop.HeaderName, "server_error", "DPoP nonce validation is temporarily unavailable", "")
			return
		}
		if !valid {
			nonce, issueErr := p.dpopRSNonceIssuer.Issue()
			if issueErr != nil {
				writeResourceAuthError(w, http.StatusInternalServerError, dpop.HeaderName, "server_error", "DPoP nonce generation is temporarily unavailable", "")
				return
			}
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Nonce Challenge", map[string]interface{}{
				"endpoint": "/oauth2/resource",
				"error":    dpop.ErrorUseDPoPNonce,
			}, p.oauth2Annotation("dpop_nonce")...)
			writeResourceAuthError(w, http.StatusUnauthorized, dpop.HeaderName, dpop.ErrorUseDPoPNonce,
				"a fresh DPoP proof nonce is required; retry with the nonce from the DPoP-Nonce response header", nonce)
			return
		}
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
			Description: "The resource server checked the token's typ, iss, aud, signature and expiry, and -- for a DPoP-bound token -- the accompanying proof's key and ath, before returning any data.",
			Reference:   "RFC 9068 Section 4; RFC 9449 Section 7.1",
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
