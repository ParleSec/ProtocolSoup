package ssf

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

type tokenRevoker interface {
	IsTokenRevoked(token string) bool
}

// CAEP Interoperability Profile §2.7.3 OAuth Scopes.
const (
	ScopeSSFRead   = "ssf.read"
	ScopeSSFManage = "ssf.manage"
)

// receiverIdentity is the Event Receiver bound to a Stream Management request.
// [SSF] §8: authorisation MUST associate a Receiver with one or more stream IDs
// and aud values.
type receiverIdentity struct {
	ID     string
	Scopes []string
}

func (id receiverIdentity) hasScope(need string) bool {
	for _, scope := range id.Scopes {
		if scope == ScopeSSFManage {
			return true
		}
		if scope == need {
			return true
		}
	}
	return false
}

func parseScopeClaim(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return strings.Fields(v)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

// authenticateReceiver binds a Stream Management request to a Receiver.
//
// [CAEPINTEROP] The SSF Transmitter as a Resource Server:
// MUST accept tokens in the Authorization header (RFC 6750 §2.1) and MUST NOT
// accept them as a URI query parameter (RFC 6750 §2.3).
//
// Looking Glass sessions remain a presentation-layer filter: a valid
// X-Looking-Glass-Session identifies the demo Receiver without a bearer token.
// When SSF_AS_JWKS_URI is set and neither a bearer token nor a Looking Glass
// session is present, the request is 401.
func (p *Plugin) authenticateReceiver(w http.ResponseWriter, r *http.Request, need string) (receiverIdentity, bool) {
	if strings.TrimSpace(r.URL.Query().Get("access_token")) != "" {
		p.writeBearerError(w, http.StatusBadRequest, "invalid_request",
			"access tokens MUST NOT be passed in the URI query parameter (RFC 6750 Section 2.3)")
		return receiverIdentity{}, false
	}

	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header != "" {
		typ, token, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(typ, "Bearer") || strings.TrimSpace(token) == "" {
			p.writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Authorization header must use the Bearer scheme")
			return receiverIdentity{}, false
		}
		ident, err := p.validateBearerJWT(strings.TrimSpace(token))
		if err != nil {
			p.writeBearerError(w, http.StatusUnauthorized, "invalid_token", "access token validation failed")
			return receiverIdentity{}, false
		}
		if !ident.hasScope(need) {
			p.writeBearerError(w, http.StatusForbidden, "insufficient_scope",
				"the request requires a scope that the access token does not grant")
			return receiverIdentity{}, false
		}
		return ident, true
	}

	if sessionID := getSessionID(r); sessionID != "" {
		return receiverIdentity{
			ID:     "session:" + sessionID,
			Scopes: []string{ScopeSSFManage},
		}, true
	}

	if strings.TrimSpace(p.asJWKSURI) != "" {
		p.writeBearerError(w, http.StatusUnauthorized, "invalid_token", "authorization is required")
		return receiverIdentity{}, false
	}

	return receiverIdentity{
		ID:     "anonymous",
		Scopes: []string{ScopeSSFManage},
	}, true
}

func (p *Plugin) validateBearerJWT(tokenString string) (receiverIdentity, error) {
	if strings.TrimSpace(p.asJWKSURI) == "" || p.jwksFetch == nil {
		return receiverIdentity{}, fmt.Errorf("authorization server JWKS is not configured")
	}

	jwks, err := p.jwksFetch.Fetch(p.asJWKSURI)
	if err != nil {
		return receiverIdentity{}, fmt.Errorf("fetch AS JWKS: %w", err)
	}

	// RFC 9068 Section 4: signature, expiry, typ, iss and aud.
	claims, err := crypto.ValidateAccessTokenWithJWKS(tokenString, jwks, p.asIssuer, p.asAudience)
	if err != nil {
		return receiverIdentity{}, err
	}

	if err := p.checkAccessTokenRevocation(tokenString); err != nil {
		return receiverIdentity{}, err
	}

	clientID, _ := claims["sub"].(string)
	if clientID == "" {
		clientID, _ = claims["client_id"].(string)
	}
	if clientID == "" {
		return receiverIdentity{}, fmt.Errorf("access token missing client identifier")
	}

	return receiverIdentity{
		ID:     clientID,
		Scopes: parseScopeClaim(claims["scope"]),
	}, nil
}

// introspectionClientID is the resource server registration the OAuth 2.0
// authorization server seeds for this Transmitter
// (mockidp.SSFTransmitterClientID).
const introspectionClientID = "ssf-transmitter"

func (p *Plugin) checkAccessTokenRevocation(tokenString string) error {
	if p.revoker != nil {
		if p.revoker.IsTokenRevoked(tokenString) {
			return fmt.Errorf("access token has been revoked")
		}
		return nil
	}
	if strings.TrimSpace(p.introspectURL) == "" {
		return nil
	}
	if p.introspectSecret == "" {
		return fmt.Errorf("token introspection is configured without SSF_AS_INTROSPECT_CLIENT_SECRET")
	}
	// The Transmitter authenticates as its own resource server registration.
	return crypto.IntrospectAccessToken(p.introspectURL, introspectionClientID, p.introspectSecret, tokenString)
}

// writeBearerError returns an RFC 6750 Section 3.1 error response.
func (p *Plugin) writeBearerError(w http.ResponseWriter, status int, errCode, description string) {
	params := []string{`realm="ssf"`}
	if errCode != "" {
		params = append(params, fmt.Sprintf(`error=%q`, errCode))
	}
	if description != "" {
		params = append(params, fmt.Sprintf(`error_description=%q`, description))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

func writeStreamJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, data)
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
