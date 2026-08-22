package ssf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	unverified := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(tokenString, unverified)
	if err != nil {
		return receiverIdentity{}, err
	}

	jwks, err := p.jwksFetch.Fetch(p.asJWKSURI)
	if err != nil {
		return receiverIdentity{}, fmt.Errorf("fetch AS JWKS: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		var jwk interface{ ToPublicKey() (interface{}, error) }
		if kid != "" {
			key, keyErr := jwks.GetKeyByID(kid)
			if keyErr != nil {
				return nil, keyErr
			}
			jwk = key
		} else if len(jwks.Keys) == 1 {
			jwk = &jwks.Keys[0]
		} else {
			return nil, fmt.Errorf("token kid is required when the AS JWKS has multiple keys")
		}
		return jwk.ToPublicKey()
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil || token == nil || !token.Valid {
		if err == nil {
			err = fmt.Errorf("invalid access token")
		}
		return receiverIdentity{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return receiverIdentity{}, fmt.Errorf("invalid access token claims")
	}

	iss, _ := claims["iss"].(string)
	if p.asIssuer != "" && iss != p.asIssuer {
		return receiverIdentity{}, fmt.Errorf("invalid issuer")
	}

	if p.asAudience != "" {
		switch aud := claims["aud"].(type) {
		case string:
			if aud != p.asAudience {
				return receiverIdentity{}, fmt.Errorf("invalid audience")
			}
		case []interface{}:
			found := false
			for _, item := range aud {
				if s, ok := item.(string); ok && s == p.asAudience {
					found = true
					break
				}
			}
			if !found {
				return receiverIdentity{}, fmt.Errorf("invalid audience")
			}
		default:
			return receiverIdentity{}, fmt.Errorf("invalid audience")
		}
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
	form := url.Values{}
	form.Set("token", tokenString)
	req, err := http.NewRequest(http.MethodPost, p.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tokenString)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token introspection failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token introspection HTTP %d", resp.StatusCode)
	}
	var out struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("token introspection response: %w", err)
	}
	if !out.Active {
		return fmt.Errorf("access token is not active")
	}
	return nil
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
