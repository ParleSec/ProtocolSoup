package scim

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/golang-jwt/jwt/v5"
)

// RFC 7644 Section 2: "The SCIM protocol is based upon HTTP and does not
// itself define a SCIM-specific scheme for authentication and authorization."
// This service provider is an OAuth 2.0 protected resource. It accepts the
// bearer tokens of RFC 6750, which Section 2 allows "when combined with TLS
// and a token framework such as OAuth 2.0 [RFC6749]", and validates them as
// the JWT access tokens of RFC 9068.
//
// A static shared secret is not accepted. RFC 7644 Section 7.4: "Bearer
// tokens MUST have a limited lifetime that can be determined directly or
// indirectly (e.g., by checking with a validation service) by the service
// provider." An access token carries its lifetime in "exp".

// OAuth 2.0 scope values of this service provider. RFC 7644 Section 2:
// "Regardless of methodology, the SCIM service provider MUST be able to map
// the authenticated client to an access control policy in order to determine
// the client's authorization to retrieve and update SCIM resources."
// scim.read authorizes retrieval; scim.write authorizes creation,
// modification and deletion.
const (
	ScopeRead  = "scim.read"
	ScopeWrite = "scim.write"
)

// authRealm is the realm of the Bearer challenge (RFC 6750 Section 3).
const authRealm = "scim"

// introspectionClientID is the resource server registration the OAuth 2.0
// authorization server seeds for this service provider
// (mockidp.SCIMServiceProviderClientID).
const introspectionClientID = "scim-service-provider"

// authorizationServer is the OAuth 2.0 authorization server when it runs in
// this process: it validates the access tokens it signed and knows which of
// them it has revoked.
type authorizationServer interface {
	JWTService() *crypto.JWTService
	IsTokenRevoked(token string) bool
}

// clientIdentity is the SCIM client a request was authenticated as.
type clientIdentity struct {
	ID     string
	Scopes []string
}

func (c clientIdentity) hasScope(need string) bool {
	for _, scope := range c.Scopes {
		if scope == need {
			return true
		}
	}
	return false
}

// tokenRefused is an access token this service provider does not accept.
type tokenRefused struct {
	// description is the RFC 6750 Section 3 error_description. That section
	// keeps it to %x20-21 / %x23-5B / %x5D-7E, so it has no quotation mark.
	description string
	// reason is the failed check in full, for Looking Glass.
	reason string
}

func (e *tokenRefused) Error() string { return e.reason }

// configureAuthorization reads which authorization server this service
// provider trusts and how it identifies itself.
//
// RFC 9068 Section 4: "The issuer identifier for the authorization server
// (which is typically obtained during discovery) MUST exactly match the value
// of the "iss" claim." Access tokens come from the OAuth 2.0 authorization
// server, whose issuer is {origin}/oauth2. On the monolith that server is in
// this process; a split deployment names it and the JWK Set it publishes.
func (p *Plugin) configureAuthorization(config plugin.PluginConfig) error {
	base := strings.TrimRight(p.baseURL, "/")
	p.asIssuer = strings.TrimRight(strings.TrimSpace(os.Getenv("SCIM_AS_ISSUER")), "/")
	if p.asIssuer == "" {
		p.asIssuer = base + "/oauth2"
	}
	// The resource indicator is the Base URI of RFC 7644 Section 1.3.
	p.resource = strings.TrimRight(strings.TrimSpace(os.Getenv("SCIM_RESOURCE")), "/")
	if p.resource == "" {
		p.resource = base + "/scim/v2"
	}
	p.asJWKSURI = strings.TrimSpace(os.Getenv("SCIM_AS_JWKS_URI"))
	p.introspectURL = strings.TrimSpace(os.Getenv("SCIM_AS_INTROSPECT_URI"))
	p.introspectSecret = strings.TrimSpace(os.Getenv("SCIM_AS_INTROSPECT_CLIENT_SECRET"))

	if p.asJWKSURI == "" {
		as, ok := config.MockIdP.(authorizationServer)
		if !ok {
			return fmt.Errorf("SCIM_AS_JWKS_URI is required: no authorization server runs in this process, so the service provider needs the JWK Set of the one that issues its access tokens")
		}
		p.authorizationServer = as
		return nil
	}
	if p.introspectURL != "" && p.introspectSecret == "" {
		return fmt.Errorf("SCIM_AS_INTROSPECT_URI is set without SCIM_AS_INTROSPECT_CLIENT_SECRET: the service provider could not authenticate to the introspection endpoint")
	}
	p.jwksFetch = crypto.NewJWKSFetcher(5 * time.Minute)
	return nil
}

// requiredScope is the scope a request needs. Retrieval is GET, and the POST
// query of RFC 7644 Section 3.4.3, whose path ends in "/.search".
func requiredScope(r *http.Request) string {
	switch {
	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		return ScopeRead
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/.search"):
		return ScopeRead
	default:
		return ScopeWrite
	}
}

// authorize authenticates the SCIM client from its access token and checks
// that the token grants the scope the request needs.
func (p *Plugin) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		token = strings.TrimSpace(token)
		if !strings.EqualFold(scheme, "Bearer") {
			// RFC 6750 Section 3.1: "If the request lacks any authentication
			// information (e.g., the client was unaware that authentication
			// is necessary or attempted using an unsupported authentication
			// method), the resource server SHOULD NOT include an error code
			// or other error information."
			p.refuse(w, r, http.StatusUnauthorized, "",
				"an OAuth 2.0 access token is required in the Authorization header with the Bearer scheme", "")
			return
		}
		if token == "" {
			// RFC 6750 Section 3.1, invalid_request: the request "is
			// otherwise malformed. The resource server SHOULD respond with
			// the HTTP 400 (Bad Request) status code."
			p.refuse(w, r, http.StatusBadRequest, "invalid_request",
				"the Authorization header names the Bearer scheme and carries no access token", "")
			return
		}

		client, err := p.authenticate(token)
		if err != nil {
			var refused *tokenRefused
			if !errors.As(err, &refused) {
				// The token could not be checked at all; that is not the
				// client's failure.
				WriteError(w, ErrInternalServer(err.Error()))
				return
			}
			// RFC 6750 Section 3.1, invalid_token: "The access token provided
			// is expired, revoked, malformed, or invalid for other reasons.
			// The resource SHOULD respond with the HTTP 401 (Unauthorized)
			// status code."
			p.refuse(w, r, http.StatusUnauthorized, "invalid_token", refused.description, refused.reason)
			return
		}

		need := requiredScope(r)
		if !client.hasScope(need) {
			// RFC 6750 Section 3.1, insufficient_scope: "The request requires
			// higher privileges than provided by the access token. The
			// resource server SHOULD respond with the HTTP 403 (Forbidden)
			// status code and MAY include the "scope" attribute with the
			// scope necessary to access the protected resource."
			p.refuse(w, r, http.StatusForbidden, "insufficient_scope",
				"the access token does not grant the scope this request needs", "the request needs "+need+"; the token grants: "+strings.Join(client.Scopes, " "))
			return
		}

		p.emitAuthorization(r, lookingglass.EventTypeTokenValidated, "SCIM Client Authorized", map[string]interface{}{
			"endpoint":       r.Method + " " + r.URL.Path,
			"client_id":      client.ID,
			"scope":          strings.Join(client.Scopes, " "),
			"required_scope": need,
			"issuer":         p.asIssuer,
			"audience":       p.resource,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Access Token Mapped To An Access Control Policy",
			Description: "The service provider checked the access token's typ, iss, aud, signature and expiry, then matched the scope it grants against the scope this request needs: scim.read to retrieve resources, scim.write to create, modify or delete them.",
			Reference:   "RFC 7644 Section 2; RFC 9068 Section 4",
		})
		next.ServeHTTP(w, r)
	})
}

// authenticate validates an access token as RFC 9068 Section 4 has a resource
// server do, and returns the client it was issued to.
func (p *Plugin) authenticate(token string) (clientIdentity, error) {
	var claims jwt.MapClaims
	var err error
	if p.authorizationServer != nil {
		claims, err = p.authorizationServer.JWTService().ValidateAccessToken(token, p.asIssuer, p.resource)
	} else {
		jwks, fetchErr := p.jwksFetch.Fetch(p.asJWKSURI)
		if fetchErr != nil {
			return clientIdentity{}, fmt.Errorf("the authorization server's JWK Set could not be fetched: %w", fetchErr)
		}
		claims, err = crypto.ValidateAccessTokenWithJWKS(token, jwks, p.asIssuer, p.resource)
	}
	if err != nil {
		refused := &tokenRefused{description: "the access token signature or expiry did not validate", reason: err.Error()}
		var failed *crypto.AccessTokenError
		if errors.As(err, &failed) {
			switch failed.Check {
			case "typ":
				refused.description = "the access token typ header is not at+jwt"
			case "iss":
				refused.description = "the access token was not issued by the authorization server this service provider trusts"
			case "aud":
				refused.description = "the access token aud does not name this service provider"
			}
		}
		return clientIdentity{}, refused
	}

	// RFC 7009 Section 2.1: a revoked token is one the authorization server
	// has invalidated. In this process the server is asked directly; apart
	// from it, through introspection (RFC 7662) when that is configured.
	switch {
	case p.authorizationServer != nil:
		if p.authorizationServer.IsTokenRevoked(token) {
			return clientIdentity{}, &tokenRefused{description: "the access token has been revoked", reason: "the authorization server has revoked this access token"}
		}
	case p.introspectURL != "":
		if err := crypto.IntrospectAccessToken(p.introspectURL, introspectionClientID, p.introspectSecret, token); err != nil {
			return clientIdentity{}, &tokenRefused{description: "the access token is not active", reason: err.Error()}
		}
	}

	// This service provider supports the Bearer scheme alone, so it cannot
	// check a proof of possession. RFC 9449 Section 7.2 has a resource that
	// supports DPoP "reject a DPoP-bound access token received as a bearer
	// token" in order "to prevent downgraded usage of a DPoP-bound access
	// token"; a token bound to a key (RFC 7800 "cnf") is refused here for the
	// same reason.
	if _, bound := claims["cnf"]; bound {
		return clientIdentity{}, &tokenRefused{
			description: "the access token is bound to a key and this service provider accepts bearer tokens only",
			reason:      "the access token carries a cnf claim; this service provider supports the Bearer scheme alone and cannot verify a proof of possession",
		}
	}

	// RFC 9068 Section 2.2 makes client_id REQUIRED: "as defined in Section
	// 4.3 of [RFC8693]".
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		return clientIdentity{}, &tokenRefused{description: "the access token names no client", reason: "the access token has no client_id claim"}
	}
	// RFC 9068 Section 2.2.3: the "scope" claim is "as defined in Section 4.2
	// of [RFC8693]", a space-separated list.
	scope, _ := claims["scope"].(string)
	return clientIdentity{ID: clientID, Scopes: strings.Fields(scope)}, nil
}

// refuse answers a request this service provider does not authorize.
//
// RFC 7644 Section 2: "As per Section 4.1 of [RFC7235], a SCIM service
// provider SHALL indicate supported HTTP authentication schemes via the
// "WWW-Authenticate" header." The challenge follows RFC 6750 Section 3 and the
// body RFC 7644 Section 3.12. errCode is empty when the request carried no
// bearer credentials.
func (p *Plugin) refuse(w http.ResponseWriter, r *http.Request, status int, errCode, description, reason string) {
	params := []string{`realm="` + authRealm + `"`}
	if errCode != "" {
		params = append(params, `error="`+errCode+`"`, `error_description="`+description+`"`)
	}
	if errCode == "insufficient_scope" {
		params = append(params, `scope="`+requiredScope(r)+`"`)
	}
	challenge := "Bearer " + strings.Join(params, ", ")
	w.Header().Set("WWW-Authenticate", challenge)

	data := map[string]interface{}{
		"endpoint":         r.Method + " " + r.URL.Path,
		"status":           status,
		"www_authenticate": challenge,
		"required_scope":   requiredScope(r),
		"issuer":           p.asIssuer,
		"audience":         p.resource,
	}
	if reason != "" {
		data["reason"] = reason
	}
	p.emitAuthorization(r, lookingglass.EventTypeSecurityWarning, "SCIM Request Not Authorized", data, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "The Service Provider Challenges With Bearer",
		Description: "A SCIM service provider names the HTTP authentication scheme it supports in WWW-Authenticate. This one accepts OAuth 2.0 bearer access tokens whose aud is its base URI, and tells the client which check failed.",
		Severity:    "warning",
		Reference:   "RFC 7644 Section 2; RFC 6750 Section 3",
	})

	WriteError(w, &SCIMError{Status: status, Detail: description})
}

// emitAuthorization records an authorization decision in the Looking Glass
// session the request belongs to.
func (p *Plugin) emitAuthorization(r *http.Request, eventType lookingglass.EventType, title string, data map[string]interface{}, annotation lookingglass.Annotation) {
	sessionID := r.Header.Get("X-Looking-Glass-Session")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("lg_session")
	}
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	p.lookingGlass.NewEventBroadcaster(sessionID).Emit(eventType, title, data, annotation)
}

// ProvisioningEvent represents an event from Okta provisioning
type ProvisioningEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`   // "okta", "azure", etc.
	Action    string                 `json:"action"`   // "create", "update", "delete"
	Resource  string                 `json:"resource"` // "User", "Group"
	UserAgent string                 `json:"userAgent"`
	Data      map[string]interface{} `json:"data"`
}

// ProvisioningLog tracks provisioning events from external IdPs
type ProvisioningLog struct {
	events  []ProvisioningEvent
	mu      sync.RWMutex
	maxSize int
}

var provisioningLog = &ProvisioningLog{
	events:  make([]ProvisioningEvent, 0),
	maxSize: 100, // Keep last 100 events
}

// LogProvisioningEvent logs a provisioning event
func LogProvisioningEvent(event ProvisioningEvent) {
	provisioningLog.mu.Lock()
	defer provisioningLog.mu.Unlock()

	// Add to front
	provisioningLog.events = append([]ProvisioningEvent{event}, provisioningLog.events...)

	// Trim if needed
	if len(provisioningLog.events) > provisioningLog.maxSize {
		provisioningLog.events = provisioningLog.events[:provisioningLog.maxSize]
	}

	log.Printf("[SCIM Provisioning] %s %s from %s - %s", event.Action, event.Resource, event.Source, event.ID)
}

// GetProvisioningEvents returns recent provisioning events
func GetProvisioningEvents(limit int) []ProvisioningEvent {
	provisioningLog.mu.RLock()
	defer provisioningLog.mu.RUnlock()

	if limit <= 0 || limit > len(provisioningLog.events) {
		limit = len(provisioningLog.events)
	}

	result := make([]ProvisioningEvent, limit)
	copy(result, provisioningLog.events[:limit])
	return result
}

// DetectIdPSource attempts to detect the IdP from request headers
func DetectIdPSource(r *http.Request) string {
	userAgent := r.Header.Get("User-Agent")

	// Okta's SCIM client
	if strings.Contains(userAgent, "Okta") {
		return "okta"
	}

	// Azure AD SCIM client
	if strings.Contains(userAgent, "Azure") || strings.Contains(userAgent, "Microsoft") {
		return "azure"
	}

	// OneLogin
	if strings.Contains(userAgent, "OneLogin") {
		return "onelogin"
	}

	// JumpCloud
	if strings.Contains(userAgent, "JumpCloud") {
		return "jumpcloud"
	}

	// Check for custom header that some IdPs send
	if idp := r.Header.Get("X-IdP-Source"); idp != "" {
		return strings.ToLower(idp)
	}

	return "unknown"
}
