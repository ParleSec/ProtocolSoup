package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
)

const (
	maxRegistrationBodyBytes = 64 * 1024
	defaultRegistrationTTL   = 2 * time.Hour
	defaultMaxDynamicClients = 200
	defaultRegistrationRate  = 30
	defaultRegistrationBurst = time.Minute
)

type registrationRateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	attempts map[string][]time.Time
}

func newRegistrationRateLimiter(limit int, window time.Duration) *registrationRateLimiter {
	if limit <= 0 {
		limit = defaultRegistrationRate
	}
	if window <= 0 {
		window = defaultRegistrationBurst
	}
	return &registrationRateLimiter{
		window:   window,
		limit:    limit,
		attempts: make(map[string][]time.Time),
	}
}

func (l *registrationRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.attempts[key][:0]
	for _, ts := range l.attempts[key] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.limit {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}

func (p *Plugin) registrationEnabled() bool {
	return p.dynamicRegistrationEnabled
}

func (p *Plugin) handleRegister(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if !p.registrationEnabled() {
		writeOIDCError(w, http.StatusNotFound, "not_found", "Dynamic Client Registration is not enabled")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOIDCError(w, http.StatusMethodNotAllowed, "invalid_request", "Registration requires POST")
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Content-Type must be application/json")
		return
	}

	source := registrationSourceKey(r)
	if p.registrationLimiter != nil && !p.registrationLimiter.allow(source, time.Now()) {
		writeRegistrationError(w, http.StatusTooManyRequests, "invalid_client_metadata", "Registration rate limit exceeded")
		return
	}
	if p.mockIdP.CountDynamicClients() >= p.maxDynamicClients {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Dynamic registration capacity exceeded")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRegistrationBodyBytes+1))
	if err != nil {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to read registration body")
		return
	}
	if len(body) > maxRegistrationBodyBytes {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Registration body too large")
		return
	}

	req, err := decodeRegistrationRequest(body)
	if err != nil {
		writeRegistrationValidationError(w, err)
		return
	}
	if err := validateRegistrationRequest(req); err != nil {
		writeRegistrationValidationError(w, err)
		return
	}
	if err := p.validateSectorIdentifierDocument(req); err != nil {
		writeRegistrationValidationError(w, err)
		return
	}

	client, registrationAccessToken, err := p.issueDynamicClient(req)
	if err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "server_error", "Failed to create client registration")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Dynamic Client Registered", map[string]interface{}{
		"client_id":                    client.ID,
		"redirect_uris":                client.RedirectURIs,
		"response_types":               client.ResponseTypes,
		"grant_types":                  client.GrantTypes,
		"token_endpoint_auth_method":   client.TokenEndpointAuthMethod,
		"initiate_login_uri":           client.InitiateLoginURI,
		"registration_client_uri":      client.RegistrationClientURI,
		"registration_access_token":    "[redacted]",
		"client_secret_present":        client.Secret != "",
		"client_secret_expires_at":     client.ClientSecretExpiresAt,
		"application_type":             client.ApplicationType,
		"userinfo_signed_response_alg": client.UserinfoSignedResponseAlg,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OpenID Connect Dynamic Client Registration",
		Description: "The OP issued a unique client_id and optional credentials for an open registration request. Unknown metadata was ignored; understood invalid metadata would have been rejected.",
		Reference:   "OpenID Connect Dynamic Client Registration 1.0 Section 3.2",
	})

	writeRegistrationResponse(w, http.StatusCreated, buildRegistrationResponse(client, registrationAccessToken))
}

func (p *Plugin) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
	if !p.registrationEnabled() {
		writeOIDCError(w, http.StatusNotFound, "not_found", "Dynamic Client Registration is not enabled")
		return
	}

	clientID := chi.URLParam(r, "client_id")
	client, ok := p.authenticateRegistrationManagement(w, r, clientID)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeRegistrationResponse(w, http.StatusOK, buildRegistrationResponse(client, ""))
	case http.MethodPut:
		p.handleUpdateRegisterClient(w, r, client)
	case http.MethodDelete:
		p.handleDeleteRegisterClient(w, r, client)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeRegistrationError(w, http.StatusMethodNotAllowed, "invalid_request", "Client configuration supports GET, PUT, and DELETE")
	}
}

// authenticateRegistrationManagement verifies the bearer registration access
// token required by RFC 7592 Section 2 for every configuration operation.
func (p *Plugin) authenticateRegistrationManagement(w http.ResponseWriter, r *http.Request, clientID string) (*models.Client, bool) {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Registration Access Token required")
		return nil, false
	}
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists || !client.Dynamic {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Unknown or expired client registration")
		return nil, false
	}
	if !registrationAccessTokenMatches(client, token) {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Registration Access Token is invalid for this client")
		return nil, false
	}
	return client, true
}

func (p *Plugin) handleUpdateRegisterClient(w http.ResponseWriter, r *http.Request, client *models.Client) {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Content-Type must be application/json")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRegistrationBodyBytes+1))
	if err != nil {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to read registration body")
		return
	}
	if len(body) > maxRegistrationBodyBytes {
		writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", "Registration body too large")
		return
	}
	req, err := decodeRegistrationRequest(body)
	if err != nil {
		writeRegistrationValidationError(w, err)
		return
	}
	if err := validateRegistrationUpdateRequest(body, req, client); err != nil {
		writeRegistrationValidationError(w, err)
		return
	}
	if err := validateRegistrationRequest(req); err != nil {
		writeRegistrationValidationError(w, err)
		return
	}
	if err := p.validateSectorIdentifierDocument(req); err != nil {
		writeRegistrationValidationError(w, err)
		return
	}

	if err := applyRegistrationMetadata(client, req); err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "server_error", "Failed to update client registration")
		return
	}
	registrationAccessToken, err := randomURLString(32)
	if err != nil {
		writeRegistrationError(w, http.StatusInternalServerError, "server_error", "Failed to rotate registration access token")
		return
	}
	client.RegistrationAccessTokenHash = hashRegistrationAccessToken(registrationAccessToken)
	p.mockIdP.RegisterClient(client)

	p.emitEvent(p.getSessionFromRequest(r), lookingglass.EventTypeFlowStep, "Dynamic Client Updated", map[string]interface{}{
		"client_id":                  client.ID,
		"redirect_uris":              client.RedirectURIs,
		"response_types":             client.ResponseTypes,
		"grant_types":                client.GrantTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"registration_access_token":  "[rotated]",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Dynamic Client Registration Updated",
		Description: "The client metadata was fully replaced using an authenticated RFC 7592 update request. A new registration access token was issued.",
		Reference:   "RFC 7592 Section 2.2",
	})
	writeRegistrationResponse(w, http.StatusOK, buildRegistrationResponse(client, registrationAccessToken))
}

func (p *Plugin) handleDeleteRegisterClient(w http.ResponseWriter, r *http.Request, client *models.Client) {
	if !p.mockIdP.DeleteClient(client.ID) {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "Unknown or expired client registration")
		return
	}
	p.emitEvent(p.getSessionFromRequest(r), lookingglass.EventTypeSecurityWarning, "Dynamic Client Deprovisioned", map[string]interface{}{
		"client_id": client.ID,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Dynamic Client Registration Deleted",
		Description: "The authenticated client configuration endpoint deprovisioned this dynamic client. Its client ID, secret, and registration access token are no longer usable.",
		Reference:   "RFC 7592 Section 2.3",
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) issueDynamicClient(req *registrationRequest) (*models.Client, string, error) {
	now := time.Now().UTC()
	clientID, err := randomURLString(18)
	if err != nil {
		return nil, "", err
	}
	registrationAccessToken, err := randomURLString(32)
	if err != nil {
		return nil, "", err
	}

	ttl := p.dynamicRegistrationTTL
	if ttl <= 0 {
		ttl = defaultRegistrationTTL
	}
	expiresAt := now.Add(ttl)

	issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	registrationClientURI := issuer + "/oidc/register/" + url.PathEscape(clientID)

	client := &models.Client{
		ID:                          clientID,
		RegistrationAccessTokenHash: hashRegistrationAccessToken(registrationAccessToken),
		RegistrationClientURI:       registrationClientURI,
		ClientIDIssuedAt:            now.Unix(),
		Dynamic:                     true,
		CreatedAt:                   now,
		ExpiresAt:                   &expiresAt,
	}
	if err := applyRegistrationMetadata(client, req); err != nil {
		return nil, "", err
	}

	p.mockIdP.RegisterClient(client)
	return client, registrationAccessToken, nil
}

// applyRegistrationMetadata replaces client metadata rather than merging it,
// as required by RFC 7592 Section 2.2. Server-issued identity and registration
// management fields remain untouched.
func applyRegistrationMetadata(client *models.Client, req *registrationRequest) error {
	client.Name = strings.TrimSpace(req.ClientName)
	if client.Name == "" {
		client.Name = "Dynamically Registered Client"
	}
	client.RedirectURIs = append([]string{}, req.RedirectURIs...)
	client.ResponseTypes = append([]string{}, req.ResponseTypes...)
	client.GrantTypes = append([]string{}, req.GrantTypes...)
	client.Scopes = registrationScopes(req.Scope)
	client.ApplicationType = req.ApplicationType
	client.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	client.JWKS = req.Jwks
	client.JWKSURI = strings.TrimSpace(req.JwksURI)
	client.Contacts = append([]string{}, req.Contacts...)
	client.ClientURI = strings.TrimSpace(req.ClientURI)
	client.LogoURI = strings.TrimSpace(req.LogoURI)
	client.PolicyURI = strings.TrimSpace(req.PolicyURI)
	client.TosURI = strings.TrimSpace(req.TosURI)
	client.SubjectType = req.SubjectType
	client.SectorIdentifierURI = strings.TrimSpace(req.SectorIdentifierURI)
	client.IDTokenSignedResponseAlg = req.IDTokenSignedResponseAlg
	client.UserinfoSignedResponseAlg = strings.TrimSpace(req.UserinfoSignedResponseAlg)
	client.RequestObjectSigningAlg = strings.TrimSpace(req.RequestObjectSigningAlg)
	client.TokenEndpointAuthSigningAlg = strings.TrimSpace(req.TokenEndpointAuthSigningAlg)
	client.InitiateLoginURI = strings.TrimSpace(req.InitiateLoginURI)
	client.DefaultMaxAge = req.DefaultMaxAge
	client.RequireAuthTime = req.RequireAuthTime != nil && *req.RequireAuthTime

	switch req.TokenEndpointAuthMethod {
	case "none":
		client.Public = true
		client.Secret = ""
		client.ClientSecretExpiresAt = nil
	case "private_key_jwt":
		client.Public = false
		client.Secret = ""
		client.ClientSecretExpiresAt = nil
	default:
		client.Public = false
		if client.Secret == "" {
			secret, err := randomURLString(32)
			if err != nil {
				return err
			}
			client.Secret = secret
			if client.ExpiresAt != nil {
				expiresAt := client.ExpiresAt.Unix()
				client.ClientSecretExpiresAt = &expiresAt
			}
		}
	}
	return nil
}

func registrationScopes(scope string) []string {
	scopes := []string{"openid", "profile", "email", "address", "phone", "roles"}
	if scope == "" {
		return scopes
	}
	scopes = strings.Fields(scope)
	if !containsScope(strings.Join(scopes, " "), "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

func buildRegistrationResponse(client *models.Client, registrationAccessToken string) map[string]interface{} {
	resp := map[string]interface{}{
		"client_id":                    client.ID,
		"client_id_issued_at":          client.ClientIDIssuedAt,
		"client_name":                  client.Name,
		"redirect_uris":                client.RedirectURIs,
		"response_types":               client.ResponseTypes,
		"grant_types":                  client.GrantTypes,
		"application_type":             client.ApplicationType,
		"token_endpoint_auth_method":   client.TokenEndpointAuthMethod,
		"subject_type":                 client.SubjectType,
		"id_token_signed_response_alg": client.IDTokenSignedResponseAlg,
		"registration_client_uri":      client.RegistrationClientURI,
	}
	if registrationAccessToken != "" {
		resp["registration_access_token"] = registrationAccessToken
	}
	if client.Secret != "" {
		resp["client_secret"] = client.Secret
		if client.ClientSecretExpiresAt != nil {
			resp["client_secret_expires_at"] = *client.ClientSecretExpiresAt
		}
	}
	if len(client.Contacts) > 0 {
		resp["contacts"] = client.Contacts
	}
	if client.ClientURI != "" {
		resp["client_uri"] = client.ClientURI
	}
	if client.LogoURI != "" {
		resp["logo_uri"] = client.LogoURI
	}
	if client.PolicyURI != "" {
		resp["policy_uri"] = client.PolicyURI
	}
	if client.TosURI != "" {
		resp["tos_uri"] = client.TosURI
	}
	if client.JWKSURI != "" {
		resp["jwks_uri"] = client.JWKSURI
	}
	if client.JWKS != nil {
		resp["jwks"] = client.JWKS
	}
	if client.UserinfoSignedResponseAlg != "" {
		resp["userinfo_signed_response_alg"] = client.UserinfoSignedResponseAlg
	}
	if client.RequestObjectSigningAlg != "" {
		resp["request_object_signing_alg"] = client.RequestObjectSigningAlg
	}
	if client.TokenEndpointAuthSigningAlg != "" {
		resp["token_endpoint_auth_signing_alg"] = client.TokenEndpointAuthSigningAlg
	}
	if client.InitiateLoginURI != "" {
		resp["initiate_login_uri"] = client.InitiateLoginURI
	}
	if client.SectorIdentifierURI != "" {
		resp["sector_identifier_uri"] = client.SectorIdentifierURI
	}
	if client.DefaultMaxAge != nil {
		resp["default_max_age"] = *client.DefaultMaxAge
	}
	if client.RequireAuthTime {
		resp["require_auth_time"] = true
	}
	if len(client.Scopes) > 0 {
		resp["scope"] = strings.Join(client.Scopes, " ")
	}
	return resp
}

func writeRegistrationResponse(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeRegistrationValidationError(w http.ResponseWriter, err error) {
	if ve, ok := err.(*registrationValidationError); ok {
		writeRegistrationError(w, http.StatusBadRequest, ve.Code, ve.Description)
		return
	}
	writeRegistrationError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
}

func writeRegistrationError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeBearerError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+description+`"`)
	writeRegistrationError(w, status, code, description)
}

func bearerToken(header string) (string, bool) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

func hashRegistrationAccessToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func registrationAccessTokenMatches(client *models.Client, token string) bool {
	if client == nil || client.RegistrationAccessTokenHash == "" || token == "" {
		return false
	}
	return subtleConstantTimeEqual(client.RegistrationAccessTokenHash, hashRegistrationAccessToken(token))
}

func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randomURLString(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func registrationSourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
