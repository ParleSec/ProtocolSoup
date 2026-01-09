package mockidp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// MockIdP provides a mock identity provider for demonstrations
type MockIdP struct {
	users         map[string]*models.User
	clients       map[string]*models.Client
	authCodes     map[string]*models.AuthorizationCode
	sessions      map[string]*models.Session
	refreshTokens map[string]*models.RefreshToken
	revokedTokens map[string]time.Time // RFC 7009: Track revoked access tokens by JTI
	keySet        *crypto.KeySet
	jwtService    *crypto.JWTService
	issuer        string
	mu            sync.RWMutex
}

// NewMockIdP creates a new mock identity provider
func NewMockIdP(keySet *crypto.KeySet) *MockIdP {
	idp := &MockIdP{
		users:         make(map[string]*models.User),
		clients:       make(map[string]*models.Client),
		authCodes:     make(map[string]*models.AuthorizationCode),
		sessions:      make(map[string]*models.Session),
		refreshTokens: make(map[string]*models.RefreshToken),
		revokedTokens: make(map[string]time.Time), // RFC 7009: Revoked token tracking
		keySet:        keySet,
		issuer:        "http://localhost:8080",
	}

	idp.jwtService = crypto.NewJWTService(keySet, idp.issuer)

	// Initialize demo users and clients
	idp.initDemoData()

	return idp
}

// SetIssuer sets the issuer URL
func (idp *MockIdP) SetIssuer(issuer string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.issuer = issuer
	idp.jwtService = crypto.NewJWTService(idp.keySet, issuer)
}

// GetIssuer returns the issuer URL
func (idp *MockIdP) GetIssuer() string {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	return idp.issuer
}

// initDemoData initializes demo users and clients
func (idp *MockIdP) initDemoData() {
	// Demo users
	idp.users["alice"] = &models.User{
		ID:       "alice",
		Email:    "alice@example.com",
		Name:     "Alice Johnson",
		Password: "password123", // In a real system, this would be hashed
		Roles:    []string{"user"},
		Claims: map[string]string{
			"department": "Engineering",
		},
		CreatedAt: time.Now(),
	}

	idp.users["bob"] = &models.User{
		ID:       "bob",
		Email:    "bob@example.com",
		Name:     "Bob Smith",
		Password: "password123",
		Roles:    []string{"user"},
		Claims: map[string]string{
			"department": "Marketing",
		},
		CreatedAt: time.Now(),
	}

	idp.users["admin"] = &models.User{
		ID:       "admin",
		Email:    "admin@example.com",
		Name:     "Admin User",
		Password: "admin123",
		Roles:    []string{"user", "admin"},
		Claims: map[string]string{
			"department": "IT",
		},
		CreatedAt: time.Now(),
	}

	// Demo OAuth clients
	// Note: Redirect URIs include local development, Fly.io, and custom domain URLs
	idp.clients["demo-app"] = &models.Client{
		ID:     "demo-app",
		Secret: "demo-secret",
		Name:   "Demo Application",
		RedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:5173/callback",
			"https://protocolsoup.com/callback",
			"https://www.protocolsoup.com/callback",
			"https://protocolsoup.fly.dev/callback",
		},
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile", "email"},
		Public:     false,
		CreatedAt:  time.Now(),
	}

	idp.clients["public-app"] = &models.Client{
		ID:     "public-app",
		Secret: "",
		Name:   "Public Application (SPA)",
		RedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:5173/callback",
			"https://protocolsoup.com/callback",
			"https://www.protocolsoup.com/callback",
			"https://protocolsoup.fly.dev/callback",
		},
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile", "email"},
		Public:     true,
		CreatedAt:  time.Now(),
	}

	idp.clients["machine-client"] = &models.Client{
		ID:           "machine-client",
		Secret:       "machine-secret",
		Name:         "Machine-to-Machine Client",
		RedirectURIs: []string{},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"api:read", "api:write"},
		Public:       false,
		CreatedAt:    time.Now(),
	}
}

// GetUser retrieves a user by ID
func (idp *MockIdP) GetUser(id string) (*models.User, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	user, exists := idp.users[id]
	return user, exists
}

// GetUserByEmail retrieves a user by email
func (idp *MockIdP) GetUserByEmail(email string) (*models.User, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	for _, user := range idp.users {
		if user.Email == email {
			return user, true
		}
	}
	return nil, false
}

// ValidateCredentials validates user credentials
func (idp *MockIdP) ValidateCredentials(email, password string) (*models.User, error) {
	user, exists := idp.GetUserByEmail(email)
	if !exists {
		return nil, errors.New("user not found")
	}
	if user.Password != password {
		return nil, errors.New("invalid password")
	}
	return user, nil
}

// GetClient retrieves a client by ID
func (idp *MockIdP) GetClient(id string) (*models.Client, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	client, exists := idp.clients[id]
	return client, exists
}

// ValidateClient validates client credentials
func (idp *MockIdP) ValidateClient(clientID, clientSecret string) (*models.Client, error) {
	client, exists := idp.GetClient(clientID)
	if !exists {
		return nil, errors.New("client not found")
	}
	if !client.Public && client.Secret != clientSecret {
		return nil, errors.New("invalid client secret")
	}
	return client, nil
}

// ValidateRedirectURI validates a redirect URI for a client
func (idp *MockIdP) ValidateRedirectURI(clientID, redirectURI string) bool {
	client, exists := idp.GetClient(clientID)
	if !exists {
		return false
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// CreateAuthorizationCode creates and stores an authorization code
// Validates PKCE code_challenge per RFC 7636 Section 4.2 if provided
func (idp *MockIdP) CreateAuthorizationCode(
	clientID, userID, redirectURI, scope, state, nonce string,
	codeChallenge, codeChallengeMethod string,
) (*models.AuthorizationCode, error) {
	// Validate PKCE code_challenge if provided (RFC 7636 Section 4.2)
	if codeChallenge != "" {
		if err := ValidatePKCEChallenge(codeChallenge, codeChallengeMethod); err != nil {
			return nil, err
		}
	}

	code := generateRandomString(32)

	authCode := &models.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
	}

	idp.mu.Lock()
	idp.authCodes[code] = authCode
	idp.mu.Unlock()

	return authCode, nil
}

// ValidateAuthorizationCode validates and consumes an authorization code
func (idp *MockIdP) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	authCode, exists := idp.authCodes[code]
	if !exists {
		return nil, errors.New("invalid authorization code")
	}

	// Delete code (one-time use)
	delete(idp.authCodes, code)

	if authCode.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("authorization code expired")
	}

	if authCode.ClientID != clientID {
		return nil, errors.New("client ID mismatch")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	// Validate PKCE if code challenge was provided (RFC 7636)
	if authCode.CodeChallenge != "" {
		if err := ValidatePKCEWithError(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			// Return specific PKCE error for RFC 7636 compliance
			return nil, err
		}
	}

	return authCode, nil
}

// CreateSession creates a new session
func (idp *MockIdP) CreateSession(userID, clientID string) *models.Session {
	session := &models.Session{
		ID:        generateRandomString(32),
		UserID:    userID,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	idp.mu.Lock()
	idp.sessions[session.ID] = session
	idp.mu.Unlock()

	return session
}

// GetSession retrieves a session by ID
func (idp *MockIdP) GetSession(id string) (*models.Session, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	session, exists := idp.sessions[id]
	if exists && session.ExpiresAt.Before(time.Now()) {
		return nil, false
	}
	return session, exists
}

// StoreRefreshToken stores a refresh token
func (idp *MockIdP) StoreRefreshToken(token, clientID, userID, scope string, expiresAt time.Time) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.refreshTokens[token] = &models.RefreshToken{
		Token:     token,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// ValidateRefreshToken validates a refresh token
func (idp *MockIdP) ValidateRefreshToken(token, clientID string) (*models.RefreshToken, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	rt, exists := idp.refreshTokens[token]
	if !exists {
		return nil, errors.New("invalid refresh token")
	}

	if rt.ExpiresAt.Before(time.Now()) {
		delete(idp.refreshTokens, token)
		return nil, errors.New("refresh token expired")
	}

	if rt.ClientID != clientID {
		return nil, errors.New("client ID mismatch")
	}

	// Implement refresh token rotation - delete old token
	delete(idp.refreshTokens, token)

	return rt, nil
}

// RevokeRefreshToken revokes a refresh token
func (idp *MockIdP) RevokeRefreshToken(token string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	delete(idp.refreshTokens, token)
}

// RevokeAccessToken revokes an access token by its JTI claim per RFC 7009
// The token string can be either the JTI directly or the full JWT token
func (idp *MockIdP) RevokeAccessToken(token string) error {
	// Try to extract JTI from JWT token
	jti := token
	claims, err := idp.jwtService.ValidateToken(token)
	if err == nil {
		// Token is a valid JWT, extract JTI
		if jtiClaim, ok := claims["jti"].(string); ok {
			jti = jtiClaim
		}
	}
	// If not a valid JWT, treat the token string as the JTI itself

	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.revokedTokens[jti] = time.Now()
	return nil
}

// IsTokenRevoked checks if an access token has been revoked per RFC 7009
func (idp *MockIdP) IsTokenRevoked(token string) bool {
	// Try to extract JTI from JWT token
	jti := token
	claims, err := idp.jwtService.ValidateToken(token)
	if err == nil {
		if jtiClaim, ok := claims["jti"].(string); ok {
			jti = jtiClaim
		}
	}

	idp.mu.RLock()
	defer idp.mu.RUnlock()
	_, revoked := idp.revokedTokens[jti]
	return revoked
}

// RevokeToken revokes a token regardless of type per RFC 7009 Section 2.1
// This is the preferred method - token_type_hint is advisory only
func (idp *MockIdP) RevokeToken(token, tokenTypeHint string) {
	// RFC 7009 Section 2.1: The authorization server first validates the client credentials
	// (if provided) and then verifies whether the token was issued to the client making the request.
	// Per RFC 7009 Section 2.1, the server SHOULD attempt to determine the type
	// even if the hint is incorrect or not provided.

	// Try refresh token first if hinted or no hint provided
	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		idp.mu.Lock()
		if _, exists := idp.refreshTokens[token]; exists {
			delete(idp.refreshTokens, token)
			idp.mu.Unlock()
			return
		}
		idp.mu.Unlock()
	}

	// Try access token (always attempt per RFC 7009)
	// Ignore error - revocation is best-effort per RFC 7009 Section 2.2
	_ = idp.RevokeAccessToken(token)

	// Also try refresh token if hint was access_token (hint may be wrong)
	if tokenTypeHint == "access_token" {
		idp.mu.Lock()
		delete(idp.refreshTokens, token)
		idp.mu.Unlock()
	}
}

// CleanupRevokedTokens removes expired entries from the revoked tokens list
// This should be called periodically to prevent memory growth
func (idp *MockIdP) CleanupRevokedTokens(maxAge time.Duration) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for jti, revokedAt := range idp.revokedTokens {
		if revokedAt.Before(cutoff) {
			delete(idp.revokedTokens, jti)
		}
	}
}

// JWTService returns the JWT service
func (idp *MockIdP) JWTService() *crypto.JWTService {
	return idp.jwtService
}

// KeySet returns the key set
func (idp *MockIdP) KeySet() *crypto.KeySet {
	return idp.keySet
}

// ListUsers returns all demo users (for the UI)
func (idp *MockIdP) ListUsers() []*models.User {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	users := make([]*models.User, 0, len(idp.users))
	for _, u := range idp.users {
		users = append(users, u)
	}
	return users
}

// ListClients returns all registered clients (for the UI)
func (idp *MockIdP) ListClients() []*models.Client {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	clients := make([]*models.Client, 0, len(idp.clients))
	for _, c := range idp.clients {
		clients = append(clients, c)
	}
	return clients
}

// Helper functions

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}
