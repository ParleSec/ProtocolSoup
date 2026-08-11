package mockidp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// AuthorizationCodeTTL is the lifetime of issued authorization codes.
// FAPI 2.0 Security Profile Final §5.3.2.1 clause 11 requires a maximum of
// 60 seconds (stricter than RFC 6749's recommended 10 minutes).
const AuthorizationCodeTTL = 60 * time.Second

// MockIdP provides a mock identity provider for demonstrations
type MockIdP struct {
	users          map[string]*models.User
	clients        map[string]*models.Client
	authCodes      map[string]*models.AuthorizationCode
	sessions       map[string]*models.Session
	refreshTokens  map[string]*models.RefreshToken
	revokedTokens  map[string]time.Time              // RFC 7009: Track revoked access tokens by JTI
	usedCodes      map[string]*usedAuthorizationCode // RFC 6749 Section 4.1.2: replayed-code detection and token revocation
	pushedRequests map[string]*PushedAuthorizationRequest
	keySet         *crypto.KeySet
	jwtService     *crypto.JWTService
	issuer         string
	defaultUserID  string
	pairwiseSalt   []byte
	mu             sync.RWMutex
}

// usedAuthorizationCode records an authorization code that has already been
// redeemed, together with the tokens minted from it. RFC 6749 Section 4.1.2
// requires the OP to deny a replayed code (MUST) and to revoke the tokens
// previously issued from that code (SHOULD); retaining this record lets the OP
// do both when the same code is presented a second time.
type usedAuthorizationCode struct {
	accessTokenJTIs []string
	refreshTokens   []string
	usedAt          time.Time
}

// PushedAuthorizationRequest is the validated RFC 9126 request state shared
// between the OID4VCI PAR endpoint and the OIDC authorization endpoint.
type PushedAuthorizationRequest struct {
	RequestURI                     string
	ClientID                       string
	RedirectURI                    string
	ResponseType                   string
	Scope                          string
	State                          string
	Nonce                          string
	CodeChallenge                  string
	CodeChallengeMethod            string
	CredentialConfigurationIDs     []string
	// AuthorizationDetailsUsed is true when the wallet supplied RFC 9396
	// authorization_details in the PAR. Scope-only OID4VCI requests leave this
	// false so the token endpoint does not invent an authorization_details
	// response (OID4VCI §6.2: OPTIONAL for scope).
	AuthorizationDetailsUsed       bool
	DPoPJKT                        string
	IssuerState                    string
	ExpiresAt                      time.Time
	AuthorizationResponseCompleted bool
}

// usedCodeRetention bounds how long a redeemed authorization code is remembered
// for replay detection. It matches the access-token lifetime: once the tokens a
// code minted have expired on their own, there is nothing left to revoke.
const usedCodeRetention = time.Hour

// NewMockIdP creates a new mock identity provider
func NewMockIdP(keySet *crypto.KeySet) *MockIdP {
	pairwiseSalt := make([]byte, 32)
	if _, err := rand.Read(pairwiseSalt); err != nil {
		panic("generate pairwise subject salt: " + err.Error())
	}
	idp := &MockIdP{
		users:          make(map[string]*models.User),
		clients:        make(map[string]*models.Client),
		authCodes:      make(map[string]*models.AuthorizationCode),
		sessions:       make(map[string]*models.Session),
		refreshTokens:  make(map[string]*models.RefreshToken),
		revokedTokens:  make(map[string]time.Time),              // RFC 7009: Revoked token tracking
		usedCodes:      make(map[string]*usedAuthorizationCode), // RFC 6749 Section 4.1.2: replayed-code detection
		pushedRequests: make(map[string]*PushedAuthorizationRequest),
		keySet:         keySet,
		issuer:         "http://localhost:8080",
		pairwiseSalt:   pairwiseSalt,
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

// SetPairwiseSubjectSalt installs the durable provider secret used to derive
// pairwise subject identifiers. Callers must supply a stable secret for a
// production deployment so subject values survive process restarts.
func (idp *MockIdP) SetPairwiseSubjectSalt(salt string) {
	if strings.TrimSpace(salt) == "" {
		return
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.pairwiseSalt = []byte(salt)
}

// SubjectForClient returns the public or pairwise subject identifier visible to
// a client. Pairwise identifiers follow OIDC Core Section 8.1's salted
// SHA-256 construction and are deterministic for a user and sector.
func (idp *MockIdP) SubjectForClient(client *models.Client, userID string) (string, error) {
	if client == nil || client.SubjectType != "pairwise" {
		return userID, nil
	}
	sector, err := sectorIdentifier(client)
	if err != nil {
		return "", err
	}
	idp.mu.RLock()
	salt := append([]byte(nil), idp.pairwiseSalt...)
	idp.mu.RUnlock()
	hash := sha256.Sum256([]byte(sector + "\x00" + userID + "\x00" + string(salt)))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ResolveUserIDForSubject maps a public or pairwise access-token subject back
// to the canonical local user identifier for UserInfo claim lookup.
func (idp *MockIdP) ResolveUserIDForSubject(client *models.Client, subject string) (string, bool) {
	if client == nil {
		return "", false
	}
	if client.SubjectType != "pairwise" {
		_, exists := idp.GetUser(subject)
		return subject, exists
	}
	idp.mu.RLock()
	userIDs := make([]string, 0, len(idp.users))
	for userID := range idp.users {
		userIDs = append(userIDs, userID)
	}
	idp.mu.RUnlock()
	for _, userID := range userIDs {
		candidate, err := idp.SubjectForClient(client, userID)
		if err == nil && subtle.ConstantTimeCompare([]byte(candidate), []byte(subject)) == 1 {
			return userID, true
		}
	}
	return "", false
}

func sectorIdentifier(client *models.Client) (string, error) {
	if client == nil {
		return "", errors.New("client is required")
	}
	if client.SectorIdentifierURI != "" {
		parsed, err := url.Parse(client.SectorIdentifierURI)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("invalid sector_identifier_uri")
		}
		return strings.ToLower(parsed.Hostname()), nil
	}
	if len(client.RedirectURIs) == 0 {
		return "", errors.New("pairwise client has no redirect_uris")
	}
	parsed, err := url.Parse(client.RedirectURIs[0])
	if err != nil || parsed.Hostname() == "" {
		return "", errors.New("invalid redirect_uri for pairwise subject")
	}
	sector := strings.ToLower(parsed.Hostname())
	for _, raw := range client.RedirectURIs[1:] {
		parsed, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(parsed.Hostname(), sector) {
			return "", errors.New("pairwise client has multiple redirect URI hosts without sector_identifier_uri")
		}
	}
	return sector, nil
}

// initDemoData initializes demo users and clients
func (idp *MockIdP) initDemoData() {
	alicePassword := envOrRandom("MOCKIDP_ALICE_PASSWORD", 24)
	bobPassword := envOrRandom("MOCKIDP_BOB_PASSWORD", 24)
	adminPassword := envOrRandom("MOCKIDP_ADMIN_PASSWORD", 24)
	demoClientSecret := envOrRandom("MOCKIDP_DEMO_CLIENT_SECRET", 32)
	machineClientSecret := envOrRandom("MOCKIDP_MACHINE_CLIENT_SECRET", 32)

	// Demo users
	alice := &models.User{
		ID:                  "alice",
		Email:               "alice@example.com",
		Name:                "Alice Johnson",
		GivenName:           "Alice",
		FamilyName:          "Johnson",
		MiddleName:          "Marie",
		Nickname:            "Ali",
		Profile:             "https://www.protocolsoup.com/u/alice",
		Picture:             "https://www.protocolsoup.com/u/alice/avatar.png",
		Website:             "https://alice.example.com",
		Gender:              "female",
		Birthdate:           "1990-03-12",
		Zoneinfo:            "Australia/Sydney",
		Locale:              "en-AU",
		PhoneNumber:         "+61 2 5550 1234",
		PhoneNumberVerified: true,
		Address: &models.Address{
			Formatted:     "12 Wattle Street\nSydney NSW 2000\nAustralia",
			StreetAddress: "12 Wattle Street",
			Locality:      "Sydney",
			Region:        "NSW",
			PostalCode:    "2000",
			Country:       "Australia",
		},
		Password: alicePassword, // In a real system, this would be hashed
		Roles:    []string{"user"},
		Claims: map[string]string{
			"department":                  "Engineering",
			"degree":                      "Bachelor of Engineering",
			"graduation_year":             "2018",
			"mdl_document_number":         "D-ALICE-001",
			"mdl_driving_privilege_codes": "B",
		},
		CreatedAt: time.Now(),
	}
	idp.users[alice.ID] = alice
	idp.defaultUserID = alice.ID

	idp.users["bob"] = &models.User{
		ID:                  "bob",
		Email:               "bob@example.com",
		Name:                "Bob Smith",
		GivenName:           "Bob",
		FamilyName:          "Smith",
		MiddleName:          "Daniel",
		Nickname:            "Bobby",
		Profile:             "https://www.protocolsoup.com/u/bob",
		Picture:             "https://www.protocolsoup.com/u/bob/avatar.png",
		Website:             "https://bob.example.com",
		Gender:              "male",
		Birthdate:           "1985-07-23",
		Zoneinfo:            "Australia/Melbourne",
		Locale:              "en-AU",
		PhoneNumber:         "+61 3 5550 5678",
		PhoneNumberVerified: true,
		Address: &models.Address{
			Formatted:     "48 Collins Street\nMelbourne VIC 3000\nAustralia",
			StreetAddress: "48 Collins Street",
			Locality:      "Melbourne",
			Region:        "VIC",
			PostalCode:    "3000",
			Country:       "Australia",
		},
		Password: bobPassword,
		Roles:    []string{"user"},
		Claims: map[string]string{
			"department":                  "Marketing",
			"degree":                      "Bachelor of Commerce",
			"graduation_year":             "2007",
			"mdl_document_number":         "D-BOB-001",
			"mdl_driving_privilege_codes": "B",
		},
		CreatedAt: time.Now(),
	}

	idp.users["admin"] = &models.User{
		ID:                  "admin",
		Email:               "admin@example.com",
		Name:                "Admin User",
		GivenName:           "Admin",
		FamilyName:          "User",
		MiddleName:          "System",
		Nickname:            "Admin",
		Profile:             "https://www.protocolsoup.com/u/admin",
		Picture:             "https://www.protocolsoup.com/u/admin/avatar.png",
		Website:             "https://www.protocolsoup.com",
		Gender:              "other",
		Birthdate:           "1980-11-05",
		Zoneinfo:            "Australia/Brisbane",
		Locale:              "en-AU",
		PhoneNumber:         "+61 7 5550 9012",
		PhoneNumberVerified: true,
		Address: &models.Address{
			Formatted:     "300 Queen Street\nBrisbane QLD 4000\nAustralia",
			StreetAddress: "300 Queen Street",
			Locality:      "Brisbane",
			Region:        "QLD",
			PostalCode:    "4000",
			Country:       "Australia",
		},
		Password: adminPassword,
		Roles:    []string{"user", "admin"},
		Claims: map[string]string{
			"department":                  "IT",
			"degree":                      "Bachelor of Information Technology",
			"graduation_year":             "2002",
			"mdl_document_number":         "D-ADMIN-001",
			"mdl_driving_privilege_codes": "B",
		},
		CreatedAt: time.Now(),
	}

	// Demo OAuth clients
	// Note: Redirect URIs include local development, Fly.io, and custom domain URLs
	idp.clients["demo-app"] = &models.Client{
		ID:     "demo-app",
		Secret: demoClientSecret,
		Name:   "Demo Application",
		RedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:5173/callback",
			"http://localhost:4174/api/oid4vci/callback",
			"http://localhost:8080/api/oid4vci/callback",
			"https://protocolsoup.com/callback",
			"https://www.protocolsoup.com/callback",
			"https://protocolsoup.fly.dev/callback",
			"https://wallet.protocolsoup.com/api/oid4vci/callback",
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
			"http://localhost:4174/api/oid4vci/callback",
			"http://localhost:8080/api/oid4vci/callback",
			"https://protocolsoup.com/callback",
			"https://www.protocolsoup.com/callback",
			"https://protocolsoup.fly.dev/callback",
			"https://wallet.protocolsoup.com/api/oid4vci/callback",
		},
		GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes:     []string{"openid", "profile", "email"},
		Public:     true,
		CreatedAt:  time.Now(),
	}

	idp.clients["machine-client"] = &models.Client{
		ID:           "machine-client",
		Secret:       machineClientSecret,
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

// DefaultUserID returns the seeded identity used by interactive demo flows when
// the caller does not select a specific identity.
func (idp *MockIdP) DefaultUserID() string {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	return idp.defaultUserID
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
	client, exists := idp.clients[id]
	if !exists || !clientRegistrationExpired(client, time.Now()) {
		idp.mu.RUnlock()
		return client, exists
	}
	idp.mu.RUnlock()

	idp.mu.Lock()
	defer idp.mu.Unlock()
	client, exists = idp.clients[id]
	if exists && clientRegistrationExpired(client, time.Now()) {
		delete(idp.clients, id)
		return nil, false
	}
	return client, exists
}

func clientRegistrationExpired(client *models.Client, now time.Time) bool {
	return client != nil && client.ExpiresAt != nil && !client.ExpiresAt.After(now)
}

// RegisterClient adds or replaces a client registration. It is used to
// provision conformance clients at startup; it does not relax any validation,
// the registered redirect URIs are still matched exactly at the authorization
// endpoint.
func (idp *MockIdP) RegisterClient(client *models.Client) {
	if client == nil || client.ID == "" {
		return
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now()
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.clients[client.ID] = client
}

// DeleteClient removes a client registration. It is used by dynamic-registration
// cleanup and does not affect other stores.
func (idp *MockIdP) DeleteClient(id string) bool {
	if id == "" {
		return false
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if _, exists := idp.clients[id]; !exists {
		return false
	}
	delete(idp.clients, id)
	return true
}

// CountDynamicClients returns the number of non-expired dynamically registered
// clients currently held in memory.
func (idp *MockIdP) CountDynamicClients() int {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, client := range idp.clients {
		if client == nil || !client.Dynamic {
			continue
		}
		if clientRegistrationExpired(client, now) {
			continue
		}
		count++
	}
	return count
}

// FindClientByRegistrationAccessTokenHash returns the dynamic client whose
// hashed registration access token matches the supplied hash.
func (idp *MockIdP) FindClientByRegistrationAccessTokenHash(tokenHash string) (*models.Client, bool) {
	if tokenHash == "" {
		return nil, false
	}
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	now := time.Now()
	for _, client := range idp.clients {
		if client == nil || client.RegistrationAccessTokenHash == "" {
			continue
		}
		if clientRegistrationExpired(client, now) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(client.RegistrationAccessTokenHash), []byte(tokenHash)) == 1 {
			return client, true
		}
	}
	return nil, false
}

// ValidateClient validates client credentials
func (idp *MockIdP) ValidateClient(clientID, clientSecret string) (*models.Client, error) {
	client, exists := idp.GetClient(clientID)
	if !exists {
		return nil, errors.New("client not found")
	}
	if !client.Public && (client.Secret == "" || client.Secret != clientSecret) {
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

// NormalizeRedirectURI returns the registered redirect URI if it matches exactly
func (idp *MockIdP) NormalizeRedirectURI(clientID, redirectURI string) (string, error) {
	client, exists := idp.GetClient(clientID)
	if !exists {
		return "", errors.New("client not found")
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return uri, nil
		}
	}
	return "", errors.New("invalid redirect_uri")
}

// CreateAuthorizationCode creates and stores an authorization code
// Validates PKCE code_challenge per RFC 7636 Section 4.2 if provided
// authTime records when the End-User authenticated; it is propagated into the
// ID Token auth_time claim (OpenID Connect Core 1.0 Section 2). Callers that do
// not track a distinct authentication time pass the current time.
// claims is the raw OIDC claims request parameter (OpenID Connect Core 1.0
// Section 5.5), stored so individually requested claims can be honoured when the
// code is exchanged for tokens. Callers not using it pass an empty string.
func (idp *MockIdP) CreateAuthorizationCode(
	clientID, userID, redirectURI, scope, state, nonce string,
	codeChallenge, codeChallengeMethod, claims string,
	authTime time.Time,
) (*models.AuthorizationCode, error) {
	// Validate PKCE code_challenge if provided (RFC 7636 Section 4.2)
	if codeChallenge != "" {
		if err := ValidatePKCEChallenge(codeChallenge, codeChallengeMethod); err != nil {
			return nil, err
		}
	}

	code := generateRandomString(32)

	if authTime.IsZero() {
		authTime = time.Now()
	}

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
		Claims:              claims,
		AuthTime:            authTime,
		ExpiresAt:           time.Now().Add(AuthorizationCodeTTL),
		CreatedAt:           time.Now(),
	}

	idp.mu.Lock()
	idp.authCodes[code] = authCode
	idp.mu.Unlock()

	return authCode, nil
}

// StorePushedAuthorizationRequest stores a fully validated RFC 9126 request and
// returns its opaque urn:ietf:params:oauth:request_uri handle.
func (idp *MockIdP) StorePushedAuthorizationRequest(request PushedAuthorizationRequest) string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	requestURI := "urn:ietf:params:oauth:request_uri:" + generateRandomString(32)
	request.RequestURI = requestURI
	request.CredentialConfigurationIDs = append([]string(nil), request.CredentialConfigurationIDs...)
	idp.pushedRequests[requestURI] = &request
	return requestURI
}

// GetPushedAuthorizationRequest resolves a PAR handle without consuming it.
// RFC 9126 permits retries before the authorization interaction completes.
func (idp *MockIdP) GetPushedAuthorizationRequest(requestURI, clientID string) (*PushedAuthorizationRequest, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	now := time.Now()
	for uri, request := range idp.pushedRequests {
		if now.After(request.ExpiresAt) {
			delete(idp.pushedRequests, uri)
		}
	}
	request, exists := idp.pushedRequests[requestURI]
	if !exists {
		return nil, errors.New("invalid or expired request_uri")
	}
	if request.AuthorizationResponseCompleted {
		return nil, errors.New("request_uri has already completed authorization")
	}
	if strings.TrimSpace(clientID) != "" && request.ClientID != strings.TrimSpace(clientID) {
		return nil, errors.New("request_uri client mismatch")
	}
	copy := *request
	copy.CredentialConfigurationIDs = append([]string(nil), request.CredentialConfigurationIDs...)
	return &copy, nil
}

// CompletePushedAuthorizationRequest prevents a PAR handle from starting a
// second authorization after the first response has been issued.
func (idp *MockIdP) CompletePushedAuthorizationRequest(requestURI string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if request := idp.pushedRequests[requestURI]; request != nil {
		request.AuthorizationResponseCompleted = true
	}
}

// BindCredentialAuthorizationDetails records the OID4VCI authorization details
// that were approved with an authorization code. The binding is made while the
// code is still live so the OID4VCI token endpoint can issue access-token-bound
// credential_identifiers for exactly those Credential Configurations.
func (idp *MockIdP) BindCredentialAuthorizationDetails(code string, credentialConfigurationIDs []string) error {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	authCode, exists := idp.authCodes[code]
	if !exists {
		return errors.New("authorization code not found")
	}
	authCode.CredentialConfigurationIDs = append([]string(nil), credentialConfigurationIDs...)
	authCode.CredentialAuthorizationDetailsUsed = true
	return nil
}

// BindCredentialConfigurationIDs records Credential Configurations authorized
// via scope (without RFC 9396 authorization_details). The token endpoint may
// issue an access token bound to these configurations without returning
// authorization_details / credential_identifiers.
func (idp *MockIdP) BindCredentialConfigurationIDs(code string, credentialConfigurationIDs []string) error {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	authCode, exists := idp.authCodes[code]
	if !exists {
		return errors.New("authorization code not found")
	}
	authCode.CredentialConfigurationIDs = append([]string(nil), credentialConfigurationIDs...)
	authCode.CredentialAuthorizationDetailsUsed = false
	return nil
}

// BindAuthorizationCodeDPoP records the PAR DPoP key on the authorization code
// so the token endpoint can enforce sender-constrained code redemption.
func (idp *MockIdP) BindAuthorizationCodeDPoP(code, jkt string) error {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	authCode, exists := idp.authCodes[code]
	if !exists {
		return errors.New("authorization code not found")
	}
	authCode.DPoPJKT = strings.TrimSpace(jkt)
	return nil
}

// BindAuthorizationCodeIssuerState carries the OpenID4VCI issuer-created
// processing context from the validated PAR request into code redemption.
func (idp *MockIdP) BindAuthorizationCodeIssuerState(code, issuerState string) error {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	authCode, exists := idp.authCodes[code]
	if !exists {
		return errors.New("authorization code not found")
	}
	authCode.IssuerState = strings.TrimSpace(issuerState)
	return nil
}

// GetAuthorizationCode returns a defensive copy of a live authorization code
// without consuming it. Protocol extensions use this only to select the
// security policy that must be applied before redemption; ValidateAuthorizationCode
// remains the sole operation that validates and atomically consumes the code.
func (idp *MockIdP) GetAuthorizationCode(code string) (*models.AuthorizationCode, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	authCode, exists := idp.authCodes[strings.TrimSpace(code)]
	if !exists || authCode == nil {
		return nil, false
	}
	copy := *authCode
	copy.CredentialConfigurationIDs = append([]string(nil), authCode.CredentialConfigurationIDs...)
	return &copy, true
}

// ValidateAuthorizationCode validates and consumes an authorization code
func (idp *MockIdP) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	idp.pruneUsedCodesLocked()

	authCode, exists := idp.authCodes[code]
	if !exists {
		// RFC 6749 Section 4.1.2: an authorization code presented more than once
		// MUST be denied, and the OP SHOULD revoke the tokens it previously issued
		// from that code. A code that is gone from authCodes but recorded in
		// usedCodes is exactly such a replay, so the access tokens it minted are
		// revoked (by JTI) and any refresh token dropped before the denial.
		if used, replayed := idp.usedCodes[code]; replayed {
			for _, jti := range used.accessTokenJTIs {
				idp.revokedTokens[jti] = time.Now()
			}
			for _, rt := range used.refreshTokens {
				delete(idp.refreshTokens, rt)
			}
			return nil, errors.New("authorization code already used")
		}
		return nil, errors.New("invalid authorization code")
	}

	// Reject expired codes before consuming them (RFC 6749 §4.1.2;
	// FAPI2 SP Final §5.3.2.1-11 caps lifetime at AuthorizationCodeTTL).
	if !authCode.ExpiresAt.After(time.Now()) {
		delete(idp.authCodes, code)
		return nil, errors.New("authorization code expired")
	}

	// Bind the code to the issuing client and redirect_uri before consuming
	// it. A mismatched client must not burn the legitimate client's code
	// (OIDCC §3.1.3.4 / FAPI2 SP §5.3.2.1).
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

	// Consume only after every binding check succeeds (one-time use).
	delete(idp.authCodes, code)

	// Remember the redeemed code so a later replay is detected and the tokens it
	// produces can be revoked (RFC 6749 Section 4.1.2). RecordIssuedTokens fills
	// in the token identifiers once issuance succeeds; recording the code here
	// (rather than at issuance) closes the window between consumption and
	// issuance during which a concurrent replay could otherwise slip through.
	idp.usedCodes[code] = &usedAuthorizationCode{usedAt: time.Now()}

	return authCode, nil
}

// RecordIssuedTokens binds the tokens minted from an authorization code to that
// code's replay-detection record. If the code is later replayed,
// ValidateAuthorizationCode revokes exactly these tokens (RFC 6749 Section
// 4.1.2). Calling it with an empty code is a no-op, so test fixtures that build
// an AuthorizationCode without a Code value are unaffected.
func (idp *MockIdP) RecordIssuedTokens(code, accessToken, refreshToken string) {
	if code == "" {
		return
	}

	// Resolve the access token's JTI so the exact token can be revoked later;
	// revocation is tracked by JTI to match RevokeAccessToken/IsTokenRevoked.
	// ValidateToken does not touch idp state, so it is safe before the lock.
	jti := accessToken
	if claims, err := idp.jwtService.ValidateToken(accessToken); err == nil {
		if v, ok := claims["jti"].(string); ok && v != "" {
			jti = v
		}
	}

	idp.mu.Lock()
	defer idp.mu.Unlock()
	used, ok := idp.usedCodes[code]
	if !ok {
		// The record was pruned (or never created); recreate it so a replay can
		// still revoke this token.
		used = &usedAuthorizationCode{usedAt: time.Now()}
		idp.usedCodes[code] = used
	}
	if jti != "" {
		used.accessTokenJTIs = append(used.accessTokenJTIs, jti)
	}
	if refreshToken != "" {
		used.refreshTokens = append(used.refreshTokens, refreshToken)
	}
}

// pruneUsedCodesLocked drops redeemed-code records older than usedCodeRetention.
// The caller must hold idp.mu. Pruning opportunistically on each redemption
// bounds memory without a background goroutine.
func (idp *MockIdP) pruneUsedCodesLocked() {
	cutoff := time.Now().Add(-usedCodeRetention)
	for code, used := range idp.usedCodes {
		if used.usedAt.Before(cutoff) {
			delete(idp.usedCodes, code)
		}
	}
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

// StoreRefreshToken stores a refresh token. authTime is the original End-User
// authentication time, preserved so a refreshed ID Token carries the same
// auth_time as the original (OpenID Connect Core 1.0 Section 12.2).
func (idp *MockIdP) StoreRefreshToken(token, clientID, userID, scope string, authTime, expiresAt time.Time) {
	if authTime.IsZero() {
		authTime = time.Now()
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.refreshTokens[token] = &models.RefreshToken{
		Token:     token,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		AuthTime:  authTime,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// BindRefreshTokenKey associates a DPoP jkt with an already-stored refresh
// token (RFC 9449 Section 5: a refresh token issued alongside a DPoP-bound
// access token remains bound to that same key on later redemptions). Callers
// invoke this immediately after StoreRefreshToken rather than threading a
// jkt parameter through it, so every existing StoreRefreshToken call site
// (including outside the oauth2 plugin) is unaffected. A no-op if jkt is
// empty or the token is no longer present.
func (idp *MockIdP) BindRefreshTokenKey(token, jkt string) {
	if jkt == "" {
		return
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if rt, exists := idp.refreshTokens[token]; exists {
		rt.JKT = jkt
	}
}

// BindRefreshTokenClientInstanceKey associates an OAuth client-attestation
// Client Instance Key thumbprint with an already-stored refresh token
// (draft-ietf-oauth-attestation-based-client-auth §9.3). Later refresh
// requests MUST present attestation for that same instance key.
func (idp *MockIdP) BindRefreshTokenClientInstanceKey(token, instanceJKT string) {
	if instanceJKT == "" {
		return
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if rt, exists := idp.refreshTokens[token]; exists {
		rt.ClientInstanceJKT = instanceJKT
	}
}

// GetRefreshToken returns a defensive copy of a live refresh token without
// consuming it. Binding checks (DPoP jkt, Client Instance Key) run against
// this snapshot before ValidateRefreshToken rotates the token.
func (idp *MockIdP) GetRefreshToken(token string) (*models.RefreshToken, bool) {
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	rt, exists := idp.refreshTokens[strings.TrimSpace(token)]
	if !exists || rt == nil {
		return nil, false
	}
	if rt.ExpiresAt.Before(time.Now()) {
		return nil, false
	}
	copy := *rt
	return &copy, true
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

	// Implement refresh token rotation - delete old token. Return a copy so
	// binding fields remain available to the caller after removal.
	copy := *rt
	delete(idp.refreshTokens, token)

	return &copy, nil
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
	idp.mu.Lock()
	defer idp.mu.Unlock()
	now := time.Now()
	clients := make([]*models.Client, 0, len(idp.clients))
	for id, c := range idp.clients {
		if clientRegistrationExpired(c, now) {
			delete(idp.clients, id)
			continue
		}
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

func envOrRandom(envKey string, length int) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return generateRandomString(length)
}
