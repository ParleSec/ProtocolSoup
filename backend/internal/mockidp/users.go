package mockidp

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"time"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// UserClaims returns OIDC claims for a user
func (idp *MockIdP) UserClaims(userID string, scopes []string) map[string]interface{} {
	user, exists := idp.GetUser(userID)
	if !exists {
		return nil
	}

	claims := make(map[string]interface{})

	// Always include sub
	claims["sub"] = user.ID

	// Check scopes and include appropriate claims
	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims["name"] = user.Name
			claims["preferred_username"] = user.ID
			claims["updated_at"] = user.CreatedAt.Unix()
			// The remaining profile-scope claims (OIDC Core 1.0 Section 5.4) are
			// emitted for every value the user record holds. Section 5.4 states it
			// is not an error if the End-User lacks a value, so empty fields are
			// omitted rather than returned blank.
			for claim, value := range map[string]string{
				"given_name":  user.GivenName,
				"family_name": user.FamilyName,
				"middle_name": user.MiddleName,
				"nickname":    user.Nickname,
				"profile":     user.Profile,
				"picture":     user.Picture,
				"website":     user.Website,
				"gender":      user.Gender,
				"birthdate":   user.Birthdate,
				"zoneinfo":    user.Zoneinfo,
				"locale":      user.Locale,
			} {
				if value != "" {
					claims[claim] = value
				}
			}
		case "email":
			claims["email"] = user.Email
			claims["email_verified"] = true // Demo assumes verified
		case "address":
			// The address claim is a structured JSON object (OIDC Core 1.0
			// Section 5.1.1). Only populated members are emitted; an empty
			// object is omitted entirely.
			if addr := addressClaim(user); addr != nil {
				claims["address"] = addr
			}
		case "phone":
			if user.PhoneNumber != "" {
				claims["phone_number"] = user.PhoneNumber
				claims["phone_number_verified"] = user.PhoneNumberVerified
			}
		case "roles":
			claims["roles"] = user.Roles
		}
	}

	// Custom user attributes (for example the demo "department") are NOT emitted
	// here. Claims are governed by the requested scopes (OIDC Core 1.0 Section
	// 5.4), and there is no scope or claims request that authorises these
	// attributes. Returning them unrequested breaks data minimisation and is
	// flagged by the OIDF suite (EnsureIdTokenDoesNotContainNonRequestedClaims).
	// The attributes remain on the user record for flows that legitimately
	// consume them directly (for example OID4VCI credential issuance).

	return claims
}

// CreateUserInfoResponse creates a UserInfo response for OIDC
func (idp *MockIdP) CreateUserInfoResponse(userID string, scopes []string) map[string]interface{} {
	return idp.UserClaims(userID, scopes)
}

// UserClaimsByNames returns the requested standard claims for a user, sourced
// from the user record. It backs the OIDC claims request parameter (OpenID
// Connect Core 1.0 Section 5.5), which lets a client request individual claims
// by name independent of scope. Only claims the user actually holds a value for
// are returned; a missing value is omitted, which is not an error (Section
// 5.5.1). sub is never returned here because the caller always sets it from the
// authenticated subject.
func (idp *MockIdP) UserClaimsByNames(userID string, names []string) map[string]interface{} {
	user, exists := idp.GetUser(userID)
	if !exists {
		return nil
	}

	out := make(map[string]interface{})
	for _, name := range names {
		switch name {
		case "name":
			addIfNotEmpty(out, "name", user.Name)
		case "given_name":
			addIfNotEmpty(out, "given_name", user.GivenName)
		case "family_name":
			addIfNotEmpty(out, "family_name", user.FamilyName)
		case "middle_name":
			addIfNotEmpty(out, "middle_name", user.MiddleName)
		case "nickname":
			addIfNotEmpty(out, "nickname", user.Nickname)
		case "preferred_username":
			out["preferred_username"] = user.ID
		case "profile":
			addIfNotEmpty(out, "profile", user.Profile)
		case "picture":
			addIfNotEmpty(out, "picture", user.Picture)
		case "website":
			addIfNotEmpty(out, "website", user.Website)
		case "gender":
			addIfNotEmpty(out, "gender", user.Gender)
		case "birthdate":
			addIfNotEmpty(out, "birthdate", user.Birthdate)
		case "zoneinfo":
			addIfNotEmpty(out, "zoneinfo", user.Zoneinfo)
		case "locale":
			addIfNotEmpty(out, "locale", user.Locale)
		case "updated_at":
			out["updated_at"] = user.CreatedAt.Unix()
		case "email":
			addIfNotEmpty(out, "email", user.Email)
		case "email_verified":
			// email_verified is only meaningful alongside an email value.
			if user.Email != "" {
				out["email_verified"] = true
			}
		case "phone_number":
			addIfNotEmpty(out, "phone_number", user.PhoneNumber)
		case "phone_number_verified":
			// phone_number_verified is only meaningful alongside a phone number.
			if user.PhoneNumber != "" {
				out["phone_number_verified"] = user.PhoneNumberVerified
			}
		case "address":
			if addr := addressClaim(user); addr != nil {
				out["address"] = addr
			}
		case "roles":
			if len(user.Roles) > 0 {
				out["roles"] = user.Roles
			}
		}
	}
	return out
}

func addIfNotEmpty(claims map[string]interface{}, name, value string) {
	if value != "" {
		claims[name] = value
	}
}

// addressClaim builds the OIDC address claim object (OIDC Core 1.0 Section
// 5.1.1) from the populated members of the user's address. It returns nil when
// the user has no address or every member is empty, so a blank object is never
// emitted (the conformance suite rejects blank address members).
func addressClaim(user *models.User) map[string]interface{} {
	if user.Address == nil {
		return nil
	}
	addr := make(map[string]interface{})
	addIfNotEmpty(addr, "formatted", user.Address.Formatted)
	addIfNotEmpty(addr, "street_address", user.Address.StreetAddress)
	addIfNotEmpty(addr, "locality", user.Address.Locality)
	addIfNotEmpty(addr, "region", user.Address.Region)
	addIfNotEmpty(addr, "postal_code", user.Address.PostalCode)
	addIfNotEmpty(addr, "country", user.Address.Country)
	if len(addr) == 0 {
		return nil
	}
	return addr
}

// GetUserRoles returns the roles for a user
func (idp *MockIdP) GetUserRoles(userID string) []string {
	user, exists := idp.GetUser(userID)
	if !exists {
		return nil
	}
	return user.Roles
}

// HasRole checks if a user has a specific role
func (idp *MockIdP) HasRole(userID string, role string) bool {
	roles := idp.GetUserRoles(userID)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// PKCE utilities per RFC 7636

// PKCEError represents a PKCE validation error with RFC reference
type PKCEError struct {
	Code        string
	Description string
	RFCSection  string
}

func (e *PKCEError) Error() string {
	return e.Description
}

// RFC 7636 Section 4.1: code_verifier character set
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
var codeVerifierRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// ValidatePKCEVerifier validates the code_verifier per RFC 7636 Section 4.1
// Returns nil if valid, or a PKCEError with specific violation details
func ValidatePKCEVerifier(verifier string) error {
	// RFC 7636 Section 4.1: code_verifier length MUST be between 43 and 128 characters
	if len(verifier) < 43 {
		return &PKCEError{
			Code:        "invalid_request",
			Description: "code_verifier must be at least 43 characters (RFC 7636 Section 4.1)",
			RFCSection:  "RFC 7636 Section 4.1",
		}
	}
	if len(verifier) > 128 {
		return &PKCEError{
			Code:        "invalid_request",
			Description: "code_verifier must be at most 128 characters (RFC 7636 Section 4.1)",
			RFCSection:  "RFC 7636 Section 4.1",
		}
	}

	// RFC 7636 Section 4.1: code_verifier MUST only contain unreserved characters
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	if !codeVerifierRegex.MatchString(verifier) {
		return &PKCEError{
			Code:        "invalid_request",
			Description: "code_verifier contains invalid characters (RFC 7636 Section 4.1: only [A-Za-z0-9-._~] allowed)",
			RFCSection:  "RFC 7636 Section 4.1",
		}
	}

	return nil
}

// ValidatePKCEChallenge validates the code_challenge per RFC 7636 Section 4.2
func ValidatePKCEChallenge(challenge, method string) error {
	if challenge == "" {
		return &PKCEError{
			Code:        "invalid_request",
			Description: "code_challenge is required when code_challenge_method is specified",
			RFCSection:  "RFC 7636 Section 4.2",
		}
	}

	// RFC 7636 Section 4.2: For S256, code_challenge is BASE64URL(SHA256(code_verifier))
	// SHA256 produces 32 bytes, base64url encodes to 43 characters (without padding)
	if method == "S256" || method == "" {
		if len(challenge) != 43 {
			return &PKCEError{
				Code:        "invalid_request",
				Description: "code_challenge for S256 must be exactly 43 characters (BASE64URL-encoded SHA256)",
				RFCSection:  "RFC 7636 Section 4.2",
			}
		}
	}

	return nil
}

// ValidatePKCEWithError validates PKCE and returns detailed error for RFC compliance
func ValidatePKCEWithError(verifier, challenge, method string) error {
	if verifier == "" {
		return &PKCEError{
			Code:        "invalid_request",
			Description: "code_verifier is required for PKCE validation",
			RFCSection:  "RFC 7636 Section 4.5",
		}
	}

	// Validate verifier format
	if err := ValidatePKCEVerifier(verifier); err != nil {
		return err
	}

	var computed string
	switch method {
	case "S256", "":
		hash := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(hash[:])
	case "plain":
		computed = verifier
	default:
		return &PKCEError{
			Code:        "invalid_request",
			Description: "unsupported code_challenge_method (only S256 and plain are supported per RFC 7636)",
			RFCSection:  "RFC 7636 Section 4.2",
		}
	}

	if computed != challenge {
		return &PKCEError{
			Code:        "invalid_grant",
			Description: "code_verifier does not match code_challenge (RFC 7636 Section 4.6)",
			RFCSection:  "RFC 7636 Section 4.6",
		}
	}

	return nil
}

// GeneratePKCE generates a PKCE code verifier and challenge pair
func GeneratePKCE() (verifier, challenge string) {
	verifier = generateRandomString(64)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return
}

// Demo user presets for quick selection

// DemoUserPreset represents a preset demo user configuration
type DemoUserPreset struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Credentials DemoCredentials `json:"credentials"`
	Scopes      []string        `json:"suggested_scopes"`
}

// DemoCredentials contains login credentials for demo
type DemoCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// GetDemoUserPresets returns preset configurations for demo users
func (idp *MockIdP) GetDemoUserPresets() []DemoUserPreset {
	alice := idp.getUserPreset("alice")
	bob := idp.getUserPreset("bob")
	admin := idp.getUserPreset("admin")

	return []DemoUserPreset{
		{
			ID:          "alice",
			Name:        "Alice (Standard User)",
			Description: "A standard user with basic permissions",
			Credentials: alice,
			Scopes: []string{"openid", "profile", "email"},
		},
		{
			ID:          "bob",
			Name:        "Bob (Standard User)",
			Description: "Another standard user for testing multi-user scenarios",
			Credentials: bob,
			Scopes: []string{"openid", "profile", "email"},
		},
		{
			ID:          "admin",
			Name:        "Admin (Elevated Permissions)",
			Description: "An administrator with elevated permissions and roles",
			Credentials: admin,
			Scopes: []string{"openid", "profile", "email", "roles"},
		},
	}
}

// Demo client presets

// DemoClientPreset represents a preset demo client configuration
type DemoClientPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"` // "confidential", "public", "machine"
	GrantTypes  []string `json:"grant_types"`
	Scopes      []string `json:"scopes"`
	Secret      string   `json:"secret,omitempty"`
}

// GetDemoClientPresets returns preset configurations for demo clients
func (idp *MockIdP) GetDemoClientPresets() []DemoClientPreset {
	demoAppSecret := idp.getClientSecret("demo-app")
	machineSecret := idp.getClientSecret("machine-client")

	return []DemoClientPreset{
		{
			ID:          "demo-app",
			Name:        "Demo Application (Confidential)",
			Description: "A server-side application with a client secret",
			Type:        "confidential",
			GrantTypes:  []string{"authorization_code", "refresh_token"},
			Scopes:      []string{"openid", "profile", "email"},
			Secret:      demoAppSecret,
		},
		{
			ID:          "public-app",
			Name:        "Public Application (SPA)",
			Description: "A single-page application without a client secret (uses PKCE)",
			Type:        "public",
			GrantTypes:  []string{"authorization_code", "refresh_token"},
			Scopes:      []string{"openid", "profile", "email"},
		},
		{
			ID:          "machine-client",
			Name:        "Machine-to-Machine Client",
			Description: "A service account for API access without user context",
			Type:        "machine",
			GrantTypes:  []string{"client_credentials"},
			Scopes:      []string{"api:read", "api:write"},
			Secret:      machineSecret,
		},
	}
}

func (idp *MockIdP) getUserPreset(id string) DemoCredentials {
	user, ok := idp.GetUser(id)
	if !ok || user == nil {
		return DemoCredentials{}
	}
	return DemoCredentials{
		Email:    user.Email,
		Password: user.Password,
	}
}

func (idp *MockIdP) getClientSecret(id string) string {
	client, ok := idp.GetClient(id)
	if !ok || client == nil {
		return ""
	}
	return client.Secret
}

// TokenMetadata provides metadata about issued tokens for inspection
type TokenMetadata struct {
	TokenType string    `json:"token_type"`
	Subject   string    `json:"subject"`
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenID   string    `json:"token_id,omitempty"`
}

// CreateTokenMetadata creates metadata for a token (for looking glass)
func CreateTokenMetadata(tokenType, subject, clientID, scope string, issuedAt, expiresAt time.Time) TokenMetadata {
	return TokenMetadata{
		TokenType: tokenType,
		Subject:   subject,
		ClientID:  clientID,
		Scope:     scope,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
}
