package oidc

import (
	"context"

	"github.com/go-chi/chi/v5"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
)

// Plugin implements the OpenID Connect protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	oauth2Plugin *oauth2.Plugin
	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
}

// NewPlugin creates a new OIDC plugin
func NewPlugin(oauth2Plugin *oauth2.Plugin) *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "oidc",
			Name:        "OpenID Connect",
			Version:     "1.0.0",
			Description: "OpenID Connect 1.0 identity layer on top of OAuth 2.0",
			Tags:        []string{"identity", "authentication", "id-token", "userinfo"},
			RFCs:        []string{"OpenID Connect Core 1.0", "OpenID Connect Discovery 1.0"},
		}),
		oauth2Plugin: oauth2Plugin,
	}
}

// Initialize initializes the plugin
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = config.BaseURL

	if idp, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIdP = idp
	}

	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}

	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	return nil
}

// Shutdown shuts down the plugin
func (p *Plugin) Shutdown(ctx context.Context) error {
	return nil
}

// RegisterRoutes registers the plugin's HTTP routes
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// Discovery document
	router.Get("/.well-known/openid-configuration", p.handleDiscovery)

	// JWKS endpoint
	router.Get("/.well-known/jwks.json", p.handleJWKS)
	router.Get("/jwks", p.handleJWKS)

	// UserInfo endpoint
	router.Get("/userinfo", p.handleUserInfo)
	router.Post("/userinfo", p.handleUserInfo)

	// Authorization endpoint (extends OAuth2)
	router.Get("/authorize", p.handleAuthorize)
	router.Post("/authorize", p.handleAuthorizeSubmit)

	// Token endpoint (extends OAuth2 to include ID token)
	router.Post("/token", p.handleToken)
}

// GetInspectors returns the protocol's inspectors
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "oidc-id-token",
			Name:        "ID Token Inspector",
			Description: "Decode and analyze OIDC ID tokens",
			Type:        "token",
		},
		{
			ID:          "oidc-discovery",
			Name:        "Discovery Document Inspector",
			Description: "Analyze OpenID Connect discovery documents",
			Type:        "response",
		},
		{
			ID:          "oidc-claims",
			Name:        "Claims Inspector",
			Description: "Analyze and explain OIDC claims",
			Type:        "token",
		},
	}
}

// GetFlowDefinitions returns the protocol's flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "oidc_authorization_code",
			Name:        "OIDC Authorization Code Flow",
			Description: "OpenID Connect 1.0 authentication using the OAuth 2.0 Authorization Code flow (OIDC Core §3.1). Adds an ID Token containing identity claims about the authenticated user. Most secure flow for server-side applications.",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Discovery Document Fetch",
					Description: "Client fetches the OpenID Provider's configuration from the well-known endpoint (OIDC Discovery §4). This document contains all endpoint URLs, supported scopes, and cryptographic capabilities.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/openid-configuration",
						"issuer":   "Base URL of the OpenID Provider",
					},
					Security: []string{
						"Cache the discovery document - it rarely changes",
						"Verify issuer in discovery matches expected value",
					},
				},
				{
					Order:       2,
					Name:        "JWKS Fetch",
					Description: "Client fetches the JSON Web Key Set (JWKS) containing public keys for token signature verification (OIDC Core §10.1). Keys are identified by 'kid' (key ID) in token headers.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "jwks_uri from discovery document",
						"keys":     "Array of JWK objects (RSA, EC, etc.)",
					},
					Security: []string{
						"Cache JWKS with appropriate TTL",
						"Implement key rotation handling - refetch on unknown kid",
					},
				},
				{
					Order:       3,
					Name:        "Authentication Request",
					Description: "Client redirects user to the authorization_endpoint with 'openid' scope (OIDC Core §3.1.2.1). The 'nonce' parameter is REQUIRED for replay protection - it binds the ID Token to this specific request.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type": "code (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"redirect_uri":  "Callback URI (REQUIRED)",
						"scope":         "openid (REQUIRED) + profile email address phone",
						"state":         "CSRF protection token (REQUIRED for security)",
						"nonce":         "Replay attack prevention (REQUIRED - returned in ID Token)",
						"prompt":        "none|login|consent|select_account (OPTIONAL)",
					},
					Security: []string{
						"nonce MUST be cryptographically random - binds ID Token to session",
						"state prevents CSRF - must be validated on callback",
						"Scope 'openid' is REQUIRED to trigger OIDC flow",
					},
				},
				{
					Order:       4,
					Name:        "User Authentication",
					Description: "User authenticates with the OpenID Provider using their credentials. The OP determines authentication method (password, MFA, passkey, SSO). Client never sees user credentials.",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"authentication": "Password, MFA, biometric, SSO, etc.",
						"auth_time":      "Timestamp recorded for ID Token auth_time claim",
					},
					Security: []string{
						"Client NEVER handles user credentials",
						"OP may skip authentication if SSO session exists",
					},
				},
				{
					Order:       5,
					Name:        "User Consent",
					Description: "User reviews and approves requested scopes. The OP shows what information will be shared (profile, email, etc.). User can deny access.",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"scopes":  "Requested claims based on scopes",
						"consent": "Grant or deny access to claims",
					},
				},
				{
					Order:       6,
					Name:        "Authorization Code Response",
					Description: "OpenID Provider redirects back with authorization code (OIDC Core §3.1.2.5). The code is bound to the client and nonce. Single-use, short-lived (~10 minutes).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":  "Single-use authorization code (short-lived)",
						"state": "MUST match original state exactly",
					},
					Security: []string{
						"Verify state before proceeding - mismatch = CSRF attack",
						"Code is single-use - replay protection built-in",
					},
				},
				{
					Order:       7,
					Name:        "Token Request",
					Description: "Client exchanges code for tokens at the token_endpoint via back-channel HTTPS request (OIDC Core §3.1.3.1). Browser is not involved - tokens stay server-side.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code (REQUIRED)",
						"code":          "The authorization code (REQUIRED)",
						"redirect_uri":  "Must match original request (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"client_secret": "Client secret for confidential clients",
					},
					Security: []string{
						"MUST use HTTPS for token endpoint",
						"Content-Type MUST be application/x-www-form-urlencoded",
						"Back-channel request keeps tokens away from browser",
					},
				},
				{
					Order:       8,
					Name:        "Token Response with ID Token",
					Description: "OpenID Provider returns access_token AND id_token (OIDC Core §3.1.3.3). The ID Token is a signed JWT containing identity claims about the authenticated user.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "For accessing protected resources (UserInfo, APIs)",
						"token_type":    "Bearer",
						"id_token":      "JWT with identity claims (sub, iss, aud, exp, iat, nonce)",
						"expires_in":    "Access token lifetime in seconds",
						"refresh_token": "For token renewal (if granted)",
					},
					Security: []string{
						"ID Token MUST be validated before trusting claims",
						"Store tokens securely server-side",
					},
				},
				{
					Order:       9,
					Name:        "ID Token Validation",
					Description: "Client MUST validate the ID Token before trusting it (OIDC Core §3.1.3.7). Verify signature using JWKS, then validate all required claims including nonce.",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Parameters: map[string]string{
						"signature": "Verify using public key from JWKS (match kid)",
						"iss":       "MUST match OP's issuer exactly",
						"aud":       "MUST contain this client's client_id",
						"exp":       "MUST NOT be expired (with clock skew tolerance)",
						"iat":       "SHOULD be recent (detect old tokens)",
						"nonce":     "MUST match value sent in authentication request",
						"auth_time": "If max_age was sent, verify authentication is recent",
					},
					Security: []string{
						"NEVER skip any validation step",
						"nonce validation prevents replay attacks",
						"azp required if multiple audiences present",
					},
				},
				{
					Order:       10,
					Name:        "UserInfo Request (Optional)",
					Description: "Client can request additional claims from the userinfo_endpoint using the access token (OIDC Core §5.3). Returns claims based on granted scopes.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"Authorization": "Bearer {access_token}",
					},
					Security: []string{
						"Sub claim in UserInfo MUST match sub in ID Token",
					},
				},
				{
					Order:       11,
					Name:        "UserInfo Response",
					Description: "OpenID Provider returns additional user claims based on scopes: profile (name, picture), email (email, email_verified), phone (phone_number), address.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"sub":            "Subject identifier - ALWAYS present, MUST match ID Token",
						"name":           "Full name (profile scope)",
						"email":          "Email address (email scope)",
						"email_verified": "Boolean - is email verified? (email scope)",
						"picture":        "Profile picture URL (profile scope)",
					},
					Security: []string{
						"MUST verify sub matches ID Token before using claims",
						"Use 'sub' as primary identifier, not email",
					},
				},
			},
		},
		{
			ID:          "oidc_implicit",
			Name:        "OIDC Implicit Flow (Legacy)",
			Description: "OpenID Connect Implicit flow returns tokens directly from the authorization endpoint (OIDC Core §3.2). ⚠️ DEPRECATED: Not recommended for new applications due to token exposure in browser history and URL. Use Authorization Code + PKCE instead.",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Authentication Request",
					Description: "Client redirects user to authorization endpoint requesting tokens directly (no code exchange). The nonce parameter is REQUIRED when response_type includes 'id_token' (OIDC Core §3.2.2.1).",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type": "id_token token (both) or id_token (ID token only)",
						"client_id":     "Client identifier (REQUIRED)",
						"redirect_uri":  "Callback URI (REQUIRED)",
						"scope":         "openid (REQUIRED) + profile email etc.",
						"state":         "CSRF protection token (REQUIRED)",
						"nonce":         "Replay protection (REQUIRED for id_token response types)",
					},
					Security: []string{
						"⚠️ DEPRECATED: Use Authorization Code + PKCE for new applications",
						"Nonce is REQUIRED to bind ID Token to session (replay protection)",
						"Tokens will be exposed in browser history",
					},
				},
				{
					Order:       2,
					Name:        "User Authentication & Consent",
					Description: "User authenticates with the OpenID Provider and grants permission. Client never sees credentials.",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
				},
				{
					Order:       3,
					Name:        "Token Response via Fragment",
					Description: "Tokens returned in URL fragment (#) - fragment is NOT sent to server, only accessible via JavaScript. ID Token includes at_hash when access_token is also returned (OIDC Core §3.2.2.9).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"id_token":     "JWT with identity claims (REQUIRED)",
						"access_token": "For API access (if 'token' in response_type)",
						"token_type":   "Bearer",
						"state":        "MUST match original value",
						"at_hash":      "Access Token hash in ID Token (if access_token present)",
					},
					Security: []string{
						"Tokens visible in browser history and logs - security risk",
						"at_hash binds access_token to ID Token - validate it",
						"No refresh tokens - user must re-authenticate when expired",
					},
				},
				{
					Order:       4,
					Name:        "ID Token Validation",
					Description: "Client MUST validate the ID Token before trusting claims (OIDC Core §3.2.2.11). Validation is critical as token came through front-channel.",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Parameters: map[string]string{
						"signature": "Verify using public key from JWKS",
						"iss":       "MUST match OP's issuer exactly",
						"aud":       "MUST contain client_id",
						"nonce":     "MUST match value sent in authentication request",
						"at_hash":   "If access_token present: validate hash matches",
					},
					Security: []string{
						"NEVER skip validation - tokens came through untrusted channel",
						"nonce validation is CRITICAL for replay attack prevention",
						"Consider switching to Authorization Code + PKCE",
					},
				},
			},
		},
		{
			ID:          "oidc_hybrid",
			Name:        "OIDC Hybrid Flow",
			Description: "Combines Authorization Code and Implicit flows (OIDC Core §3.3). Returns ID Token immediately for fast identity verification while authorization code is exchanged securely server-side. Useful when client needs identity before backend token exchange completes.",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Authentication Request",
					Description: "Request both authorization code and tokens. The response_type determines what is returned immediately vs via token exchange (OIDC Core §3.3.2.1).",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type": "'code id_token' | 'code token' | 'code id_token token' (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"redirect_uri":  "Callback URI (REQUIRED)",
						"scope":         "openid (REQUIRED) + profile email etc.",
						"state":         "CSRF protection token (REQUIRED)",
						"nonce":         "Replay protection (REQUIRED when id_token in response_type)",
					},
					Security: []string{
						"nonce REQUIRED when response_type includes 'id_token'",
						"Consider if simple Authorization Code + PKCE meets your needs",
					},
				},
				{
					Order:       2,
					Name:        "User Authentication & Consent",
					Description: "User authenticates with the OpenID Provider and grants permission. OpenID Provider generates code and tokens based on response_type.",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
				},
				{
					Order:       3,
					Name:        "Hybrid Response with Hash Claims",
					Description: "ID Token returned immediately with hash claims for integrity verification. c_hash binds ID Token to authorization code; at_hash binds to access_token (OIDC Core §3.3.2.11).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":         "Authorization code (for backend token exchange)",
						"id_token":     "JWT with identity claims (immediate)",
						"access_token": "If 'token' in response_type (immediate)",
						"state":        "MUST match original value",
						"c_hash":       "Code hash in ID Token: BASE64URL(left-half(SHA256(code)))",
						"at_hash":      "Access Token hash in ID Token (if access_token present)",
					},
					Security: []string{
						"c_hash MUST be validated to detect code tampering",
						"at_hash MUST be validated if access_token is present",
						"Immediate ID Token allows fast identity verification",
					},
				},
				{
					Order:       4,
					Name:        "Validate ID Token with Hash Claims",
					Description: "Client validates ID Token including c_hash and at_hash to ensure integrity of all front-channel tokens (OIDC Core §3.3.2.12).",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Parameters: map[string]string{
						"signature": "Verify using public key from JWKS",
						"nonce":     "Must match original (replay protection)",
						"c_hash":    "Compute SHA256(code), take left half, base64url encode, compare",
						"at_hash":   "Compute SHA256(access_token), take left half, base64url encode, compare",
						"azp":       "If aud has multiple values, azp MUST equal client_id",
					},
					Security: []string{
						"Hash validation detects token substitution attacks",
						"If c_hash fails, DO NOT exchange the authorization code",
						"If at_hash fails, DO NOT use the access_token",
					},
				},
				{
					Order:       5,
					Name:        "Token Exchange (Backend)",
					Description: "Exchange authorization code for tokens via secure back-channel. This may return a fresh access_token with longer lifetime than the immediate one.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code (REQUIRED)",
						"code":          "The authorization code (REQUIRED)",
						"redirect_uri":  "Must match original (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"client_secret": "Client secret for confidential clients",
					},
					Security: []string{
						"Back-channel exchange is more secure than front-channel",
						"Refresh token is typically only returned here, not in fragment",
					},
				},
				{
					Order:       6,
					Name:        "Token Response",
					Description: "Receive access_token, id_token, and optionally refresh_token from token endpoint. The exchanged tokens may differ from immediate tokens.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "Bearer token for API access",
						"token_type":    "Bearer",
						"expires_in":    "Token lifetime in seconds",
						"refresh_token": "For token renewal (not returned in fragment)",
						"id_token":      "May be returned again with updated claims",
					},
					Security: []string{
						"Refresh token ONLY returned via back-channel (not in fragment)",
						"Compare sub claim in both ID Tokens - must match",
					},
				},
			},
		},
		{
			ID:          "oidc_userinfo",
			Name:        "UserInfo Endpoint",
			Description: "Protected resource that returns claims about the authenticated End-User (OIDC Core §5.3). Access requires a valid access token with 'openid' scope. Returns claims based on granted scopes (profile, email, address, phone).",
			Executable:  true,
			Category:    "claims",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "UserInfo Request",
					Description: "Client requests claims about the authenticated user using the access_token obtained from a prior authentication (OIDC Core §5.3.1). GET or POST methods are supported.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"method":        "GET (REQUIRED to support) or POST",
						"Authorization": "Bearer {access_token} (REQUIRED)",
						"endpoint":      "userinfo_endpoint from discovery document",
					},
					Security: []string{
						"Access token MUST have 'openid' scope",
						"HTTPS is REQUIRED for transmitting access tokens",
					},
				},
				{
					Order:       2,
					Name:        "Token Validation & User Lookup",
					Description: "OpenID Provider validates the access token and retrieves the associated user record. Checks token expiration, scope, and revocation status.",
					From:        "OpenID Provider",
					To:          "OpenID Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"validate": "Token signature and expiration",
						"scope":    "Verify 'openid' scope is present",
						"subject":  "Look up user by 'sub' claim in token",
					},
				},
				{
					Order:       3,
					Name:        "UserInfo Response",
					Description: "Returns claims about the End-User as JSON or JWT. The 'sub' claim is always present and MUST match the ID Token (OIDC Core §5.3.2).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"sub":            "Subject identifier - ALWAYS present, MUST match ID Token",
						"name":           "Full name (profile scope)",
						"given_name":     "First name (profile scope)",
						"family_name":    "Last name (profile scope)",
						"email":          "Email address (email scope)",
						"email_verified": "Boolean - is email verified? (email scope)",
						"picture":        "Profile picture URL (profile scope)",
						"phone_number":   "Phone number (phone scope)",
					},
					Security: []string{
						"MUST verify 'sub' matches ID Token before using claims",
						"Use 'sub' as primary identifier, not email (email can change)",
					},
				},
			},
		},
		{
			ID:          "oidc_discovery",
			Name:        "OpenID Connect Discovery",
			Description: "Auto-configuration mechanism that allows Relying Parties to discover the OpenID Provider's endpoints, supported features, and cryptographic capabilities (OIDC Discovery §4). Essential for dynamic client registration and multi-provider support.",
			Executable:  true,
			Category:    "configuration",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Discovery Document Request",
					Description: "Client fetches the OpenID Provider Configuration from the well-known endpoint (OIDC Discovery §4.1). URL is constructed from issuer: {issuer}/.well-known/openid-configuration",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/openid-configuration",
						"method":   "GET",
					},
					Security: []string{
						"HTTPS required - document contains security-critical endpoints",
						"Cache the response - it changes infrequently",
					},
				},
				{
					Order:       2,
					Name:        "Configuration Response",
					Description: "Returns comprehensive metadata about the OpenID Provider including all endpoints, supported features, and cryptographic capabilities (OIDC Discovery §3).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"issuer":                                "OP identifier URL - MUST match ID Token 'iss' (REQUIRED)",
						"authorization_endpoint":                "URL for authorization requests (REQUIRED)",
						"token_endpoint":                        "URL for token exchange (REQUIRED)",
						"userinfo_endpoint":                     "URL for UserInfo claims (RECOMMENDED)",
						"jwks_uri":                              "URL for JSON Web Key Set (REQUIRED)",
						"scopes_supported":                      "Array of supported scope values (RECOMMENDED)",
						"response_types_supported":              "Array: code, id_token, token combinations (REQUIRED)",
						"id_token_signing_alg_values_supported": "Array: RS256, etc. (REQUIRED)",
						"claims_supported":                      "Array of available claim names (RECOMMENDED)",
					},
					Security: []string{
						"Verify 'issuer' matches expected OP identifier exactly",
						"Use scopes_supported to validate scope requests",
					},
				},
				{
					Order:       3,
					Name:        "JWKS Request",
					Description: "Client fetches the JSON Web Key Set (JWKS) from jwks_uri. Contains public keys for validating ID Token and UserInfo JWT signatures (RFC 7517).",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "jwks_uri from discovery document",
						"method":   "GET",
					},
					Security: []string{
						"Cache JWKS with appropriate TTL (hours)",
						"Implement key rotation handling - refetch on unknown 'kid'",
					},
				},
				{
					Order:       4,
					Name:        "JWKS Response",
					Description: "Returns array of JSON Web Keys (JWKs) used for signing tokens. Match 'kid' (key ID) from token header to find correct verification key (RFC 7517 §5).",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"keys": "Array of JWK objects",
						"kty":  "Key type: 'RSA' or 'EC' (REQUIRED)",
						"use":  "Key usage: 'sig' for signing (OPTIONAL but common)",
						"alg":  "Algorithm: 'RS256', 'ES256', etc. (OPTIONAL)",
						"kid":  "Key ID - matches 'kid' in token header (OPTIONAL but common)",
						"n":    "RSA public key modulus (for RSA keys)",
						"e":    "RSA public key exponent (for RSA keys)",
					},
					Security: []string{
						"Match 'kid' from token to correct key in JWKS",
						"Multiple keys support key rotation without downtime",
					},
				},
			},
		},
		// Interactive Code Flow - comprehensive OIDC flow for the Looking Glass
		{
			ID:          "interactive_code",
			Name:        "Interactive Code Flow",
			Description: "Full interactive OAuth 2.0 + OIDC flow with Discovery, PKCE, and Nonce validation. This comprehensive flow demonstrates the complete authentication journey including provider discovery, secure code exchange with PKCE, ID Token validation, and UserInfo retrieval.",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "OpenID Discovery",
					Description: "Fetch the OpenID Provider's configuration from .well-known/openid-configuration. This provides all endpoint URLs, supported features, and cryptographic capabilities.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/openid-configuration",
					},
				},
				{
					Order:       2,
					Name:        "JWKS Fetch",
					Description: "Retrieve the JSON Web Key Set for signature verification. Keys are identified by 'kid' in token headers.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "jwks_uri from discovery",
					},
				},
				{
					Order:       3,
					Name:        "Authorization Request",
					Description: "Redirect user to authorize with PKCE (code_challenge) and nonce for replay protection.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type":         "code",
						"client_id":             "Your application's client ID",
						"redirect_uri":          "Your callback URL",
						"scope":                 "openid profile email",
						"state":                 "Random CSRF protection value",
						"nonce":                 "Random replay protection value",
						"code_challenge":        "SHA256 hash of code_verifier",
						"code_challenge_method": "S256",
					},
					Security: []string{
						"PKCE prevents authorization code interception attacks",
						"Nonce binds ID Token to this specific request",
						"State prevents CSRF attacks",
					},
				},
				{
					Order:       4,
					Name:        "User Authentication",
					Description: "User authenticates with the OpenID Provider and consents to the requested scopes.",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "interaction",
				},
				{
					Order:       5,
					Name:        "Authorization Response",
					Description: "Provider redirects back with authorization code. Verify state matches original request.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":  "Authorization code (short-lived)",
						"state": "Must match original state",
					},
				},
				{
					Order:       6,
					Name:        "Token Exchange",
					Description: "Exchange authorization code for tokens using PKCE code_verifier.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code",
						"code":          "Authorization code from callback",
						"redirect_uri":  "Must match original request",
						"client_id":     "Your client ID",
						"code_verifier": "Original PKCE verifier",
					},
				},
				{
					Order:       7,
					Name:        "Token Response",
					Description: "Receive access token, ID token, and optionally refresh token.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "Bearer token for API access",
						"token_type":    "Bearer",
						"expires_in":    "Token lifetime in seconds",
						"id_token":      "JWT containing user identity claims",
						"refresh_token": "Optional - for obtaining new tokens",
						"scope":         "Granted scopes",
					},
				},
				{
					Order:       8,
					Name:        "ID Token Validation",
					Description: "Validate ID Token signature using JWKS, verify issuer, audience, expiration, and nonce claims.",
					From:        "Client",
					To:          "Client",
					Type:        "validation",
					Parameters: map[string]string{
						"signature": "Verify using public key from JWKS",
						"iss":       "Must match expected issuer",
						"aud":       "Must include client_id",
						"exp":       "Must not be expired",
						"nonce":     "Must match original nonce",
					},
					Security: []string{
						"ALWAYS validate ID Token signature",
						"Verify nonce matches to prevent replay attacks",
						"Check exp claim - reject expired tokens",
					},
				},
				{
					Order:       9,
					Name:        "UserInfo Request",
					Description: "Fetch additional user claims using the access token.",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint":      "/userinfo",
						"Authorization": "Bearer {access_token}",
					},
				},
				{
					Order:       10,
					Name:        "UserInfo Response",
					Description: "Receive user profile claims: sub, name, email, picture, etc.",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"sub":     "Subject identifier (unique user ID)",
						"name":    "Full name",
						"email":   "Email address",
						"picture": "Profile picture URL",
					},
				},
			},
		},
	}
}

// GetDemoScenarios returns the protocol's demo scenarios
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "oidc_login",
			Name:        "Login with OpenID Connect",
			Description: "Complete OIDC authentication flow with ID token",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Fetch Discovery Document", Description: "Get OpenID Provider configuration", Auto: true},
				{Order: 2, Name: "Start Authentication", Description: "Redirect to authorization endpoint", Auto: true},
				{Order: 3, Name: "Authenticate User", Description: "Login as a demo user", Auto: false},
				{Order: 4, Name: "Exchange Code", Description: "Get tokens including ID token", Auto: true},
				{Order: 5, Name: "Validate ID Token", Description: "Verify signature and claims", Auto: true},
				{Order: 6, Name: "Fetch UserInfo", Description: "Get additional user claims", Auto: true},
			},
		},
		{
			ID:          "id_token_inspection",
			Name:        "ID Token Deep Dive",
			Description: "Detailed inspection of ID token structure and claims",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Obtain ID Token", Description: "Complete authentication flow", Auto: true},
				{Order: 2, Name: "Decode Header", Description: "Examine JWT header", Auto: true},
				{Order: 3, Name: "Decode Payload", Description: "Examine claims", Auto: true},
				{Order: 4, Name: "Verify Signature", Description: "Step-by-step signature verification", Auto: true},
				{Order: 5, Name: "Validate Claims", Description: "Check iss, aud, exp, nonce", Auto: true},
			},
		},
		{
			ID:          "discovery_exploration",
			Name:        "Discovery Document Exploration",
			Description: "Understand the OpenID Provider metadata",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Fetch Discovery", Description: "Get .well-known/openid-configuration", Auto: true},
				{Order: 2, Name: "Explore Endpoints", Description: "Understand available endpoints", Auto: false},
				{Order: 3, Name: "Fetch JWKS", Description: "Get public keys", Auto: true},
				{Order: 4, Name: "Analyze Keys", Description: "Understand JWK structure", Auto: false},
			},
		},
	}
}

