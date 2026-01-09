package oauth2

import (
	"context"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// Plugin implements the OAuth 2.0 protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
}

// NewPlugin creates a new OAuth 2.0 plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "oauth2",
			Name:        "OAuth 2.0",
			Version:     "1.0.0",
			Description: "OAuth 2.0 Authorization Framework implementation with PKCE support",
			Tags:        []string{"authorization", "tokens", "pkce"},
			RFCs:        []string{"RFC 6749", "RFC 7636", "RFC 7009", "RFC 7662"},
		}),
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
	// Authorization endpoint
	router.Get("/authorize", p.handleAuthorize)
	router.Post("/authorize", p.handleAuthorizeSubmit)

	// Token endpoint
	router.Post("/token", p.handleToken)

	// Token introspection (RFC 7662)
	router.Post("/introspect", p.handleIntrospect)

	// Token revocation (RFC 7009)
	router.Post("/revoke", p.handleRevoke)

	// Demo/utility endpoints
	router.Get("/demo/users", p.handleListUsers)
	router.Get("/demo/clients", p.handleListClients)
}

// GetInspectors returns the protocol's inspectors
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "oauth2-token",
			Name:        "OAuth 2.0 Token Inspector",
			Description: "Decode and analyze OAuth 2.0 access and refresh tokens",
			Type:        "token",
		},
		{
			ID:          "oauth2-request",
			Name:        "OAuth 2.0 Request Inspector",
			Description: "Analyze authorization and token requests",
			Type:        "request",
		},
	}
}

// GetFlowDefinitions returns the protocol's flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "authorization_code",
			Name:        "Authorization Code Flow",
			Description: "The standard OAuth 2.0 flow for server-side applications with a confidential client (RFC 6749 §4.1). The authorization code is exchanged server-to-server, keeping access tokens away from the browser.",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Authorization Request",
					Description: "Client redirects user's browser to the Authorization Server's /authorize endpoint. The state parameter MUST be included to prevent CSRF attacks (RFC 6749 §10.12).",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type": "code (REQUIRED - indicates Authorization Code flow)",
						"client_id":     "Client identifier issued during registration (REQUIRED)",
						"redirect_uri":  "URI to return user after authorization (REQUIRED)",
						"scope":         "Space-delimited list of requested permissions",
						"state":         "Opaque value for CSRF protection (REQUIRED for security)",
					},
					Security: []string{
						"State parameter prevents CSRF attacks - must be cryptographically random",
						"Redirect URI must exactly match pre-registered URI",
						"HTTPS required in production to protect authorization code in transit",
					},
				},
				{
					Order:       2,
					Name:        "User Authentication",
					Description: "Authorization Server authenticates the resource owner (user) via login form. This step is handled entirely by the Authorization Server - the Client never sees user credentials.",
					From:        "User",
					To:          "Authorization Server",
					Type:        "internal",
					Parameters: map[string]string{
						"credentials": "Username/password or SSO (never exposed to Client)",
					},
					Security: []string{
						"Client application NEVER handles user credentials",
						"Authentication method is determined by Authorization Server policy",
					},
				},
				{
					Order:       3,
					Name:        "User Consent",
					Description: "Authorization Server displays consent screen showing requested scopes. User explicitly grants or denies access to their data.",
					From:        "User",
					To:          "Authorization Server",
					Type:        "internal",
					Parameters: map[string]string{
						"scopes":      "Permissions being requested (profile, email, etc.)",
						"client_info": "Application name and verified publisher",
					},
					Security: []string{
						"User must understand what access they are granting",
						"Scope should follow principle of least privilege",
					},
				},
				{
					Order:       4,
					Name:        "Authorization Code Response",
					Description: "Authorization Server redirects user back to Client's redirect_uri with a short-lived authorization code (RFC 6749 §4.1.2). The code is single-use and expires quickly (~10 minutes).",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":  "Single-use authorization code (short-lived, ~10 min)",
						"state": "MUST match the original state value exactly",
					},
					Security: []string{
						"Code is transmitted via browser redirect (front-channel) - keep it short-lived",
						"State mismatch indicates CSRF attack - abort flow immediately",
						"Code can only be used once - replay attacks are prevented",
					},
				},
				{
					Order:       5,
					Name:        "Token Exchange Request",
					Description: "Client's backend server exchanges the authorization code for tokens via direct HTTPS request to the token endpoint (RFC 6749 §4.1.3). This is a back-channel request - browser is not involved.",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code (REQUIRED)",
						"code":          "The authorization code received (REQUIRED)",
						"redirect_uri":  "Must match original authorization request (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"client_secret": "Client secret for confidential clients (REQUIRED)",
					},
					Security: []string{
						"MUST use HTTPS - tokens are highly sensitive",
						"Content-Type MUST be application/x-www-form-urlencoded (RFC 6749 §4.1.3)",
						"Client authentication via client_secret or client_secret_basic header",
						"Back-channel request keeps tokens away from browser",
					},
				},
				{
					Order:       6,
					Name:        "Token Response",
					Description: "Authorization Server validates the code, client credentials, and redirect_uri, then issues tokens (RFC 6749 §4.1.4). Access token is used for API calls; refresh token for renewal without user interaction.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "Bearer token for API authorization (REQUIRED)",
						"token_type":    "Bearer (REQUIRED)",
						"expires_in":    "Token lifetime in seconds (RECOMMENDED)",
						"refresh_token": "For obtaining new access tokens (OPTIONAL)",
						"scope":         "Granted scopes if different from requested (OPTIONAL)",
					},
					Security: []string{
						"Store tokens securely - never in localStorage or client-side code",
						"Access tokens should be short-lived (1 hour typical)",
						"Refresh tokens require secure server-side storage",
					},
				},
				{
					Order:       7,
					Name:        "API Request with Token",
					Description: "Client includes the access token in API requests to the Resource Server using the Authorization header with Bearer scheme (RFC 6750 §2.1).",
					From:        "Client",
					To:          "Resource Server",
					Type:        "request",
					Parameters: map[string]string{
						"Authorization": "Bearer {access_token}",
					},
					Security: []string{
						"Always use HTTPS when transmitting access tokens",
						"Never include tokens in URL query parameters",
					},
				},
				{
					Order:       8,
					Name:        "Protected Resource Response",
					Description: "Resource Server validates the access token and returns the requested data. Token validation may use introspection (RFC 7662) or local JWT verification.",
					From:        "Resource Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"data": "Requested protected resource",
					},
					Security: []string{
						"Resource Server MUST validate token before returning data",
						"Check token expiration, scope, and audience claims",
						"Return 401 Unauthorized for invalid/expired tokens",
					},
				},
			},
		},
		{
			ID:          "authorization_code_pkce",
			Name:        "Authorization Code + PKCE",
			Description: "OAuth 2.0 Authorization Code flow with Proof Key for Code Exchange (RFC 7636). PKCE protects public clients (SPAs, mobile apps) that cannot securely store a client secret. It prevents authorization code interception attacks even if the code is stolen.",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Generate PKCE Parameters",
					Description: "Client generates a cryptographically random code_verifier, then derives the code_challenge using SHA-256 (RFC 7636 §4.1). The verifier is stored securely; only the challenge is sent to the Authorization Server.",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Parameters: map[string]string{
						"code_verifier":         "Cryptographic random string (43-128 chars, [A-Za-z0-9-._~])",
						"code_challenge":        "BASE64URL(SHA256(code_verifier)) = exactly 43 characters",
						"code_challenge_method": "S256 (REQUIRED - SHA-256 hash, never use 'plain')",
					},
					Security: []string{
						"code_verifier MUST be 43-128 characters (RFC 7636 §4.1)",
						"Only characters [A-Za-z0-9-._~] allowed in verifier",
						"Use cryptographically secure random generator",
						"Store verifier securely until token exchange completes",
					},
				},
				{
					Order:       2,
					Name:        "Authorization Request with Challenge",
					Description: "Client redirects user to Authorization Server with the code_challenge (never the verifier). The challenge binds this authorization request to the specific client instance that generated the verifier.",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type":         "code (REQUIRED)",
						"client_id":             "Client identifier (REQUIRED)",
						"redirect_uri":          "Callback URI (REQUIRED)",
						"code_challenge":        "BASE64URL(SHA256(verifier)) - 43 chars (REQUIRED)",
						"code_challenge_method": "S256 (REQUIRED - always use SHA-256)",
						"state":                 "CSRF protection token (REQUIRED)",
						"scope":                 "Requested permissions",
					},
					Security: []string{
						"NEVER send code_verifier to authorization endpoint",
						"code_challenge binds the request to your specific client instance",
						"S256 method is required - plain method is vulnerable",
					},
				},
				{
					Order:       3,
					Name:        "User Authentication & Consent",
					Description: "User authenticates with the Authorization Server and grants permission. Client never sees user credentials. Authorization Server stores the code_challenge for later verification.",
					From:        "User",
					To:          "Authorization Server",
					Type:        "internal",
					Parameters: map[string]string{
						"authentication": "User credentials (never exposed to client)",
						"consent":        "User grants or denies requested scopes",
					},
					Security: []string{
						"Authorization Server stores code_challenge with the authorization code",
					},
				},
				{
					Order:       4,
					Name:        "Authorization Code Response",
					Description: "Authorization Server redirects back to client with authorization code. The code is bound to the code_challenge that was submitted - only the holder of the original verifier can exchange it.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":  "Single-use authorization code (bound to challenge)",
						"state": "MUST match original state value",
					},
					Security: []string{
						"Even if code is intercepted, attacker cannot exchange it without verifier",
						"Verify state parameter before proceeding",
					},
				},
				{
					Order:       5,
					Name:        "Token Exchange with Verifier",
					Description: "Client exchanges authorization code with the original code_verifier as proof of possession (RFC 7636 §4.5). The server hashes the verifier and compares to stored challenge.",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code (REQUIRED)",
						"code":          "The authorization code (REQUIRED)",
						"redirect_uri":  "Must match original request (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"code_verifier": "Original random string 43-128 chars (REQUIRED)",
					},
					Security: []string{
						"Server computes SHA256(code_verifier) and compares to stored challenge",
						"Mismatch proves the requester is not the original client",
						"No client_secret needed - PKCE provides client authentication",
					},
				},
				{
					Order:       6,
					Name:        "Token Response",
					Description: "After verifying the code_verifier matches the stored code_challenge, the Authorization Server issues tokens. This completes the PKCE flow with proof of client identity.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "Bearer token for API access (REQUIRED)",
						"token_type":    "Bearer (REQUIRED)",
						"expires_in":    "Token lifetime in seconds (RECOMMENDED)",
						"refresh_token": "For token renewal (OPTIONAL)",
					},
					Security: []string{
						"Tokens are only issued after successful PKCE verification",
						"Store access token securely",
						"Clear verifier from memory after successful exchange",
					},
				},
			},
		},
		{
			ID:          "client_credentials",
			Name:        "Client Credentials Grant",
			Description: "Machine-to-machine (M2M) authentication for server-side applications (RFC 6749 §4.4). The client authenticates using its own credentials (not user credentials) to access resources it owns or has been granted permission to access. No user interaction required.",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Token Request",
					Description: "Client authenticates directly to the token endpoint using its client_id and client_secret. This is a confidential client flow - credentials must never be exposed to browsers or end users.",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "client_credentials (REQUIRED)",
						"client_id":     "Client identifier (REQUIRED)",
						"client_secret": "Client secret (REQUIRED for confidential clients)",
						"scope":         "Requested permissions (OPTIONAL)",
					},
					Security: []string{
						"ONLY for confidential clients (server-side) - never SPAs/mobile",
						"Client credentials must be stored securely (environment variables, vault)",
						"Use TLS/HTTPS - credentials are transmitted in request body",
						"Content-Type MUST be application/x-www-form-urlencoded",
					},
				},
				{
					Order:       2,
					Name:        "Access Token Response",
					Description: "Authorization Server validates client credentials and issues access token. No refresh token is issued since the client can always re-authenticate with its credentials.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token": "Bearer token for API access (REQUIRED)",
						"token_type":   "Bearer (REQUIRED)",
						"expires_in":   "Token lifetime in seconds (RECOMMENDED)",
						"scope":        "Granted scopes if different from requested",
					},
					Security: []string{
						"No refresh token issued - client can re-request with credentials",
						"Token represents client identity, not a user",
						"Implement token caching to avoid excessive token requests",
					},
				},
				{
					Order:       3,
					Name:        "API Request",
					Description: "Client uses the access token to authenticate API requests. The token represents the client application, not an end user.",
					From:        "Client",
					To:          "Resource Server",
					Type:        "request",
					Parameters: map[string]string{
						"Authorization": "Bearer {access_token}",
					},
					Security: []string{
						"Resource Server validates token before processing request",
						"Check 'sub' claim identifies the client, not a user",
					},
				},
			},
		},
		{
			ID:          "refresh_token",
			Name:        "Refresh Token Flow",
			Description: "Obtain new access tokens without user interaction using a refresh token (RFC 6749 §6). Refresh tokens are long-lived credentials that allow the client to maintain access after the access token expires.",
			Executable:  true,
			Category:    "token-management",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Refresh Token Request",
					Description: "When the access token expires or is about to expire, the client sends the refresh token to obtain a new access token. This happens without user involvement.",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "refresh_token (REQUIRED)",
						"refresh_token": "The refresh token (REQUIRED)",
						"scope":         "Requested scopes (OPTIONAL - same or subset of original)",
						"client_id":     "Client identifier (REQUIRED for public clients)",
						"client_secret": "Client secret (REQUIRED for confidential clients)",
					},
					Security: []string{
						"Refresh tokens are highly sensitive - store securely (encrypted, server-side)",
						"Never expose refresh tokens to client-side JavaScript",
						"Consider refresh token rotation (new refresh token each use)",
					},
				},
				{
					Order:       2,
					Name:        "New Token Response",
					Description: "Authorization Server validates the refresh token and issues new tokens. Many implementations use refresh token rotation - issuing a new refresh token and invalidating the old one.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "New access token (REQUIRED)",
						"token_type":    "Bearer (REQUIRED)",
						"expires_in":    "Token lifetime in seconds (RECOMMENDED)",
						"refresh_token": "New refresh token (OPTIONAL - rotation)",
					},
					Security: []string{
						"Refresh token rotation prevents token replay attacks",
						"If rotation enabled, old refresh token is invalidated",
						"Detect and revoke all tokens if refresh token reuse detected",
					},
				},
			},
		},
		{
			ID:          "token_introspection",
			Name:        "Token Introspection (RFC 7662)",
			Description: "Allows a Resource Server to query the Authorization Server about the current state of an access token. Returns metadata including whether the token is active, its scopes, subject, and expiration. Essential for opaque tokens and revocation checking.",
			Executable:  true,
			Category:    "token-management",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Introspection Request",
					Description: "Resource Server sends the token to the Authorization Server's introspection endpoint. The Resource Server must authenticate itself (it's a protected endpoint).",
					From:        "Resource Server",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"token":           "The token to introspect (REQUIRED)",
						"token_type_hint": "access_token or refresh_token (OPTIONAL - advisory)",
						"client_id":       "Resource Server's client ID (for authentication)",
						"client_secret":   "Resource Server's secret (for authentication)",
					},
					Security: []string{
						"Introspection endpoint MUST be protected - requires client authentication",
						"token_type_hint is advisory - server may check both types",
						"Content-Type MUST be application/x-www-form-urlencoded",
					},
				},
				{
					Order:       2,
					Name:        "Token Validation",
					Description: "Authorization Server validates the token: checks signature (if JWT), expiration, and whether it has been revoked. Revoked tokens return active: false.",
					From:        "Authorization Server",
					To:          "Authorization Server",
					Type:        "internal",
					Parameters: map[string]string{
						"signature":  "Verify JWT signature using private key",
						"expiration": "Check exp claim against current time",
						"revocation": "Check if token is in revocation blacklist",
					},
				},
				{
					Order:       3,
					Name:        "Introspection Response",
					Description: "Authorization Server returns token metadata. The 'active' field indicates if the token is currently valid. Revoked tokens return active=false.",
					From:        "Authorization Server",
					To:          "Resource Server",
					Type:        "response",
					Parameters: map[string]string{
						"active":    "Boolean - false if expired, revoked, or invalid (REQUIRED)",
						"scope":     "Space-separated list of scopes",
						"client_id": "Client that requested the token",
						"username":  "Resource owner (if applicable)",
						"exp":       "Expiration timestamp",
						"iat":       "Issued-at timestamp",
						"sub":       "Subject identifier",
						"aud":       "Intended audience",
						"iss":       "Token issuer",
					},
					Security: []string{
						"active=false for expired, revoked, or invalid tokens",
						"Introspection is authoritative for token status",
					},
				},
			},
		},
		{
			ID:          "token_revocation",
			Name:        "Token Revocation (RFC 7009)",
			Description: "Invalidate access or refresh tokens before their natural expiration. Essential for logout flows and security incident response. Supports both access and refresh token revocation.",
			Executable:  true,
			Category:    "token-management",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Revocation Request",
					Description: "Client sends the token to the revocation endpoint. The server MUST attempt revocation regardless of token_type_hint (RFC 7009 §2.1).",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"token":           "The token to revoke (REQUIRED)",
						"token_type_hint": "refresh_token or access_token (OPTIONAL - advisory)",
						"client_id":       "Client identifier (REQUIRED)",
						"client_secret":   "Client secret (if confidential client)",
					},
					Security: []string{
						"Server MUST attempt revocation regardless of hint",
						"Client authentication required for confidential clients",
						"Content-Type MUST be application/x-www-form-urlencoded",
					},
				},
				{
					Order:       2,
					Name:        "Revocation Response",
					Description: "Server acknowledges revocation with 200 OK even if token was already invalid or unknown. This prevents attackers from probing token validity.",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"status": "200 OK (always, per RFC 7009 §2.2)",
						"body":   "Empty on success",
					},
					Security: []string{
						"Always returns 200 OK to prevent token validity probing",
						"Introspection will return active=false for revoked tokens",
						"Revoking refresh token may revoke associated access tokens",
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
			ID:          "auth_code_flow",
			Name:        "Authorization Code Flow Demo",
			Description: "Interactive demonstration of the OAuth 2.0 authorization code flow",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Start Authorization", Description: "Initiate the authorization request", Auto: true},
				{Order: 2, Name: "Authenticate User", Description: "Login as a demo user", Auto: false},
				{Order: 3, Name: "Receive Authorization Code", Description: "Handle the callback with code", Auto: true},
				{Order: 4, Name: "Exchange Code for Tokens", Description: "Request tokens from token endpoint", Auto: true},
				{Order: 5, Name: "Inspect Tokens", Description: "Examine the issued tokens", Auto: false},
			},
		},
		{
			ID:          "pkce_flow",
			Name:        "PKCE Flow Demo",
			Description: "Authorization code flow with PKCE for public clients",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Generate PKCE Challenge", Description: "Create code_verifier and code_challenge", Auto: true},
				{Order: 2, Name: "Start Authorization", Description: "Include code_challenge in request", Auto: true},
				{Order: 3, Name: "Authenticate User", Description: "Login as a demo user", Auto: false},
				{Order: 4, Name: "Exchange with Verifier", Description: "Include code_verifier in token request", Auto: true},
				{Order: 5, Name: "Verify PKCE", Description: "See PKCE validation in action", Auto: true},
			},
		},
		{
			ID:          "client_credentials_flow",
			Name:        "Client Credentials Demo",
			Description: "Machine-to-machine authentication",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Request Token", Description: "Authenticate with client credentials", Auto: true},
				{Order: 2, Name: "Inspect Token", Description: "Examine the access token", Auto: false},
			},
		},
		{
			ID:          "token_refresh",
			Name:        "Token Refresh Demo",
			Description: "Demonstrate refresh token usage and rotation",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Obtain Initial Tokens", Description: "Get access and refresh tokens", Auto: true},
				{Order: 2, Name: "Wait for Expiry", Description: "Simulate token expiration", Auto: true},
				{Order: 3, Name: "Refresh Token", Description: "Use refresh token to get new access token", Auto: true},
				{Order: 4, Name: "Verify Rotation", Description: "See that refresh token was rotated", Auto: true},
			},
		},
	}
}

// MockIdP returns the mock identity provider
func (p *Plugin) MockIdP() *mockidp.MockIdP {
	return p.mockIdP
}

// KeySet returns the crypto key set
func (p *Plugin) KeySet() *crypto.KeySet {
	return p.keySet
}

// LookingGlass returns the looking glass engine
func (p *Plugin) LookingGlass() *lookingglass.Engine {
	return p.lookingGlass
}

// BaseURL returns the base URL
func (p *Plugin) BaseURL() string {
	return p.baseURL
}
