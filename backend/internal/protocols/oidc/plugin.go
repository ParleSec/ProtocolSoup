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
			ID:          "interactive-code",
			Name:        "Interactive Code Flow",
			Description: "Comprehensive OAuth 2.0/OIDC flow with real-time events: Discovery, PKCE, nonce validation, token exchange, and UserInfo",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Discovery",
					Description: "Fetch OpenID Provider configuration and JWKS public keys",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/openid-configuration",
						"jwks":     "/.well-known/jwks.json",
					},
					Security: []string{"Validate issuer matches expected value"},
				},
				{
					Order:       2,
					Name:        "Security Parameter Generation",
					Description: "Generate state (CSRF), PKCE code_verifier/challenge, and nonce",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Parameters: map[string]string{
						"state":            "Random 32-byte hex for CSRF protection",
						"code_verifier":    "Random 43-128 char Base64URL string",
						"code_challenge":   "SHA256(code_verifier) Base64URL encoded",
						"nonce":            "Random 32-byte hex for ID token binding",
					},
					Security: []string{"Use cryptographically secure random generation", "PKCE required for public clients"},
				},
				{
					Order:       3,
					Name:        "Authorization Request",
					Description: "Redirect user to authorization endpoint with all security parameters",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "redirect",
					Parameters: map[string]string{
						"response_type":         "code",
						"client_id":             "OAuth client identifier",
						"redirect_uri":          "Callback URL",
						"scope":                 "openid profile email",
						"state":                 "CSRF protection token",
						"nonce":                 "ID token replay protection",
						"code_challenge":        "PKCE challenge",
						"code_challenge_method": "S256",
					},
					Security: []string{"Verify redirect_uri is pre-registered", "State prevents CSRF"},
				},
				{
					Order:       4,
					Name:        "User Authentication",
					Description: "User authenticates and authorizes the application",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "user_action",
					Security: []string{"Strong authentication recommended", "MFA adds security"},
				},
				{
					Order:       5,
					Name:        "Authorization Response",
					Description: "OpenID Provider redirects back with authorization code",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "redirect",
					Parameters: map[string]string{
						"code":  "Short-lived authorization code",
						"state": "Echoed for CSRF validation",
					},
					Security: []string{"Validate state matches original", "Code is single-use and time-limited"},
				},
				{
					Order:       6,
					Name:        "Token Exchange",
					Description: "Exchange authorization code for tokens via back-channel",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code",
						"code":          "Authorization code from callback",
						"redirect_uri":  "Must match authorization request",
						"code_verifier": "PKCE proof (hashed matches code_challenge)",
					},
					Security: []string{"PKCE verified server-side", "Back-channel prevents token exposure"},
				},
				{
					Order:       7,
					Name:        "Token Response",
					Description: "Receive access_token, id_token, and optionally refresh_token",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "For API access",
						"id_token":      "JWT with user identity claims",
						"refresh_token": "For obtaining new tokens",
						"token_type":    "Bearer",
						"expires_in":    "Token lifetime in seconds",
					},
				},
				{
					Order:       8,
					Name:        "Token Validation",
					Description: "Validate JWT signatures and claims",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Security: []string{"Verify signature using JWKS", "Validate iss, aud, exp, nonce claims"},
				},
				{
					Order:       9,
					Name:        "UserInfo Request (Optional)",
					Description: "Fetch additional user claims from UserInfo endpoint",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"authorization": "Bearer access_token",
					},
				},
			},
		},
		{
			ID:          "oidc_authorization_code",
			Name:        "OIDC Authorization Code Flow",
			Description: "OpenID Connect flow using authorization code for authentication",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Discovery",
					Description: "Client fetches OpenID Provider configuration",
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
					Description: "Client fetches public keys for token validation",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
				},
				{
					Order:       3,
					Name:        "Authentication Request",
					Description: "Client redirects user with openid scope",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"scope":         "openid required",
						"response_type": "code",
						"nonce":         "recommended for replay protection",
					},
					Security: []string{"Include nonce to bind ID token to session"},
				},
				{
					Order:       4,
					Name:        "User Authentication",
					Description: "User authenticates with the OpenID Provider",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
				},
				{
					Order:       5,
					Name:        "Authentication Response",
					Description: "OpenID Provider redirects with authorization code",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
				},
				{
					Order:       6,
					Name:        "Token Request",
					Description: "Client exchanges code for tokens",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
				},
				{
					Order:       7,
					Name:        "Token Response",
					Description: "OpenID Provider returns access token AND ID token",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"id_token":     "JWT with user identity claims",
						"access_token": "for accessing UserInfo endpoint",
					},
				},
				{
					Order:       8,
					Name:        "ID Token Validation",
					Description: "Client validates the ID token",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Security:    []string{"Verify signature using JWKS", "Validate iss, aud, exp, nonce"},
				},
				{
					Order:       9,
					Name:        "UserInfo Request (Optional)",
					Description: "Client requests additional user claims",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"authorization": "Bearer access_token",
					},
				},
			},
		},
		{
			ID:          "oidc_implicit",
			Name:        "OIDC Implicit Flow (Legacy)",
			Description: "Direct token response in redirect - not recommended for new applications",
			Executable:  true,
			Category:    "authentication",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Authentication Request",
					Description: "Client requests id_token directly",
					From:        "Client",
					To:          "OpenID Provider",
					Type:        "request",
					Parameters: map[string]string{
						"response_type": "id_token token",
						"nonce":         "required for implicit flow",
					},
					Security: []string{"Implicit flow is deprecated", "Tokens exposed in URL fragment"},
				},
				{
					Order:       2,
					Name:        "User Authentication",
					Description: "User authenticates",
					From:        "User",
					To:          "OpenID Provider",
					Type:        "internal",
				},
				{
					Order:       3,
					Name:        "Authentication Response",
					Description: "Tokens returned in URL fragment",
					From:        "OpenID Provider",
					To:          "Client",
					Type:        "response",
					Security:    []string{"Tokens visible in browser history", "Use authorization code flow instead"},
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

