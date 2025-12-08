package oauth2

import (
	"context"

	"github.com/go-chi/chi/v5"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
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
			Description: "Standard OAuth 2.0 authorization code flow for server-side applications",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Authorization Request",
					Description: "Client redirects user to authorization server",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"response_type": "code",
						"client_id":     "required",
						"redirect_uri":  "required",
						"scope":         "optional",
						"state":         "recommended",
					},
					Security: []string{"Use state parameter to prevent CSRF"},
				},
				{
					Order:       2,
					Name:        "User Authentication",
					Description: "User authenticates with the authorization server",
					From:        "User",
					To:          "Authorization Server",
					Type:        "internal",
				},
				{
					Order:       3,
					Name:        "Authorization Response",
					Description: "Authorization server redirects back with authorization code",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"code":  "authorization code",
						"state": "echoed from request",
					},
				},
				{
					Order:       4,
					Name:        "Token Request",
					Description: "Client exchanges authorization code for tokens",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":   "authorization_code",
						"code":         "authorization code",
						"redirect_uri": "must match original",
						"client_id":    "required",
					},
					Security: []string{"Must be sent over TLS", "Client authentication required for confidential clients"},
				},
				{
					Order:       5,
					Name:        "Token Response",
					Description: "Authorization server returns access token",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":  "the access token",
						"token_type":    "Bearer",
						"expires_in":    "token lifetime",
						"refresh_token": "optional",
					},
				},
			},
		},
		{
			ID:          "authorization_code_pkce",
			Name:        "Authorization Code Flow with PKCE",
			Description: "Authorization code flow with Proof Key for Code Exchange for public clients",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Generate PKCE Parameters",
					Description: "Client generates code_verifier and code_challenge",
					From:        "Client",
					To:          "Client",
					Type:        "internal",
					Security:    []string{"code_verifier must be high-entropy random", "Use S256 method, not plain"},
				},
				{
					Order:       2,
					Name:        "Authorization Request with PKCE",
					Description: "Client redirects user with code_challenge",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"response_type":         "code",
						"client_id":             "required",
						"redirect_uri":          "required",
						"code_challenge":        "required for PKCE",
						"code_challenge_method": "S256 recommended",
						"state":                 "recommended",
					},
				},
				{
					Order:       3,
					Name:        "User Authentication",
					Description: "User authenticates with the authorization server",
					From:        "User",
					To:          "Authorization Server",
					Type:        "internal",
				},
				{
					Order:       4,
					Name:        "Authorization Response",
					Description: "Authorization server redirects back with code",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
				},
				{
					Order:       5,
					Name:        "Token Request with code_verifier",
					Description: "Client exchanges code with code_verifier",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "authorization_code",
						"code":          "authorization code",
						"code_verifier": "original random string",
					},
					Security: []string{"Server validates code_verifier against stored code_challenge"},
				},
				{
					Order:       6,
					Name:        "Token Response",
					Description: "Authorization server validates PKCE and returns tokens",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
				},
			},
		},
		{
			ID:          "client_credentials",
			Name:        "Client Credentials Flow",
			Description: "Machine-to-machine authentication without user context",
			Executable:  true,
			Category:    "authorization",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Token Request",
					Description: "Client authenticates directly with its credentials",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type": "client_credentials",
						"scope":      "requested scopes",
					},
					Security: []string{"Client must authenticate", "Only for confidential clients"},
				},
				{
					Order:       2,
					Name:        "Token Response",
					Description: "Authorization server returns access token",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
				},
			},
		},
		{
			ID:          "refresh_token",
			Name:        "Refresh Token Flow",
			Description: "Obtain new access token using refresh token",
			Executable:  true,
			Category:    "token-management",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Refresh Request",
					Description: "Client presents refresh token",
					From:        "Client",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":    "refresh_token",
						"refresh_token": "the refresh token",
						"scope":         "optional, must not exceed original",
					},
				},
				{
					Order:       2,
					Name:        "Token Response",
					Description: "Server returns new access token (and optionally new refresh token)",
					From:        "Authorization Server",
					To:          "Client",
					Type:        "response",
					Security:    []string{"Implement refresh token rotation"},
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

