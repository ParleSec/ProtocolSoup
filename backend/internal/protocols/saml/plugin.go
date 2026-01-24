package saml

import (
	"context"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// Plugin implements the SAML 2.0 protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
	// SAML-specific configuration
	entityID         string
	acsURL           string
	sloURL           string
	metadataURL      string
	ssoServiceURL    string
	sessions         map[string]*SAMLSession // sessionID -> session
	nameIDToSessions map[string][]string     // nameID -> list of sessionIDs (for SLO)
	// Pending login requests to avoid trusting form inputs
	loginRequests   map[string]LoginRequestInfo
	loginRequestsMu sync.RWMutex
	loginRequestTTL time.Duration

	// Security validation components (SAML 2.0 Core Section 5)
	signatureValidator *SignatureValidator // XML digital signature validator
	assertionCache     *AssertionCache     // Replay prevention (Profiles Section 4.1.4.5)
	requestIDCache     *RequestIDCache     // InResponseTo validation (Profiles Section 4.1.4.3)
}

// SAMLSession represents an active SAML session
type SAMLSession struct {
	ID              string
	NameID          string
	NameIDFormat    string
	SessionIndex    string
	Attributes      map[string][]string
	AuthnInstant    string
	NotOnOrAfter    string
	AssertionID     string
	SubjectLocality string
}

// NewPlugin creates a new SAML 2.0 plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "saml",
			Name:        "SAML 2.0",
			Version:     "1.0.0",
			Description: "Security Assertion Markup Language 2.0 for federated identity and SSO",
			Tags:        []string{"federation", "sso", "xml", "assertions", "identity"},
			RFCs:        []string{"SAML 2.0 Core", "SAML 2.0 Bindings", "SAML 2.0 Profiles"},
		}),
		sessions:           make(map[string]*SAMLSession),
		nameIDToSessions:   make(map[string][]string),
		loginRequests:      make(map[string]LoginRequestInfo),
		loginRequestTTL:    10 * time.Minute,
		signatureValidator: NewSignatureValidator(),
		// Assertion cache TTL matches typical assertion validity (5 minutes + clock skew)
		assertionCache: NewAssertionCache(10 * time.Minute),
		// Request ID cache TTL for pending requests (5 minutes is typical)
		requestIDCache: NewRequestIDCache(5 * time.Minute),
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

	// Configure SAML URLs
	p.entityID = p.baseURL + "/saml"
	p.acsURL = p.baseURL + "/saml/acs"
	p.sloURL = p.baseURL + "/saml/slo"
	p.metadataURL = p.baseURL + "/saml/metadata"
	p.ssoServiceURL = p.baseURL + "/saml/sso"

	go p.cleanupLoginRequests()

	return nil
}

// Shutdown shuts down the plugin
func (p *Plugin) Shutdown(ctx context.Context) error {
	// Clear all sessions
	p.sessions = make(map[string]*SAMLSession)
	p.nameIDToSessions = make(map[string][]string)
	return nil
}

// RegisterRoutes registers the plugin's HTTP routes
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// Metadata endpoint - SP/IdP metadata document
	router.Get("/metadata", p.handleMetadata)

	// SSO Service endpoints (IdP role)
	router.Get("/sso", p.handleSSOService)      // HTTP-Redirect binding
	router.Post("/sso", p.handleSSOServicePost) // HTTP-POST binding

	// Assertion Consumer Service endpoints (SP role)
	router.Get("/acs", p.handleACS)      // HTTP-Redirect binding (artifact)
	router.Post("/acs", p.handleACSPost) // HTTP-POST binding

	// Single Logout Service endpoints
	router.Get("/slo", p.handleSLO)      // HTTP-Redirect binding
	router.Post("/slo", p.handleSLOPost) // HTTP-POST binding

	// SP-initiated login trigger
	router.Get("/login", p.handleSPInitiatedLogin)
	router.Post("/login", p.handleSPInitiatedLoginSubmit)

	// IdP-initiated SSO
	router.Get("/idp-initiated", p.handleIdPInitiatedSSO)

	// Demo/utility endpoints
	router.Get("/demo/users", p.handleListUsers)
	router.Get("/demo/sessions", p.handleListSessions)
	router.Get("/demo/logout", p.handleDemoLogout)
	router.Post("/demo/logout", p.handleDemoLogout)

	// Looking Glass API endpoints - return raw SAML protocol data as JSON
	// These execute protocol operations for frontend visualization
	router.Get("/looking-glass/authn-request", p.handleLookingGlassCreateAuthnRequest)
	router.Post("/looking-glass/authenticate", p.handleLookingGlassAuthenticate)
	router.Get("/looking-glass/logout-request", p.handleLookingGlassCreateLogoutRequest)
	router.Post("/looking-glass/logout", p.handleLookingGlassProcessLogout)
}

// GetInspectors returns the protocol's inspectors
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "saml-assertion",
			Name:        "SAML Assertion Inspector",
			Description: "Decode and analyze SAML assertions and their attributes",
			Type:        "token",
		},
		{
			ID:          "saml-request",
			Name:        "SAML Request Inspector",
			Description: "Analyze AuthnRequest and LogoutRequest messages",
			Type:        "request",
		},
		{
			ID:          "saml-response",
			Name:        "SAML Response Inspector",
			Description: "Analyze SAML Response messages and status codes",
			Type:        "response",
		},
		{
			ID:          "saml-metadata",
			Name:        "SAML Metadata Inspector",
			Description: "Analyze SP and IdP metadata documents",
			Type:        "response",
		},
	}
}

// GetFlowDefinitions returns the protocol's flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "sp_initiated_sso",
			Name:        "SP-Initiated SSO",
			Description: "Service Provider initiated Single Sign-On flow",
			Executable:  true,
			Category:    "sso",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "User Accesses SP Resource",
					Description: "User attempts to access a protected resource at the Service Provider",
					From:        "User",
					To:          "Service Provider",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "SP Creates AuthnRequest",
					Description: "SP generates a SAML AuthnRequest message",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"ID":                          "unique request identifier",
						"IssueInstant":                "timestamp of request creation",
						"Issuer":                      "SP entity ID",
						"AssertionConsumerServiceURL": "where to send the response",
						"ProtocolBinding":             "HTTP-POST or HTTP-Redirect",
					},
					Security: []string{"AuthnRequest should be signed for integrity"},
				},
				{
					Order:       3,
					Name:        "Redirect to IdP",
					Description: "SP redirects user to IdP SSO Service with AuthnRequest",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "request",
					Parameters: map[string]string{
						"SAMLRequest": "base64-encoded (and deflated for redirect) AuthnRequest",
						"RelayState":  "opaque state to be echoed back",
						"SigAlg":      "signature algorithm (if signed)",
						"Signature":   "request signature (if signed)",
					},
				},
				{
					Order:       4,
					Name:        "User Authenticates",
					Description: "IdP authenticates the user (if not already authenticated)",
					From:        "User",
					To:          "Identity Provider",
					Type:        "internal",
				},
				{
					Order:       5,
					Name:        "IdP Creates Response",
					Description: "IdP generates SAML Response with Assertion",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"Status":         "success or error code",
						"Assertion":      "signed assertion with user identity",
						"NameID":         "user identifier",
						"Attributes":     "user attributes (optional)",
						"Conditions":     "validity constraints",
						"AuthnStatement": "authentication context",
					},
					Security: []string{
						"Response and/or Assertion MUST be signed",
						"Assertion should be encrypted for confidentiality",
					},
				},
				{
					Order:       6,
					Name:        "Response to SP",
					Description: "IdP sends SAML Response to SP's ACS",
					From:        "Identity Provider",
					To:          "Service Provider",
					Type:        "response",
					Parameters: map[string]string{
						"SAMLResponse": "base64-encoded SAML Response",
						"RelayState":   "echoed from request",
					},
				},
				{
					Order:       7,
					Name:        "SP Validates Response",
					Description: "SP validates signature, conditions, and extracts identity",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Security: []string{
						"Verify Response/Assertion signature",
						"Check InResponseTo matches original request",
						"Validate NotBefore/NotOnOrAfter conditions",
						"Verify Audience restriction",
						"Check for replay (assertion ID)",
					},
				},
				{
					Order:       8,
					Name:        "Session Created",
					Description: "SP creates local session and grants access",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
				},
			},
		},
		{
			ID:          "idp_initiated_sso",
			Name:        "IdP-Initiated SSO",
			Description: "Identity Provider initiated Single Sign-On flow (unsolicited response)",
			Executable:  true,
			Category:    "sso",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "User at IdP",
					Description: "User is authenticated at IdP and selects SP to access",
					From:        "User",
					To:          "Identity Provider",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "IdP Creates Unsolicited Response",
					Description: "IdP generates SAML Response without prior AuthnRequest",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"InResponseTo": "empty (no request to respond to)",
						"Destination":  "SP's ACS URL from metadata",
					},
					Security: []string{
						"No InResponseTo to validate - increased replay risk",
						"SP must use other means to prevent replay",
					},
				},
				{
					Order:       3,
					Name:        "Response to SP",
					Description: "IdP POSTs SAML Response to SP's ACS",
					From:        "Identity Provider",
					To:          "Service Provider",
					Type:        "response",
				},
				{
					Order:       4,
					Name:        "SP Validates Response",
					Description: "SP validates and creates session",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
				},
				{
					Order:       5,
					Name:        "Access Granted",
					Description: "User is granted access to SP resource",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
				},
			},
		},
		{
			ID:          "single_logout",
			Name:        "Single Logout (SLO)",
			Description: "Federated logout across all session participants",
			Executable:  true,
			Category:    "logout",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Logout Initiated",
					Description: "User initiates logout at one participant (SP or IdP)",
					From:        "User",
					To:          "Initiating Party",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "Create LogoutRequest",
					Description: "Initiating party creates LogoutRequest",
					From:        "Initiating Party",
					To:          "Initiating Party",
					Type:        "internal",
					Parameters: map[string]string{
						"NameID":       "identifier of user being logged out",
						"SessionIndex": "specific session to terminate (optional)",
						"Reason":       "logout reason (optional)",
					},
				},
				{
					Order:       3,
					Name:        "Send to IdP",
					Description: "LogoutRequest sent to IdP (if initiated at SP)",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "request",
				},
				{
					Order:       4,
					Name:        "IdP Propagates Logout",
					Description: "IdP sends LogoutRequest to all other SPs with sessions",
					From:        "Identity Provider",
					To:          "Other Service Providers",
					Type:        "request",
					Security:    []string{"Each SP must validate and terminate session"},
				},
				{
					Order:       5,
					Name:        "SPs Respond",
					Description: "Each SP terminates session and sends LogoutResponse",
					From:        "Service Providers",
					To:          "Identity Provider",
					Type:        "response",
				},
				{
					Order:       6,
					Name:        "IdP Terminates Session",
					Description: "IdP terminates its own session for the user",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
				},
				{
					Order:       7,
					Name:        "Final LogoutResponse",
					Description: "IdP sends LogoutResponse to initiating SP",
					From:        "Identity Provider",
					To:          "Initiating Service Provider",
					Type:        "response",
					Parameters: map[string]string{
						"Status": "Success or PartialLogout",
					},
				},
				{
					Order:       8,
					Name:        "Logout Complete",
					Description: "User is logged out of all participants",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
				},
			},
		},
	}
}

// GetDemoScenarios returns the protocol's demo scenarios
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "sp_initiated_sso_demo",
			Name:        "SP-Initiated SSO Demo",
			Description: "Interactive demonstration of SP-initiated Single Sign-On",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Access Protected Resource", Description: "Attempt to access SP without authentication", Auto: true},
				{Order: 2, Name: "Generate AuthnRequest", Description: "SP creates SAML AuthnRequest", Auto: true},
				{Order: 3, Name: "Redirect to IdP", Description: "User redirected to IdP SSO Service", Auto: true},
				{Order: 4, Name: "Authenticate User", Description: "Login as a demo user at IdP", Auto: false},
				{Order: 5, Name: "Receive SAML Response", Description: "IdP posts response to ACS", Auto: true},
				{Order: 6, Name: "Validate Assertion", Description: "SP validates signature and conditions", Auto: true},
				{Order: 7, Name: "Inspect Assertion", Description: "Examine the SAML assertion details", Auto: false},
			},
		},
		{
			ID:          "idp_initiated_sso_demo",
			Name:        "IdP-Initiated SSO Demo",
			Description: "Demonstration of unsolicited SAML response flow",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Authenticate at IdP", Description: "Login at the Identity Provider", Auto: false},
				{Order: 2, Name: "Select SP", Description: "Choose Service Provider to access", Auto: false},
				{Order: 3, Name: "Generate Response", Description: "IdP creates unsolicited SAML Response", Auto: true},
				{Order: 4, Name: "Post to ACS", Description: "Response posted to SP", Auto: true},
				{Order: 5, Name: "Session Created", Description: "SP creates session from assertion", Auto: true},
			},
		},
		{
			ID:          "single_logout_demo",
			Name:        "Single Logout Demo",
			Description: "Demonstrate federated logout across multiple SPs",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Establish Sessions", Description: "Login to multiple SPs via SSO", Auto: true},
				{Order: 2, Name: "Initiate Logout", Description: "Start logout at one SP", Auto: false},
				{Order: 3, Name: "LogoutRequest to IdP", Description: "SP sends LogoutRequest", Auto: true},
				{Order: 4, Name: "Propagate to SPs", Description: "IdP notifies other SPs", Auto: true},
				{Order: 5, Name: "Collect Responses", Description: "Gather LogoutResponses", Auto: true},
				{Order: 6, Name: "Final Response", Description: "IdP confirms complete logout", Auto: true},
			},
		},
		{
			ID:          "assertion_inspection",
			Name:        "SAML Assertion Deep Dive",
			Description: "Detailed inspection of SAML assertion structure",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Obtain Assertion", Description: "Complete SSO to get assertion", Auto: true},
				{Order: 2, Name: "XML Structure", Description: "Examine raw XML format", Auto: true},
				{Order: 3, Name: "Signature Verification", Description: "Validate XML signature", Auto: true},
				{Order: 4, Name: "Conditions Analysis", Description: "Check validity period and audience", Auto: true},
				{Order: 5, Name: "Attributes Mapping", Description: "Review attribute statements", Auto: false},
			},
		},
		{
			ID:          "metadata_exploration",
			Name:        "SAML Metadata Exploration",
			Description: "Understanding SP and IdP metadata documents",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Fetch SP Metadata", Description: "Get Service Provider metadata", Auto: true},
				{Order: 2, Name: "Examine Endpoints", Description: "Review ACS and SLO URLs", Auto: false},
				{Order: 3, Name: "View Certificates", Description: "Inspect signing certificates", Auto: true},
				{Order: 4, Name: "IdP Metadata", Description: "Compare with IdP metadata", Auto: true},
			},
		},
	}
}

// Helper methods for session management

// CreateSession creates a new SAML session
func (p *Plugin) CreateSession(session *SAMLSession) {
	p.sessions[session.ID] = session
	p.nameIDToSessions[session.NameID] = append(p.nameIDToSessions[session.NameID], session.ID)
}

// GetSession retrieves a session by ID
func (p *Plugin) GetSession(sessionID string) *SAMLSession {
	return p.sessions[sessionID]
}

// DeleteSession removes a session
func (p *Plugin) DeleteSession(sessionID string) {
	if session, exists := p.sessions[sessionID]; exists {
		// Remove from nameID mapping
		if sessions, ok := p.nameIDToSessions[session.NameID]; ok {
			for i, id := range sessions {
				if id == sessionID {
					p.nameIDToSessions[session.NameID] = append(sessions[:i], sessions[i+1:]...)
					break
				}
			}
		}
		delete(p.sessions, sessionID)
	}
}

// GetSessionsByNameID retrieves all sessions for a given NameID (for SLO)
func (p *Plugin) GetSessionsByNameID(nameID string) []*SAMLSession {
	var result []*SAMLSession
	if sessionIDs, ok := p.nameIDToSessions[nameID]; ok {
		for _, id := range sessionIDs {
			if session := p.sessions[id]; session != nil {
				result = append(result, session)
			}
		}
	}
	return result
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

// EntityID returns the SAML entity ID
func (p *Plugin) EntityID() string {
	return p.entityID
}

// ACSURL returns the Assertion Consumer Service URL
func (p *Plugin) ACSURL() string {
	return p.acsURL
}

// SLOURL returns the Single Logout Service URL
func (p *Plugin) SLOURL() string {
	return p.sloURL
}

// SignatureValidator returns the XML signature validator
func (p *Plugin) SignatureValidator() *SignatureValidator {
	return p.signatureValidator
}

// AssertionCache returns the assertion replay prevention cache
func (p *Plugin) AssertionCache() *AssertionCache {
	return p.assertionCache
}

// RequestIDCache returns the request ID cache for InResponseTo validation
func (p *Plugin) RequestIDCache() *RequestIDCache {
	return p.requestIDCache
}
