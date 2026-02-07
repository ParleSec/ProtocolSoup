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
			Description: "Service Provider initiated Single Sign-On using the SAML 2.0 Web Browser SSO Profile (saml-profiles §4.1). The SP detects an unauthenticated user, generates an AuthnRequest, and redirects the user to the IdP for authentication. After successful authentication, the IdP returns a signed SAML Response containing an Assertion with the user's identity. This is the most common SAML SSO flow in enterprise environments.",
			Executable:  true,
			Category:    "sso",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "User Accesses SP Resource",
					Description: "User's browser requests a protected resource at the Service Provider. The SP determines the user is not authenticated (no valid session cookie exists) and initiates the SSO flow. The SP saves the originally requested URL for post-authentication redirect (saml-profiles §4.1.4.1).",
					From:        "User",
					To:          "Service Provider",
					Type:        "request",
					Parameters: map[string]string{
						"target_resource": "The protected URL the user originally requested",
					},
					Security: []string{
						"SP MUST save the target resource URL securely for post-SSO redirect",
						"SP SHOULD NOT leak the target URL to third parties",
					},
				},
				{
					Order:       2,
					Name:        "SP Creates AuthnRequest",
					Description: "SP generates a SAML 2.0 AuthnRequest XML message (saml-core §3.4.1). The request identifies the SP (Issuer), specifies where to send the response (AssertionConsumerServiceURL), and may include constraints on how the IdP should authenticate the user. The ID attribute MUST be a unique, non-reusable identifier.",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"ID":                          "Unique request identifier (_hex or UUID format) (REQUIRED)",
						"Version":                     "2.0 (REQUIRED)",
						"IssueInstant":                "UTC timestamp of request creation (REQUIRED)",
						"Issuer":                      "SP's Entity ID from metadata (REQUIRED)",
						"AssertionConsumerServiceURL": "URL where IdP should POST the response (REQUIRED)",
						"ProtocolBinding":             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST (REQUIRED)",
						"Destination":                 "IdP's SSO Service URL (REQUIRED for signed requests)",
						"NameIDPolicy":                "Requested NameID format (e.g., emailAddress, persistent, transient)",
						"ForceAuthn":                  "Boolean - require fresh authentication even if IdP session exists",
						"IsPassive":                   "Boolean - do not visibly interact with user (fail if auth required)",
					},
					Security: []string{
						"AuthnRequest SHOULD be signed for integrity (saml-core §3.4.1)",
						"ID MUST be unique and non-reusable to enable InResponseTo correlation",
						"Destination attribute prevents request forwarding attacks",
						"AssertionConsumerServiceURL MUST match a registered ACS URL in SP metadata",
					},
				},
				{
					Order:       3,
					Name:        "Redirect to IdP",
					Description: "SP redirects the user's browser to the IdP's Single Sign-On Service URL with the AuthnRequest. Two bindings are supported: HTTP-Redirect (saml-bindings §3.4) sends the request as a URL query parameter with DEFLATE compression, and HTTP-POST (saml-bindings §3.5) sends it as a hidden form field. HTTP-Redirect is most common for requests.",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "request",
					Parameters: map[string]string{
						"SAMLRequest": "Base64-encoded (and DEFLATE-compressed for HTTP-Redirect) AuthnRequest XML",
						"RelayState":  "Opaque value (max 80 bytes) to preserve SP application state - echoed back in response",
						"SigAlg":      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 (if request is signed)",
						"Signature":   "Base64-encoded signature over SAMLRequest+RelayState+SigAlg (for HTTP-Redirect binding)",
					},
					Security: []string{
						"HTTP-Redirect binding applies DEFLATE compression then Base64 encoding (saml-bindings §3.4.4.1)",
						"Signature for HTTP-Redirect covers the serialized query string, not the XML (saml-bindings §3.4.4.1)",
						"RelayState MUST be integrity-protected to prevent manipulation",
						"HTTPS is REQUIRED to protect the AuthnRequest in transit",
					},
				},
				{
					Order:       4,
					Name:        "User Authenticates",
					Description: "Identity Provider authenticates the resource owner. If the user already has an active IdP session (SSO session cookie), the IdP may skip the login prompt unless ForceAuthn=true was specified in the AuthnRequest. The authentication method used determines the AuthnContext class in the response (saml-core §3.3.2.2).",
					From:        "User",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"authentication_method": "Password, MFA, X.509 certificate, Kerberos, etc.",
						"AuthnContextClassRef":  "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport (most common)",
						"session_check":         "IdP checks for existing SSO session before prompting login",
					},
					Security: []string{
						"IdP MUST authenticate the user before issuing an assertion - never rely on unauthenticated state",
						"ForceAuthn=true overrides existing SSO sessions (important for step-up authentication)",
						"Authentication method MUST be reflected accurately in AuthnContextClassRef",
					},
				},
				{
					Order:       5,
					Name:        "IdP Creates Response",
					Description: "IdP generates a SAML 2.0 Response containing one or more Assertions (saml-core §3.3.1). The Assertion includes a Subject (identifying the user via NameID), Conditions (validity time window and audience restriction), an AuthnStatement (proving authentication occurred), and optionally AttributeStatements (carrying user attributes like email, groups, roles).",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"Response.ID":             "Unique response identifier (REQUIRED)",
						"Response.InResponseTo":   "Must match the AuthnRequest ID (REQUIRED for SP-initiated)",
						"Response.Destination":    "SP's ACS URL (REQUIRED)",
						"Response.Status":         "urn:oasis:names:tc:SAML:2.0:status:Success or error code",
						"Assertion.Issuer":        "IdP's Entity ID (REQUIRED)",
						"Subject.NameID":          "User identifier in requested format (REQUIRED)",
						"Conditions.NotBefore":    "Earliest validity time (UTC timestamp)",
						"Conditions.NotOnOrAfter": "Latest validity time (UTC timestamp, typically 5 min window)",
						"Conditions.AudienceRestriction": "SP Entity ID(s) allowed to consume this assertion (REQUIRED)",
						"AuthnStatement.AuthnInstant":    "When authentication occurred (UTC timestamp)",
						"AuthnStatement.SessionIndex":    "IdP session identifier (for Single Logout)",
						"AttributeStatement":             "User attributes: email, displayName, groups, roles, etc.",
					},
					Security: []string{
						"Response and/or Assertion MUST be digitally signed (saml-core §5)",
						"Assertion SHOULD be encrypted to protect user attributes in transit (saml-core §6)",
						"NotOnOrAfter window SHOULD be narrow (2-5 minutes) to limit replay window",
						"AudienceRestriction MUST list only the intended SP to prevent assertion forwarding",
					},
				},
				{
					Order:       6,
					Name:        "Response to SP via POST",
					Description: "IdP sends the SAML Response to the SP's Assertion Consumer Service (ACS) URL using the HTTP-POST binding (saml-bindings §3.5). The IdP renders an auto-submitting HTML form in the user's browser containing the Base64-encoded Response and echoed RelayState. The browser automatically POSTs the form to the SP.",
					From:        "Identity Provider",
					To:          "Service Provider",
					Type:        "response",
					Parameters: map[string]string{
						"SAMLResponse": "Base64-encoded SAML Response XML (not DEFLATE-compressed for POST)",
						"RelayState":   "Echoed from original AuthnRequest - identifies target resource at SP",
					},
					Security: []string{
						"HTTP-POST binding uses Base64 only (no DEFLATE) - response may be large",
						"The signature is inside the XML document for HTTP-POST (enveloped signature)",
						"HTTPS protects the form POST from interception",
						"SP MUST verify Destination matches its own ACS URL",
					},
				},
				{
					Order:       7,
					Name:        "SP Validates Response",
					Description: "SP performs comprehensive validation of the SAML Response (saml-core §3.4.1.4 and saml-profiles §4.1.4.3). This is the most critical security step - every check MUST pass before accepting the user's identity. Failure to validate any of these conditions can lead to authentication bypass vulnerabilities.",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"signature_verify":    "Verify XML digital signature on Response and/or Assertion using IdP's public certificate",
						"decrypt_assertion":   "Decrypt EncryptedAssertion if encrypted (using SP's private key)",
						"InResponseTo_check":  "MUST match the original AuthnRequest ID sent by this SP",
						"Destination_check":   "MUST match this SP's ACS URL exactly",
						"Issuer_check":        "MUST match the IdP's Entity ID from metadata",
						"NotBefore_check":     "Current time MUST be on or after NotBefore (with clock skew tolerance)",
						"NotOnOrAfter_check":  "Current time MUST be before NotOnOrAfter (with clock skew tolerance)",
						"Audience_check":      "SP's Entity ID MUST be listed in AudienceRestriction",
						"replay_check":        "Assertion ID MUST NOT have been seen before (cache assertion IDs)",
						"SubjectConfirmation": "Verify SubjectConfirmationData (Recipient, NotOnOrAfter, InResponseTo)",
					},
					Security: []string{
						"CRITICAL: Verify XML signature before extracting any data from the assertion",
						"Protect against XML Signature Wrapping (XSW) attacks - verify signed element references",
						"InResponseTo prevents unsolicited response injection attacks",
						"Replay protection requires caching assertion IDs for the validity window",
						"Clock skew tolerance SHOULD be small (2-3 minutes max)",
						"If both Response and Assertion are signed, verify BOTH signatures",
					},
				},
				{
					Order:       8,
					Name:        "Session Created",
					Description: "After successful validation, the SP creates a local application session for the authenticated user. The SP extracts the NameID and any attributes from the assertion, maps them to a local user account (creating one if necessary via Just-In-Time provisioning), and redirects the user to the originally requested resource preserved in RelayState.",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
					Parameters: map[string]string{
						"session_cookie": "Secure, HttpOnly session cookie for the SP application",
						"NameID":         "Extracted user identifier from assertion",
						"SessionIndex":   "Stored for Single Logout support",
						"redirect_to":    "Original target resource from RelayState",
					},
					Security: []string{
						"Session cookie MUST be Secure, HttpOnly, and SameSite=Lax or Strict",
						"Store the NameID and SessionIndex for subsequent Single Logout requests",
						"JIT provisioning should validate user attributes before creating accounts",
					},
				},
			},
		},
		{
			ID:          "idp_initiated_sso",
			Name:        "IdP-Initiated SSO",
			Description: "Identity Provider initiated Single Sign-On where the IdP sends an unsolicited SAML Response to the SP without a preceding AuthnRequest (saml-profiles §4.1.5). The user starts at the IdP portal and selects an application to access. This flow has inherently weaker security properties than SP-initiated SSO because the SP cannot correlate the response to an original request, making replay and CSRF attacks harder to detect.",
			Executable:  true,
			Category:    "sso",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "User Selects Application at IdP",
					Description: "User is already authenticated at the Identity Provider (has an active IdP SSO session) and selects a Service Provider application from the IdP's application portal or dashboard. The IdP knows the user's identity and the target SP's metadata (ACS URL, Entity ID) from its configuration.",
					From:        "User",
					To:          "Identity Provider",
					Type:        "request",
					Parameters: map[string]string{
						"target_sp":     "SP Entity ID or application identifier selected by user",
						"idp_session":   "User's existing authenticated session at the IdP",
					},
					Security: []string{
						"User MUST be authenticated at the IdP before initiating SSO",
						"IdP SHOULD display which SP the user is about to access",
					},
				},
				{
					Order:       2,
					Name:        "IdP Creates Unsolicited Response",
					Description: "IdP generates a SAML Response and Assertion without a preceding AuthnRequest (saml-profiles §4.1.5). The Response has no InResponseTo attribute since there was no request to reference. The IdP uses the SP's ACS URL and Entity ID from pre-configured metadata to construct the Destination and AudienceRestriction.",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"Response.InResponseTo":   "ABSENT - no AuthnRequest to reference (key difference from SP-initiated)",
						"Response.Destination":    "SP's ACS URL from metadata (REQUIRED)",
						"Assertion.Issuer":        "IdP Entity ID (REQUIRED)",
						"Subject.NameID":          "User identifier in configured format",
						"Conditions.AudienceRestriction": "Target SP Entity ID (REQUIRED)",
						"Conditions.NotOnOrAfter":        "Short validity window (2-5 minutes)",
						"AuthnStatement.SessionIndex":    "IdP session ID for SLO support",
						"RelayState":                     "Optional - SP-specific target resource URL",
					},
					Security: []string{
						"No InResponseTo means SP cannot correlate to a request - increased replay risk",
						"NotOnOrAfter window SHOULD be especially narrow (2 minutes) to limit replay",
						"Response and Assertion MUST be signed to prevent forgery",
						"Assertion SHOULD be encrypted to protect attributes in transit",
					},
				},
				{
					Order:       3,
					Name:        "POST Response to SP",
					Description: "IdP delivers the SAML Response to the SP's Assertion Consumer Service URL via HTTP-POST binding (saml-bindings §3.5). The IdP renders an auto-submitting HTML form in the user's browser that POSTs the Base64-encoded Response to the SP's ACS endpoint.",
					From:        "Identity Provider",
					To:          "Service Provider",
					Type:        "response",
					Parameters: map[string]string{
						"SAMLResponse": "Base64-encoded SAML Response XML",
						"RelayState":   "Optional target URL at SP (if configured at IdP)",
					},
					Security: []string{
						"HTTP-POST binding is the only binding used for IdP-initiated SSO responses",
						"HTTPS protects the response in transit",
						"Auto-submit form prevents response from being cached by browser",
					},
				},
				{
					Order:       4,
					Name:        "SP Validates Unsolicited Response",
					Description: "SP validates the unsolicited SAML Response. Validation is the same as SP-initiated SSO with one critical difference: InResponseTo cannot be checked because no AuthnRequest was sent. The SP MUST use alternative anti-replay mechanisms such as caching assertion IDs within the NotOnOrAfter window (saml-profiles §4.1.5).",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"signature_verify":   "Verify digital signature using IdP certificate from metadata",
						"InResponseTo_check": "SKIPPED - no AuthnRequest was issued (IdP-initiated specific)",
						"Destination_check":  "MUST match this SP's ACS URL",
						"Issuer_check":       "MUST match configured IdP Entity ID",
						"NotBefore/NotOnOrAfter": "Validate time window with clock skew tolerance",
						"Audience_check":     "SP Entity ID MUST be in AudienceRestriction",
						"replay_check":       "CRITICAL - cache assertion IDs to detect reuse (only defense against replay)",
					},
					Security: []string{
						"CRITICAL: Without InResponseTo, assertion ID replay detection is the primary anti-replay defense",
						"Cache assertion IDs for at least the NotOnOrAfter duration",
						"Some security frameworks discourage IdP-initiated SSO due to weaker security properties",
						"Protect against XML Signature Wrapping attacks (same as SP-initiated)",
						"Consider requiring SP-initiated SSO for high-security applications",
					},
				},
				{
					Order:       5,
					Name:        "Session Created and Access Granted",
					Description: "After successful validation, the SP creates a local application session for the user. The SP maps the NameID to a local account, sets a secure session cookie, and redirects the user to either the RelayState URL (if provided) or a default landing page. The SP stores the SessionIndex for future Single Logout support.",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
					Parameters: map[string]string{
						"session_cookie": "Secure, HttpOnly session cookie",
						"redirect_to":   "RelayState URL or default SP landing page",
						"NameID":         "Mapped to local user account",
						"SessionIndex":   "Stored for Single Logout support",
					},
					Security: []string{
						"Session cookie MUST be Secure, HttpOnly, SameSite=Lax or Strict",
						"If RelayState is present, validate it points to a legitimate SP resource (open redirect prevention)",
						"Log the SSO event for audit including IdP Entity ID, NameID, and timestamp",
					},
				},
			},
		},
		{
			ID:          "single_logout",
			Name:        "Single Logout (SLO)",
			Description: "SAML 2.0 Single Logout Profile terminates sessions across all federated participants - the IdP and every SP with an active session for the user (saml-profiles §4.4). When a user logs out at one participant, LogoutRequest messages are propagated to all other participants to ensure global session termination. SLO uses either front-channel (HTTP-Redirect/POST via browser) or back-channel (SOAP direct communication) bindings.",
			Executable:  true,
			Category:    "logout",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "User Initiates Logout",
					Description: "User clicks logout at one SAML participant - either a Service Provider or the Identity Provider. The initiating party identifies all sessions associated with this user that need to be terminated. The user's NameID and SessionIndex (from the original SSO assertion) are used to identify the sessions.",
					From:        "User",
					To:          "Initiating Party",
					Type:        "request",
					Parameters: map[string]string{
						"initiator":     "SP or IdP where the user clicked logout",
						"NameID":        "User identifier from the original SSO assertion",
						"SessionIndex":  "Session identifier from AuthnStatement.SessionIndex",
					},
					Security: []string{
						"Logout action SHOULD be protected against CSRF (e.g., anti-forgery token)",
						"The initiating party must have stored NameID and SessionIndex from the original SSO",
					},
				},
				{
					Order:       2,
					Name:        "Create LogoutRequest",
					Description: "Initiating party constructs a SAML LogoutRequest message (saml-core §3.7.1). The request identifies the subject being logged out via NameID and optionally specifies which session to terminate via SessionIndex. The LogoutRequest is digitally signed.",
					From:        "Initiating Party",
					To:          "Initiating Party",
					Type:        "internal",
					Parameters: map[string]string{
						"ID":           "Unique request identifier (REQUIRED)",
						"Version":      "2.0 (REQUIRED)",
						"IssueInstant": "UTC timestamp (REQUIRED)",
						"Issuer":       "Entity ID of the initiating party (REQUIRED)",
						"Destination":  "IdP's Single Logout Service URL (REQUIRED for signed requests)",
						"NameID":       "User identifier matching the original assertion NameID (REQUIRED)",
						"SessionIndex": "Specific session to terminate - from AuthnStatement (OPTIONAL, but RECOMMENDED)",
						"Reason":       "urn:oasis:names:tc:SAML:2.0:logout:user (user-initiated) or admin/global",
						"NotOnOrAfter": "Request expiration timestamp to prevent late processing",
					},
					Security: []string{
						"LogoutRequest MUST be signed to prevent unauthorized logout attacks",
						"NameID in LogoutRequest MUST match exactly the NameID from the original SSO assertion",
						"Without SessionIndex, IdP terminates ALL sessions for the user at that SP",
					},
				},
				{
					Order:       3,
					Name:        "LogoutRequest Sent to IdP",
					Description: "If logout was initiated at an SP, the signed LogoutRequest is sent to the IdP's Single Logout Service URL using either HTTP-Redirect (saml-bindings §3.4) or HTTP-POST (saml-bindings §3.5) binding via the user's browser (front-channel). For back-channel SLO, the SP sends the request directly via SOAP.",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "request",
					Parameters: map[string]string{
						"SAMLRequest": "Base64-encoded (DEFLATE-compressed for Redirect) LogoutRequest XML",
						"RelayState":  "Opaque value to maintain state across logout flow (OPTIONAL)",
						"SigAlg":      "Signature algorithm (for HTTP-Redirect binding)",
						"Signature":   "Request signature (for HTTP-Redirect binding)",
						"binding":     "HTTP-Redirect, HTTP-POST (front-channel) or SOAP (back-channel)",
					},
					Security: []string{
						"Front-channel SLO relies on browser redirects - can fail if browser is closed",
						"Back-channel SOAP SLO is more reliable but requires direct SP-to-IdP connectivity",
						"IdP MUST verify the LogoutRequest signature before processing",
					},
				},
				{
					Order:       4,
					Name:        "IdP Propagates Logout to All SPs",
					Description: "The IdP identifies all other Service Providers that have active sessions for this user (tracked via SessionIndex values from previous SSO assertions). The IdP sends a separate LogoutRequest to each SP's Single Logout Service URL. For front-channel, this uses sequential browser redirects; for back-channel, SOAP requests are sent in parallel (saml-profiles §4.4.4).",
					From:        "Identity Provider",
					To:          "Other Service Providers",
					Type:        "request",
					Parameters: map[string]string{
						"target_sps":   "All SPs with active sessions for this user (excluding initiating SP)",
						"NameID":       "Same NameID used in each SP's original SSO assertion",
						"SessionIndex": "Session-specific identifier for each SP's session",
					},
					Security: []string{
						"Each LogoutRequest to each SP MUST be individually signed",
						"Front-channel SLO is sequential - failure at one SP may block propagation to others",
						"Back-channel SOAP SLO can be parallelized and is more reliable",
						"IdP SHOULD track partial logout failures and report them in the final response",
					},
				},
				{
					Order:       5,
					Name:        "SPs Terminate Sessions and Respond",
					Description: "Each SP receives the LogoutRequest, validates the signature and NameID, terminates the user's local session (invalidates session cookies and server-side session state), and returns a LogoutResponse to the IdP (saml-core §3.7.2). The LogoutResponse indicates success or failure of session termination.",
					From:        "Service Providers",
					To:          "Identity Provider",
					Type:        "response",
					Parameters: map[string]string{
						"LogoutResponse.Status": "urn:oasis:names:tc:SAML:2.0:status:Success (session terminated)",
						"LogoutResponse.InResponseTo": "MUST match the LogoutRequest ID",
						"LogoutResponse.Issuer":       "SP Entity ID",
					},
					Security: []string{
						"SP MUST invalidate session cookie AND server-side session state",
						"SP MUST verify LogoutRequest signature before terminating any session",
						"SP SHOULD return Success even if session was already expired (idempotent)",
						"LogoutResponse MUST be signed",
					},
				},
				{
					Order:       6,
					Name:        "IdP Terminates Own Session",
					Description: "After collecting responses from all SPs (or after timeout), the IdP terminates its own SSO session for the user. The IdP invalidates the user's SSO session cookie and removes any cached authentication state. This prevents the user from getting new SSO assertions at other SPs.",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"action":         "Invalidate IdP SSO session cookie and server state",
						"session_cookie": "IdP SSO session cookie cleared",
						"auth_state":     "Cached authentication context removed",
					},
					Security: []string{
						"IdP session MUST be invalidated to prevent new SSO assertions being issued",
						"Clear both the session cookie and server-side session data",
					},
				},
				{
					Order:       7,
					Name:        "Final LogoutResponse to Initiating SP",
					Description: "IdP sends a LogoutResponse back to the initiating SP's Single Logout Service URL (saml-core §3.7.2). The status indicates whether logout was fully successful (all SPs confirmed) or partially successful (some SPs failed). PartialLogout status means at least one SP did not confirm session termination.",
					From:        "Identity Provider",
					To:          "Initiating Service Provider",
					Type:        "response",
					Parameters: map[string]string{
						"SAMLResponse":  "Base64-encoded LogoutResponse XML",
						"Status":        "Success (all sessions terminated) or PartialLogout (some SPs failed)",
						"InResponseTo":  "MUST match the initiating SP's LogoutRequest ID",
						"RelayState":    "Echoed from original request (if provided)",
					},
					Security: []string{
						"LogoutResponse MUST be signed by the IdP",
						"PartialLogout indicates incomplete federated logout - user may still have active sessions",
						"SP SHOULD log PartialLogout events for security monitoring",
					},
				},
				{
					Order:       8,
					Name:        "Logout Complete",
					Description: "The initiating SP validates the LogoutResponse, confirms its own local session is terminated, and redirects the user to a logout confirmation page or login screen. If the status was PartialLogout, the SP may warn the user that some applications may still have active sessions.",
					From:        "Service Provider",
					To:          "User",
					Type:        "response",
					Parameters: map[string]string{
						"redirect_to": "Logout confirmation page or login screen",
						"status":      "Display logout success or partial logout warning",
					},
					Security: []string{
						"Display appropriate message based on Success vs PartialLogout status",
						"Clear all SP-side session artifacts (cookies, tokens, caches)",
						"Consider advising user to close browser if PartialLogout occurred",
					},
				},
			},
		},
		{
			ID:          "metadata",
			Name:        "Metadata Exchange",
			Description: "SAML 2.0 Metadata enables automated trust establishment between Identity Providers and Service Providers (SAML Metadata §2). Each party publishes an XML EntityDescriptor document describing their endpoints, supported bindings, certificates, and capabilities. This eliminates manual configuration and enables dynamic federation.",
			Executable:  false,
			Category:    "configuration",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "SP Publishes Metadata",
					Description: "Service Provider publishes its EntityDescriptor XML document at a well-known URL (SAML Metadata §2.3). The SPSSODescriptor element declares the SP's capabilities: Assertion Consumer Service (ACS) endpoints, supported NameID formats, and the X.509 certificate used for signing AuthnRequests.",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"entityID":                   "Globally unique identifier for the SP (REQUIRED, typically a URL)",
						"SPSSODescriptor":            "Contains all SP-specific SSO configuration (REQUIRED)",
						"AssertionConsumerService":    "URL(s) where IdP posts SAML Response - includes Binding and index attributes",
						"SingleLogoutService":         "URL(s) for logout requests (OPTIONAL)",
						"NameIDFormat":                "Supported formats: persistent, transient, emailAddress, unspecified (RECOMMENDED)",
						"AuthnRequestsSigned":         "Boolean - whether SP signs AuthnRequests (RECOMMENDED: true)",
						"WantAssertionsSigned":        "Boolean - whether SP requires signed assertions (RECOMMENDED: true)",
						"KeyDescriptor use=signing":   "X.509 certificate for verifying SP's AuthnRequest signatures",
						"KeyDescriptor use=encryption": "X.509 certificate for encrypting assertions sent to SP (OPTIONAL)",
					},
					Security: []string{
						"entityID MUST be globally unique - use your domain URL as convention",
						"SP metadata SHOULD be signed to prevent tampering (SAML Metadata §2.1)",
						"Include both signing and encryption certificates for defense in depth",
					},
				},
				{
					Order:       2,
					Name:        "IdP Publishes Metadata",
					Description: "Identity Provider publishes its EntityDescriptor XML document (SAML Metadata §2.4). The IDPSSODescriptor element declares SSO endpoints, supported bindings (HTTP-Redirect, HTTP-POST), the X.509 certificate used for signing SAML Responses, and supported NameID formats.",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"entityID":                  "Globally unique identifier for the IdP (REQUIRED, typically a URL)",
						"IDPSSODescriptor":          "Contains all IdP-specific SSO configuration (REQUIRED)",
						"SingleSignOnService":       "URL(s) for receiving AuthnRequests - one per binding (HTTP-Redirect, HTTP-POST)",
						"SingleLogoutService":        "URL(s) for logout (OPTIONAL)",
						"NameIDFormat":               "NameID formats the IdP supports (e.g., persistent, transient, emailAddress)",
						"WantAuthnRequestsSigned":    "Boolean - whether IdP requires signed AuthnRequests",
						"KeyDescriptor use=signing":  "X.509 certificate used to sign SAML Responses and Assertions",
					},
					Security: []string{
						"IdP signing certificate is critical - SPs use it to validate all SAML Responses",
						"IdP metadata SHOULD be signed to allow SPs to verify its authenticity",
						"Publish metadata at a stable, HTTPS-protected URL",
					},
				},
				{
					Order:       3,
					Name:        "Metadata Exchange",
					Description: "SP and IdP exchange metadata documents to establish mutual trust (SAML Metadata §4). Exchange methods include: manual upload, well-known URL fetch (e.g., /saml/metadata), or metadata aggregation services. Each party downloads and processes the other's metadata.",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "request",
					Parameters: map[string]string{
						"method":           "Typically HTTP GET to the partner's metadata URL",
						"well-known URL":   "Common patterns: /saml/metadata, /saml2/metadata, /.well-known/saml-metadata",
						"Content-Type":     "application/samlmetadata+xml (SAML Metadata §4.1)",
						"validUntil":       "Expiration timestamp on the EntityDescriptor (RECOMMENDED)",
						"cacheDuration":    "Suggested cache lifetime in ISO 8601 duration format (OPTIONAL)",
					},
					Security: []string{
						"ALWAYS fetch metadata over HTTPS to prevent man-in-the-middle attacks",
						"Verify the metadata XML signature before trusting the content",
						"Respect validUntil - reject expired metadata and re-fetch",
					},
				},
				{
					Order:       4,
					Name:        "SP Processes IdP Metadata",
					Description: "SP parses the IdP's EntityDescriptor to extract the configuration needed for SSO (SAML Metadata §2.4). SP stores the IdP's SSO endpoint URLs, signing certificate, supported NameID formats, and binding preferences.",
					From:        "Service Provider",
					To:          "Service Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"extract_SSO_URL":            "SingleSignOnService Location for each supported binding",
						"extract_SLO_URL":            "SingleLogoutService Location for logout (OPTIONAL)",
						"extract_signing_cert":       "X.509 certificate from KeyDescriptor use=signing",
						"extract_NameID_formats":     "Supported NameIDFormat values for AuthnRequest",
						"extract_binding_preference": "HTTP-Redirect vs HTTP-POST for AuthnRequest delivery",
					},
					Security: []string{
						"MUST validate IdP's X.509 certificate chain before trusting it",
						"Store the certificate securely - it is used to verify every SAML Response",
						"Monitor for certificate rotation by periodically re-fetching metadata",
					},
				},
				{
					Order:       5,
					Name:        "IdP Processes SP Metadata",
					Description: "IdP parses the SP's EntityDescriptor to configure the service provider relationship (SAML Metadata §2.3). IdP registers the SP's ACS endpoints, signing certificate, required NameID format, and attribute requirements.",
					From:        "Identity Provider",
					To:          "Identity Provider",
					Type:        "internal",
					Parameters: map[string]string{
						"register_ACS_URLs":        "AssertionConsumerService endpoints by binding and index",
						"register_SP_cert":         "X.509 certificate for verifying AuthnRequest signatures",
						"register_NameID_format":   "NameID format the SP expects (persistent, email, etc.)",
						"register_attribute_reqs":  "AttributeConsumingService declares which attributes SP needs",
						"register_SLO_endpoints":   "SingleLogoutService endpoints for coordinated logout",
					},
					Security: []string{
						"Validate SP's ACS URLs match the entityID domain to prevent assertion injection",
						"If AuthnRequestsSigned=true, IdP MUST reject unsigned AuthnRequests from this SP",
						"Only release attributes the SP has requested and the user has consented to",
					},
				},
				{
					Order:       6,
					Name:        "Trust Established",
					Description: "Both parties have processed each other's metadata and can now perform SSO flows. The SP can construct AuthnRequests targeting the IdP's SSO URL, and the IdP can post SAML Responses to the SP's ACS URL. Trust is anchored by the exchanged X.509 certificates.",
					From:        "Service Provider",
					To:          "Identity Provider",
					Type:        "response",
					Parameters: map[string]string{
						"SP_can":  "Send AuthnRequests to IdP's SingleSignOnService URL",
						"IdP_can": "Post SAML Responses to SP's AssertionConsumerService URL",
						"verify":  "Both parties validate signatures using exchanged certificates",
					},
					Security: []string{
						"Metadata is the foundation of SAML trust - compromise here compromises all SSO",
						"Implement metadata refresh to handle certificate rotation before expiry",
						"Consider metadata signing with a separate key for an additional layer of trust",
						"validUntil SHOULD be set to enforce periodic re-validation of the trust relationship",
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
