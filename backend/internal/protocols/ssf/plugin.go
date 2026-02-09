package ssf

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// Plugin implements the SSF protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	storage         *Storage
	transmitter     *Transmitter
	receiver        *Receiver
	receiverService *ReceiverService
	actionExecutor  *MockIdPActionExecutor
	lookingGlass    *lookingglass.Engine
	keySet          *crypto.KeySet
	baseURL         string
	receiverPort    int
	receiverToken   string // Bearer token for authenticated push delivery
}

// NewPlugin creates a new SSF plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "ssf",
			Name:        "Shared Signals Framework",
			Version:     "1.0.0",
			Description: "OpenID Shared Signals Framework - Real-time security event sharing with CAEP and RISC",
			Tags:        []string{"security", "signals", "events", "caep", "risc", "zero-trust", "set"},
			RFCs:        []string{"RFC 8417", "OpenID SSF 1.0", "CAEP", "RISC"},
		}),
	}
}

// Initialize initializes the SSF plugin
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = config.BaseURL

	// Configure standalone receiver port and token
	p.receiverPort = 8081
	if port := os.Getenv("SSF_RECEIVER_PORT"); port != "" {
		_, _ = fmt.Sscanf(port, "%d", &p.receiverPort)
	}
	p.receiverToken = os.Getenv("SSF_RECEIVER_TOKEN")
	if p.receiverToken == "" {
		// Generate a default token for local dev
		p.receiverToken = "ssf-receiver-token-" + randomString(16)
	}

	// Set up Looking Glass
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	// Get key set for SET signing
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}

	// Initialize SQLite storage
	dataDir := getDataDir()
	storage, err := NewStorage(dataDir)
	if err != nil {
		return err
	}
	p.storage = storage

	// Initialize transmitter
	var privateKey *rsa.PrivateKey
	var keyID string
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
		keyID = p.keySet.RSAKeyID()
	}
	p.transmitter = NewTransmitter(storage, privateKey, keyID, p.baseURL)

	// Initialize action executor for real state changes (shared by both receivers)
	p.actionExecutor = NewMockIdPActionExecutor(storage, p.baseURL)

	// Initialize legacy receiver (main port - used in production)
	var publicKey *rsa.PublicKey
	if p.keySet != nil {
		publicKey = &p.keySet.RSAPrivateKey().PublicKey
	}
	p.receiver = NewReceiver(publicKey, p.baseURL, p.baseURL+"/receiver", p.actionExecutor)

	// Initialize standalone receiver service on separate port (for local dev)
	p.receiverService = NewReceiverService(p.receiverPort, p.baseURL, p.receiverToken, p.actionExecutor)

	// Use internal endpoint for push delivery (works in both local and production)
	// In production, localhost:8081 isn't accessible, so use the main server's push endpoint
	receiverEndpoint := p.baseURL + "/ssf/push"

	// Start the standalone receiver in a goroutine
	go func() {
		log.Printf("[SSF] Starting standalone receiver service on port %d", p.receiverPort)
		if err := p.receiverService.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("[SSF] Receiver service error: %v", err)
		}
	}()

	// Start session cleanup goroutine (runs every hour, removes sessions older than 24h)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			maxAge := 24 * time.Hour
			dbCount, err := p.storage.CleanupOldSessions(context.Background(), maxAge)
			memCount := p.actionExecutor.CleanupOldSessions(maxAge)
			if err != nil {
				log.Printf("[SSF] Session cleanup error: %v", err)
			} else if dbCount > 0 || memCount > 0 {
				log.Printf("[SSF] Cleaned up %d old database sessions and %d memory states", dbCount, memCount)
			}
		}
	}()

	// Seed demo data
	if err := p.storage.SeedDemoData(ctx, p.baseURL); err != nil {
		log.Printf("Warning: failed to seed SSF demo data: %v", err)
	}

	// Update default stream to use internal receiver endpoint
	stream, err := p.storage.GetDefaultStream(ctx, p.baseURL)
	if err == nil {
		stream.DeliveryEndpoint = receiverEndpoint
		stream.BearerToken = "" // Internal endpoint doesn't need auth
		_ = p.storage.UpdateStream(ctx, *stream)
	}

	log.Printf("[SSF] Plugin initialized with storage at %s", dataDir)
	log.Printf("[SSF] Transmitter: %s", p.baseURL+"/ssf")
	log.Printf("[SSF] Standalone Receiver: http://localhost:%d/ssf", p.receiverPort)
	log.Printf("[SSF] Bearer Token: %s...", p.receiverToken[:20])
	return nil
}

// Shutdown cleans up plugin resources
func (p *Plugin) Shutdown(ctx context.Context) error {
	// Stop the standalone receiver service
	if p.receiverService != nil {
		if err := p.receiverService.Stop(ctx); err != nil {
			log.Printf("[SSF] Error stopping receiver service: %v", err)
		}
	}

	if p.storage != nil {
		return p.storage.Close()
	}
	return nil
}

// RegisterRoutes registers SSF HTTP endpoints
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// Plugin info
	router.Get("/info", p.handleInfo)

	// SSF Discovery (well-known)
	router.Get("/.well-known/ssf-configuration", p.handleSSFConfiguration)
	router.Get("/jwks", p.handleJWKS)

	// Stream management
	router.Get("/stream", p.handleGetStream)
	router.Patch("/stream", p.handleUpdateStream)

	// Stream status (SSF §6)
	router.Get("/status", p.handleGetStatus)
	router.Post("/status", p.handleUpdateStatus)

	// Stream verification (SSF §7)
	router.Post("/verify", p.handleVerification)

	// Subject management
	router.Get("/subjects", p.handleListSubjects)
	router.Post("/subjects", p.handleAddSubject)
	router.Delete("/subjects/{id}", p.handleDeleteSubject)

	// Action triggers (interactive sandbox)
	router.Post("/actions/{action}", p.handleTriggerAction)

	// Event delivery (legacy same-port receiver)
	router.Post("/push", p.handlePush)
	router.Get("/poll", p.handlePoll)
	router.Post("/poll", p.handlePoll)
	router.Post("/ack", p.handleAcknowledge)

	// Event history and logs
	router.Get("/events", p.handleGetEvents)
	router.Get("/received", p.handleGetReceivedEvents)
	router.Get("/responses", p.handleGetResponseActions)
	router.Delete("/logs", p.handleClearLogs)

	// Event types info
	router.Get("/event-types", p.handleGetEventTypes)

	// SET inspection
	router.Post("/decode", p.handleDecodeSET)

	// Standalone Receiver endpoints (proxy to the separate service)
	router.Get("/receiver/status", p.handleReceiverStatus)
	router.Get("/receiver/events", p.handleReceiverEvents)
	router.Get("/receiver/actions", p.handleReceiverActions)

	// Security state (real state from action executor)
	router.Get("/security-state", p.handleGetSecurityStates)
	router.Get("/security-state/{email}", p.handleGetSecurityState)
	router.Post("/security-state/{email}/reset", p.handleResetSecurityState)
}

// GetInspectors returns SSF inspectors for Looking Glass
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "ssf-set",
			Name:        "SET Inspector",
			Description: "Decode and inspect Security Event Tokens (SET)",
			Type:        "token",
		},
		{
			ID:          "ssf-event",
			Name:        "SSF Event Inspector",
			Description: "Visualize SSF events with CAEP/RISC metadata",
			Type:        "flow",
		},
	}
}

// GetFlowDefinitions returns SSF flow definitions for educational display
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "ssf-stream-configuration",
			Name:        "Stream Configuration",
			Description: "Configure an SSF stream between a Transmitter (IdP) and Receiver (RP). Defines event types, delivery methods, and subject formats.",
			Executable:  false,
			Category:    "stream-management",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Fetch Transmitter Configuration", Description: "Receiver discovers the Transmitter's SSF capabilities via the well-known configuration endpoint (SSF §3.1)", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"method": "GET", "endpoint": "/.well-known/ssf-configuration"}},
				{Order: 2, Name: "SSF Configuration Response", Description: "Transmitter returns SSF metadata: supported event types, delivery methods, and management endpoints", From: "Transmitter", To: "Receiver", Type: "response", Parameters: map[string]string{"issuer": "Transmitter identifier URL (REQUIRED)", "jwks_uri": "URL for SET signature verification keys", "configuration_endpoint": "URL to create/manage streams", "status_endpoint": "URL to query stream status", "add_subject_endpoint": "URL to add subjects to stream", "delivery_methods_supported": "['urn:ietf:rfc:8935', 'urn:ietf:rfc:8936']"}},
				{Order: 3, Name: "Create Stream Request", Description: "Receiver creates a new event stream by POSTing to the configuration_endpoint", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"method": "POST to configuration_endpoint", "Authorization": "Bearer {management_token}", "delivery": "{ method: 'urn:ietf:rfc:8935', endpoint_url: '...' }"}},
				{Order: 4, Name: "Stream Created Response", Description: "Transmitter creates the stream and returns its configuration including stream_id", From: "Transmitter", To: "Receiver", Type: "response", Parameters: map[string]string{"stream_id": "Unique stream identifier", "iss": "Transmitter issuer URL", "aud": "Receiver identifier", "events_delivered": "Event types that will be delivered"}},
				{Order: 5, Name: "Fetch JWKS", Description: "Receiver fetches the Transmitter's JSON Web Key Set for SET signature verification", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"method": "GET", "endpoint": "jwks_uri from configuration"}},
				{Order: 6, Name: "JWKS Response", Description: "Transmitter returns its public keys for verifying SET signatures", From: "Transmitter", To: "Receiver", Type: "response", Parameters: map[string]string{"keys": "Array of JWK objects", "kid": "Key ID - matches 'kid' in SET header"}},
			},
		},
		{
			ID:          "ssf-push-delivery",
			Name:        "Push Delivery",
			Description: "Real-time event delivery where the Transmitter POSTs Security Event Tokens (SETs) directly to the Receiver's endpoint (RFC 8935)",
			Executable:  false,
			Category:    "delivery",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Security Event Occurs", Description: "A security-relevant event occurs at the Transmitter (IdP)", From: "Transmitter", To: "Transmitter", Type: "internal", Parameters: map[string]string{"event_source": "User action, admin action, policy, or system"}},
				{Order: 2, Name: "Generate SET", Description: "Transmitter creates a Security Event Token (SET) - a signed JWT containing the event data (RFC 8417)", From: "Transmitter", To: "Transmitter", Type: "internal", Parameters: map[string]string{"iss": "Transmitter issuer URL (REQUIRED)", "aud": "Receiver identifier (REQUIRED)", "iat": "Issued-at timestamp (REQUIRED)", "jti": "Unique token identifier (REQUIRED)", "events": "Object with event type URI key and payload value"}},
				{Order: 3, Name: "Push Delivery Request", Description: "Transmitter POSTs the SET to the Receiver's push endpoint (RFC 8935 §2)", From: "Transmitter", To: "Receiver", Type: "request", Parameters: map[string]string{"method": "POST", "Content-Type": "application/secevent+jwt", "Accept": "application/json"}},
				{Order: 4, Name: "Receiver Validates SET", Description: "Receiver validates the SET: verify signature, check claims, detect replay", From: "Receiver", To: "Receiver", Type: "internal", Parameters: map[string]string{"signature": "Verify using Transmitter's JWKS", "iss": "Must match expected Transmitter", "aud": "Must include this Receiver", "jti": "Must not have been seen before (replay check)"}},
				{Order: 5, Name: "Process Event", Description: "Receiver processes the validated event and takes appropriate action", From: "Receiver", To: "Receiver", Type: "internal", Parameters: map[string]string{"action": "Terminate sessions, invalidate tokens, etc."}},
				{Order: 6, Name: "Acknowledgment Response", Description: "Receiver acknowledges receipt per RFC 8935 §2.2", From: "Receiver", To: "Transmitter", Type: "response", Parameters: map[string]string{"202 Accepted": "SET received and will be processed", "400 Bad Request": "Invalid SET format", "401 Unauthorized": "Authentication required", "403 Forbidden": "Not authorized for this subject"}},
			},
		},
		{
			ID:          "ssf-poll-delivery",
			Name:        "Poll Delivery",
			Description: "Receiver-initiated event retrieval where the Receiver periodically polls the Transmitter for pending events (RFC 8936)",
			Executable:  false,
			Category:    "delivery",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Poll Request", Description: "Receiver sends a poll request to retrieve pending SETs (RFC 8936 §2)", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"method": "POST", "Content-Type": "application/json", "Authorization": "Bearer {access_token}", "maxEvents": "Maximum number of SETs to return (optional)", "returnImmediately": "If false, long-poll until events available"}},
				{Order: 2, Name: "Poll Response with SETs", Description: "Transmitter returns pending SETs and indicates if more events are available", From: "Transmitter", To: "Receiver", Type: "response", Parameters: map[string]string{"sets": "Object mapping jti to SET (compact JWT string)", "moreAvailable": "true if additional events pending"}},
				{Order: 3, Name: "Validate Each SET", Description: "Receiver validates each SET in the response", From: "Receiver", To: "Receiver", Type: "internal", Parameters: map[string]string{"signature": "Verify using Transmitter's JWKS", "iss": "Must match expected Transmitter", "jti": "Track for acknowledgment"}},
				{Order: 4, Name: "Process Events", Description: "Receiver processes all validated events", From: "Receiver", To: "Receiver", Type: "internal", Parameters: map[string]string{"batch": "May process multiple events in single poll", "idempotency": "Handle potential duplicate delivery"}},
				{Order: 5, Name: "Acknowledge Events", Description: "Receiver acknowledges processed events in the next poll request (RFC 8936 §2.4)", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"acks": "Array of jti values successfully processed", "setErrs": "Object mapping jti to error for failed SETs"}},
			},
		},
		{
			ID:          "caep-session-revoked",
			Name:        "Session Revoked (CAEP)",
			Description: "Continuous Access Evaluation Profile event indicating a user session has been terminated (CAEP §3.1). Receiving systems must immediately invalidate the affected session.",
			Executable:  false,
			Category:    "caep-events",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Session Revocation Trigger", Description: "An event triggers session revocation at the IdP: user logout, admin action, or security policy", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"triggers": "Logout, admin revoke, policy violation, security incident"}},
				{Order: 2, Name: "Create Session Revoked SET", Description: "IdP creates a Security Event Token for the session-revoked event type (CAEP §3.1)", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"event_type": "https://schemas.openid.net/secevent/caep/event-type/session-revoked", "subject": "Subject identifier (email, iss_sub, etc.)", "initiating_entity": "admin | user | policy | system", "reason_admin": "Administrative log message (optional)", "reason_user": "User-friendly message (optional)", "event_timestamp": "When the event occurred (optional)"}},
				{Order: 3, Name: "Deliver SET to Receivers", Description: "Transmitter sends the SET to all subscribed Receivers via configured delivery method", From: "Transmitter", To: "All Subscribed Receivers", Type: "request", Parameters: map[string]string{"delivery": "Push (RFC 8935) or Poll (RFC 8936)"}},
				{Order: 4, Name: "Receiver Validates SET", Description: "Receiver validates the SET signature and claims", From: "Receiver (RP)", To: "Receiver (RP)", Type: "internal", Parameters: map[string]string{"signature": "Verify against Transmitter's JWKS", "event_type": "Must be session-revoked"}},
				{Order: 5, Name: "Terminate User Sessions", Description: "Receiver immediately terminates all sessions for the affected subject", From: "Receiver (RP)", To: "Session Store", Type: "internal", Parameters: map[string]string{"action": "Delete/invalidate all sessions for subject", "effect": "User immediately logged out"}},
				{Order: 6, Name: "Revoke Access Tokens", Description: "Receiver invalidates any cached or issued access tokens", From: "Receiver (RP)", To: "Token Store", Type: "internal", Parameters: map[string]string{"access_tokens": "Revoke all active access tokens", "refresh_tokens": "Revoke refresh tokens"}},
			},
		},
		{
			ID:          "caep-credential-change",
			Name:        "Credential Change (CAEP)",
			Description: "Event indicating a user's credentials have changed (CAEP §3.2). Receiving systems should force re-authentication.",
			Executable:  false,
			Category:    "caep-events",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Credential Change Occurs", Description: "User or admin changes credentials at the Identity Provider", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"credential_type": "password | pin | x509 | fido2-platform | fido2-roaming | fido-u2f | verifiable-credential | phone-voice | phone-sms | app", "change_type": "create | revoke | update"}},
				{Order: 2, Name: "Create Credential Change SET", Description: "IdP creates a Security Event Token for the credential-change event type (CAEP §3.2)", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"event_type": "https://schemas.openid.net/secevent/caep/event-type/credential-change", "credential_type": "Type of credential that changed (REQUIRED)", "change_type": "create | revoke | update (REQUIRED)", "initiating_entity": "admin | user | policy | system (optional)", "reason_admin": "Administrative log message (optional)"}},
				{Order: 3, Name: "Deliver SET to Receivers", Description: "Transmitter sends the credential change event to all subscribed Receivers", From: "Transmitter", To: "All Subscribed Receivers", Type: "request", Parameters: map[string]string{"delivery": "Push (RFC 8935) or Poll (RFC 8936)"}},
				{Order: 4, Name: "Receiver Validates SET", Description: "Receiver validates the SET before processing", From: "Receiver (RP)", To: "Receiver (RP)", Type: "internal", Parameters: map[string]string{"signature": "Verify against Transmitter's JWKS", "credential_type": "Check if relevant to this RP"}},
				{Order: 5, Name: "Invalidate Cached Credentials", Description: "Receiver invalidates any cached credential data and tokens issued with old credentials", From: "Receiver (RP)", To: "Credential Cache", Type: "internal", Parameters: map[string]string{"cached_tokens": "Invalidate tokens from old credentials", "cached_sessions": "May require re-authentication"}},
				{Order: 6, Name: "Force Re-authentication", Description: "Receiver requires the user to re-authenticate with new credentials", From: "Receiver (RP)", To: "User", Type: "redirect", Parameters: map[string]string{"prompt": "login", "max_age": "0 (force fresh authentication)"}},
			},
		},
		{
			ID:          "risc-account-disabled",
			Name:        "Account Disabled (RISC)",
			Description: "Risk Incident Sharing event indicating a user account has been disabled (RISC §2.2). Receiving systems must immediately block access.",
			Executable:  false,
			Category:    "risc-events",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Account Disabled", Description: "Administrator or automated system disables a user account due to security concerns", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"reason": "hijacking | bulk-account (per RISC spec)", "note": "hijacking = account takeover detected, bulk-account = mass compromise"}},
				{Order: 2, Name: "Create Account Disabled SET", Description: "IdP creates a Security Event Token for the account-disabled event type (RISC §2.2)", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"event_type": "https://schemas.openid.net/secevent/risc/event-type/account-disabled", "reason": "hijacking | bulk-account (optional)", "reason_admin": "Detailed reason for logging (optional)"}},
				{Order: 3, Name: "Deliver SET to Receivers", Description: "Transmitter sends the account-disabled event to all subscribed Receivers", From: "Transmitter", To: "All Subscribed Receivers", Type: "request", Parameters: map[string]string{"delivery": "Push (RFC 8935) or Poll (RFC 8936)", "note": "RISC events are security-critical - process immediately"}},
				{Order: 4, Name: "Receiver Validates SET", Description: "Receiver validates the SET - RISC events require immediate attention", From: "Receiver (RP)", To: "Receiver (RP)", Type: "internal", Parameters: map[string]string{"signature": "Verify against Transmitter's JWKS", "event_type": "Must be account-disabled"}},
				{Order: 5, Name: "Block All Access", Description: "Receiver immediately blocks all access for the disabled account", From: "Receiver (RP)", To: "Access Control", Type: "internal", Parameters: map[string]string{"sessions": "Terminate all active sessions", "tokens": "Revoke all access and refresh tokens", "new_auth": "Block new authentication attempts"}},
				{Order: 6, Name: "Update Local Account State", Description: "Receiver updates local account records to reflect disabled status", From: "Receiver (RP)", To: "User Store", Type: "internal", Parameters: map[string]string{"status": "disabled | suspended", "note": "Account may be re-enabled later via account-enabled event"}},
			},
		},
		{
			ID:          "risc-credential-compromise",
			Name:        "Credential Compromise (RISC)",
			Description: "Security event indicating a user's credentials may have been compromised (RISC §2.1). Requires immediate protective action by all Receivers.",
			Executable:  false,
			Category:    "risc-events",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Compromise Detection", Description: "Identity Provider detects potential credential compromise via breach database, anomaly detection, or external report", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"detection_source": "Breach database, anomaly detection, user report, external notification"}},
				{Order: 2, Name: "Create Credential Compromise SET", Description: "IdP creates a Security Event Token for the credential-compromise event type (RISC §2.1)", From: "Identity Provider", To: "Identity Provider", Type: "internal", Parameters: map[string]string{"event_type": "https://schemas.openid.net/secevent/risc/event-type/credential-compromise", "reason_admin": "Detailed compromise information for logging (optional)", "note": "Do NOT include actual compromised credential values in the SET"}},
				{Order: 3, Name: "Deliver SET to Receivers", Description: "Transmitter sends the credential-compromise event to all subscribed Receivers", From: "Transmitter", To: "All Subscribed Receivers", Type: "request", Parameters: map[string]string{"delivery": "Push (RFC 8935) or Poll (RFC 8936)", "note": "Receivers should prioritize processing RISC events"}},
				{Order: 4, Name: "Receiver Validates SET", Description: "Receiver validates the SET before taking protective action", From: "Receiver (RP)", To: "Receiver (RP)", Type: "internal", Parameters: map[string]string{"signature": "Verify against Transmitter's JWKS", "event_type": "Must be credential-compromise"}},
				{Order: 5, Name: "Terminate All Sessions", Description: "Receiver immediately terminates ALL sessions for the affected user across all devices", From: "Receiver (RP)", To: "Session Store", Type: "internal", Parameters: map[string]string{"scope": "All sessions across all devices", "action": "Immediate termination"}},
				{Order: 6, Name: "Revoke All Tokens and Keys", Description: "Receiver revokes ALL access tokens, refresh tokens, and API keys for the affected user", From: "Receiver (RP)", To: "Token Store", Type: "internal", Parameters: map[string]string{"access_tokens": "Revoke all", "refresh_tokens": "Revoke all", "api_keys": "Revoke all (if applicable)"}},
				{Order: 7, Name: "Force Password Reset", Description: "Receiver flags account for mandatory credential reset on next login", From: "Receiver (RP)", To: "User Store", Type: "internal", Parameters: map[string]string{"action": "Require password reset on next login", "account_state": "Limited access until credentials reset"}},
				{Order: 8, Name: "Log and Alert", Description: "Receiver logs the incident and may trigger security alerts for investigation", From: "Receiver (RP)", To: "Security Operations", Type: "internal", Parameters: map[string]string{"logging": "Preserve audit trail for investigation", "alerting": "Notify security team (implementation-specific)"}},
			},
		},
	}
}

// GetDemoScenarios returns interactive demo scenarios
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "ssf-sandbox",
			Name:        "SSF Interactive Sandbox",
			Description: "Explore SSF by triggering real security events and watching them flow through the system",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "View Subjects", Description: "See the test subjects available in the stream", Endpoint: "/ssf/subjects", Method: "GET", Auto: true},
				{Order: 2, Name: "Trigger Event", Description: "Click an action button to trigger a security event", Endpoint: "/ssf/actions/{action}", Method: "POST", Auto: false},
				{Order: 3, Name: "Watch Flow", Description: "Observe the event flow through transmitter to receiver", Auto: true},
				{Order: 4, Name: "See Response", Description: "View the automated response actions taken", Endpoint: "/ssf/responses", Method: "GET", Auto: true},
			},
		},
		{
			ID:          "session-revocation",
			Name:        "Session Revocation Demo",
			Description: "Revoke a user's session and watch the CAEP event propagate",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Select User", Description: "Choose a subject with active sessions", Auto: false},
				{Order: 2, Name: "Revoke Session", Description: "Trigger session-revoked event", Endpoint: "/ssf/actions/session-revoked", Method: "POST", Auto: false},
				{Order: 3, Name: "Observe", Description: "Watch sessions count decrease and event delivered", Auto: true},
			},
		},
		{
			ID:          "credential-compromise",
			Name:        "Credential Compromise Response",
			Description: "Simulate a credential compromise and observe the incident response",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Trigger Compromise", Description: "Flag user credentials as compromised", Endpoint: "/ssf/actions/credential-compromise", Method: "POST", Auto: false},
				{Order: 2, Name: "View Response Chain", Description: "Watch all automated response actions execute", Auto: true},
			},
		},
		{
			ID:          "delivery-comparison",
			Name:        "Push vs Poll Comparison",
			Description: "Compare push and poll delivery methods side by side",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Switch to Poll", Description: "Change stream delivery method to poll", Endpoint: "/ssf/stream", Method: "PATCH", Auto: false},
				{Order: 2, Name: "Trigger Event", Description: "Trigger an event and see it queue", Auto: false},
				{Order: 3, Name: "Manual Poll", Description: "Fetch events manually via poll endpoint", Endpoint: "/ssf/poll", Method: "POST", Auto: false},
				{Order: 4, Name: "Switch to Push", Description: "Change back to push delivery", Auto: false},
				{Order: 5, Name: "Trigger Event", Description: "Trigger event and see immediate delivery", Auto: false},
			},
		},
	}
}

// getDataDir returns the data directory for SSF storage
func getDataDir() string {
	if dir := os.Getenv("SSF_DATA_DIR"); dir != "" {
		return dir
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "./data"
	}
	return filepath.Join(cwd, "data")
}
