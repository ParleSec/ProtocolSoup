package ssf

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

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
		fmt.Sscanf(port, "%d", &p.receiverPort)
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

	// Initialize legacy receiver (for backward compat on same port)
	var publicKey *rsa.PublicKey
	if p.keySet != nil {
		publicKey = &p.keySet.RSAPrivateKey().PublicKey
	}
	p.receiver = NewReceiver(publicKey, p.baseURL, p.baseURL+"/receiver")

	// Initialize action executor for real state changes
	p.actionExecutor = NewMockIdPActionExecutor(p.baseURL)

	// Initialize standalone receiver service on separate port
	receiverEndpoint := fmt.Sprintf("http://localhost:%d/ssf/push", p.receiverPort)
	p.receiverService = NewReceiverService(p.receiverPort, p.baseURL, p.receiverToken, p.actionExecutor)

	// Start the standalone receiver in a goroutine
	go func() {
		log.Printf("[SSF] Starting standalone receiver service on port %d", p.receiverPort)
		if err := p.receiverService.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("[SSF] Receiver service error: %v", err)
		}
	}()

	// Seed demo data
	if err := p.storage.SeedDemoData(ctx, p.baseURL); err != nil {
		log.Printf("Warning: failed to seed SSF demo data: %v", err)
	}

	// Update default stream to use standalone receiver endpoint with token
	stream, err := p.storage.GetDefaultStream(ctx, p.baseURL)
	if err == nil {
		stream.DeliveryEndpoint = receiverEndpoint
		stream.BearerToken = p.receiverToken
		p.storage.UpdateStream(ctx, *stream)
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

// GetFlowDefinitions returns SSF flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "ssf-sandbox",
			Name:        "SSF Interactive Sandbox",
			Description: "Interactive sandbox for triggering and observing SSF events in real-time",
			Executable:  true,
			Category:    "sandbox",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Configure Stream", Description: "Set up event stream between transmitter and receiver", From: "Admin", To: "Transmitter", Type: "internal"},
				{Order: 2, Name: "Add Subjects", Description: "Add users/subjects to track in the stream", From: "Admin", To: "Transmitter", Type: "internal"},
				{Order: 3, Name: "Trigger Action", Description: "Trigger a security action (revoke session, compromise, etc.)", From: "Admin", To: "Transmitter", Type: "request"},
				{Order: 4, Name: "Generate SET", Description: "Create and sign Security Event Token", From: "Transmitter", To: "Transmitter", Type: "internal"},
				{Order: 5, Name: "Deliver Event", Description: "Push or Poll delivery to receiver", From: "Transmitter", To: "Receiver", Type: "request"},
				{Order: 6, Name: "Verify SET", Description: "Validate SET signature and claims", From: "Receiver", To: "Receiver", Type: "internal"},
				{Order: 7, Name: "Process Event", Description: "Parse event and determine response actions", From: "Receiver", To: "Receiver", Type: "internal"},
				{Order: 8, Name: "Execute Response", Description: "Execute automated response actions", From: "Receiver", To: "Systems", Type: "response"},
			},
		},
		{
			ID:          "caep-session-flow",
			Name:        "CAEP Session Revocation",
			Description: "Continuous Access Evaluation - Session revocation flow",
			Executable:  true,
			Category:    "caep",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Session Active", Description: "User has active session", From: "User", To: "Application", Type: "internal"},
				{Order: 2, Name: "Security Event", Description: "Admin revokes session or policy triggers revocation", From: "Admin/Policy", To: "IdP", Type: "request"},
				{Order: 3, Name: "Generate CAEP Event", Description: "IdP creates session-revoked SET", From: "IdP", To: "IdP", Type: "internal"},
				{Order: 4, Name: "Transmit SET", Description: "Push SET to all subscribed receivers", From: "IdP", To: "Applications", Type: "request"},
				{Order: 5, Name: "Terminate Session", Description: "Application immediately terminates user session", From: "Application", To: "User", Type: "response"},
			},
		},
		{
			ID:          "risc-compromise-flow",
			Name:        "RISC Credential Compromise",
			Description: "Risk Incident Sharing - Credential compromise response",
			Executable:  true,
			Category:    "risc",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Compromise Detected", Description: "Credentials found in breach database or suspicious activity detected", From: "Security System", To: "IdP", Type: "request"},
				{Order: 2, Name: "Generate RISC Event", Description: "IdP creates credential-compromise SET", From: "IdP", To: "IdP", Type: "internal"},
				{Order: 3, Name: "Broadcast Alert", Description: "Push SET to all connected applications", From: "IdP", To: "All Receivers", Type: "request"},
				{Order: 4, Name: "Revoke Access", Description: "Applications revoke all tokens and API keys", From: "Applications", To: "Applications", Type: "internal"},
				{Order: 5, Name: "Force Password Reset", Description: "Require user to change password", From: "IdP", To: "User", Type: "response"},
				{Order: 6, Name: "Enable Step-up Auth", Description: "Require additional authentication factors", From: "Applications", To: "User", Type: "response"},
			},
		},
		{
			ID:          "push-delivery-flow",
			Name:        "Push Delivery Method",
			Description: "Webhook-based real-time event delivery",
			Executable:  true,
			Category:    "delivery",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Event Generated", Description: "Security event occurs and SET is created", From: "Transmitter", To: "Transmitter", Type: "internal"},
				{Order: 2, Name: "HTTP POST", Description: "POST SET to receiver's webhook endpoint", From: "Transmitter", To: "Receiver", Type: "request", Parameters: map[string]string{"method": "POST", "content-type": "application/json"}},
				{Order: 3, Name: "Verify & Process", Description: "Receiver verifies signature and processes event", From: "Receiver", To: "Receiver", Type: "internal"},
				{Order: 4, Name: "Acknowledge", Description: "Return success status", From: "Receiver", To: "Transmitter", Type: "response"},
			},
		},
		{
			ID:          "poll-delivery-flow",
			Name:        "Poll Delivery Method",
			Description: "Receiver-initiated event retrieval",
			Executable:  true,
			Category:    "delivery",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Events Queued", Description: "Events accumulate in transmitter queue", From: "Transmitter", To: "Transmitter", Type: "internal"},
				{Order: 2, Name: "Poll Request", Description: "Receiver requests pending events", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"method": "GET/POST", "endpoint": "/poll"}},
				{Order: 3, Name: "Return SETs", Description: "Transmitter returns batch of SET tokens", From: "Transmitter", To: "Receiver", Type: "response"},
				{Order: 4, Name: "Process Events", Description: "Receiver processes all events in batch", From: "Receiver", To: "Receiver", Type: "internal"},
				{Order: 5, Name: "Acknowledge", Description: "Receiver acknowledges processed events", From: "Receiver", To: "Transmitter", Type: "request", Parameters: map[string]string{"endpoint": "/ack"}},
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
