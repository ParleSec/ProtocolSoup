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
// SSF has its own dedicated sandbox page, so we don't expose flows to Looking Glass
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{}
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
