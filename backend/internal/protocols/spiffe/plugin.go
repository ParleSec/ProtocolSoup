// Package spiffe implements the SPIFFE/SPIRE protocol plugin for ProtocolLens.
// It provides educational visualization of SPIFFE workload identity concepts
// while demonstrating real SPIRE integration with actual SVIDs and mTLS.
package spiffe

import (
	"context"
	"log"

	"github.com/go-chi/chi/v5"
	"github.com/security-showcase/protocol-showcase/internal/lookingglass"
	"github.com/security-showcase/protocol-showcase/internal/plugin"
	spiffelib "github.com/security-showcase/protocol-showcase/internal/spiffe"
)

// Plugin implements the SPIFFE/SPIRE protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	workloadClient *spiffelib.WorkloadClient
	lookingGlass   *lookingglass.Engine
	baseURL        string
}

// NewPlugin creates a new SPIFFE protocol plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "spiffe",
			Name:        "SPIFFE/SPIRE",
			Version:     "1.0.0",
			Description: "Secure Production Identity Framework for Everyone - Workload identity with X.509 and JWT SVIDs",
			Tags:        []string{"identity", "mtls", "zero-trust", "workload", "certificates"},
			RFCs: []string{
				"SPIFFE",
				"SPIFFE-ID",
				"X509-SVID",
				"JWT-SVID",
				"SPIFFE-Workload-API",
				"SPIFFE-Federation",
			},
		}),
	}
}

// Initialize sets up the plugin with the provided configuration
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)

	// Extract looking glass engine
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	p.baseURL = config.BaseURL

	// Create SPIFFE workload client (non-blocking)
	spiffeCfg := spiffelib.DefaultConfig()
	
	// Check if SPIFFE is enabled via environment
	if spiffeCfg.Enabled {
		workloadClient, err := spiffelib.NewWorkloadClient(spiffeCfg)
		if err != nil {
			log.Printf("SPIFFE plugin: workload client creation failed (SPIFFE features disabled): %v", err)
		} else {
			p.workloadClient = workloadClient
			
			// Start the workload client in background - don't block server startup
			go func() {
				if err := workloadClient.Start(); err != nil {
					log.Printf("SPIFFE plugin: workload client start failed (running in demo mode): %v", err)
				} else {
					log.Printf("SPIFFE plugin: connected to Workload API successfully")
				}
			}()
		}
	} else {
		log.Printf("SPIFFE plugin: disabled, running in demo mode")
	}

	log.Println("SPIFFE/SPIRE plugin initialized")
	return nil
}

// Shutdown cleans up plugin resources
func (p *Plugin) Shutdown(ctx context.Context) error {
	if p.workloadClient != nil {
		return p.workloadClient.Close()
	}
	return nil
}

// RegisterRoutes sets up HTTP routes for the SPIFFE plugin
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// SPIFFE Bundle endpoint (per SPIFFE spec)
	router.Get("/.well-known/spiffe-bundle", p.handleTrustBundle)
	
	// SVID endpoints
	router.Get("/svid/x509", p.handleX509SVID)
	router.Get("/svid/x509/chain", p.handleX509SVIDChain)
	router.Get("/svid/jwt", p.handleJWTSVID)
	router.Get("/svid/info", p.handleSVIDInfo)
	
	// Validation endpoints
	router.Post("/validate/jwt", p.handleValidateJWT)
	router.Post("/validate/x509", p.handleValidateX509)
	
	// Workload information
	router.Get("/workload", p.handleWorkloadInfo)
	router.Get("/trust-bundle", p.handleTrustBundleInfo)
	
	// Demo endpoints for educational visualization
	router.Get("/demo/mtls", p.handleMTLSDemo)
	router.Post("/demo/mtls/call", p.handleMTLSCall)
	router.Get("/demo/jwt-auth", p.handleJWTAuthDemo)
	router.Post("/demo/jwt-auth/call", p.handleJWTAuthCall)
	router.Get("/demo/rotation", p.handleRotationDemo)
	
	// Status endpoint
	router.Get("/status", p.handleStatus)
}

// GetInspectors returns the protocol inspectors
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "x509-svid-inspector",
			Name:        "X.509-SVID Inspector",
			Description: "Inspect X.509 SPIFFE Verifiable Identity Documents",
			Type:        "certificate",
		},
		{
			ID:          "jwt-svid-inspector",
			Name:        "JWT-SVID Inspector",
			Description: "Inspect JWT SPIFFE Verifiable Identity Documents",
			Type:        "token",
		},
		{
			ID:          "trust-bundle-inspector",
			Name:        "Trust Bundle Inspector",
			Description: "Inspect SPIFFE trust bundles and certificate chains",
			Type:        "bundle",
		},
		{
			ID:          "spiffe-id-inspector",
			Name:        "SPIFFE ID Inspector",
			Description: "Parse and validate SPIFFE identifiers",
			Type:        "identifier",
		},
	}
}

// GetFlowDefinitions returns the protocol flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return getFlowDefinitions()
}

// GetDemoScenarios returns the available demo scenarios
// Only includes flows that can be executed via the Workload API
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "x509-svid-issuance",
			Name:        "X.509-SVID Acquisition",
			Description: "Acquire X.509 certificate with SPIFFE ID from SPIRE Workload API",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Connect to Workload API", Description: "Establish connection to SPIRE Agent socket", Auto: true},
				{Order: 2, Name: "Workload Attestation", Description: "Agent verifies caller identity via selectors", Auto: true},
				{Order: 3, Name: "SVID Issuance", Description: "Agent fetches X.509-SVID from SPIRE Server", Auto: true},
				{Order: 4, Name: "Certificate Delivery", Description: "X.509-SVID with private key returned to workload", Auto: true},
			},
		},
		{
			ID:          "jwt-svid-issuance",
			Name:        "JWT-SVID Acquisition",
			Description: "Acquire JWT token with SPIFFE claims from SPIRE Workload API",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Token Request", Description: "Request JWT-SVID with target audience", Auto: true},
				{Order: 2, Name: "Identity Verification", Description: "Agent verifies workload authorization", Auto: true},
				{Order: 3, Name: "JWT Generation", Description: "Server signs JWT with SPIFFE claims", Auto: true},
				{Order: 4, Name: "Token Delivery", Description: "JWT-SVID returned to workload", Auto: true},
			},
		},
		{
			ID:          "mtls-service-call",
			Name:        "mTLS Configuration",
			Description: "Prepare X.509-SVID and trust bundle for mutual TLS authentication",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Fetch X.509-SVID", Description: "Obtain certificate for client authentication", Auto: true},
				{Order: 2, Name: "Fetch Trust Bundle", Description: "Obtain CA certificates for peer verification", Auto: true},
				{Order: 3, Name: "TLS Configuration", Description: "Configure TLS with SVID and trust bundle", Auto: true},
				{Order: 4, Name: "mTLS Ready", Description: "Ready to establish mutually authenticated connections", Auto: true},
			},
		},
		{
			ID:          "certificate-rotation",
			Name:        "Certificate Rotation Analysis",
			Description: "Analyze current X.509-SVID and automatic rotation mechanism",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Current SVID", Description: "Fetch and display current X.509-SVID details", Auto: true},
				{Order: 2, Name: "Validity Analysis", Description: "Calculate time until rotation threshold", Auto: true},
				{Order: 3, Name: "Rotation Mechanism", Description: "Explain SPIRE streaming API rotation", Auto: true},
			},
		},
	}
}

// WorkloadClient returns the SPIFFE workload client (may be nil if not enabled)
func (p *Plugin) WorkloadClient() *spiffelib.WorkloadClient {
	return p.workloadClient
}

// IsEnabled returns whether SPIFFE is enabled and connected
func (p *Plugin) IsEnabled() bool {
	return p.workloadClient != nil && p.workloadClient.IsEnabled()
}

