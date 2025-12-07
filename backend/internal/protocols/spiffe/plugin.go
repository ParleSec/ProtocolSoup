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
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "x509-svid-issuance",
			Name:        "X.509-SVID Issuance",
			Description: "Demonstrate how workloads obtain X.509 certificates with SPIFFE IDs",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Workload Startup", Description: "Workload connects to SPIRE Agent Workload API", Auto: true},
				{Order: 2, Name: "Workload Attestation", Description: "Agent verifies workload identity via selectors", Auto: true},
				{Order: 3, Name: "SVID Request", Description: "Agent requests SVID from SPIRE Server", Auto: true},
				{Order: 4, Name: "SVID Issuance", Description: "Server generates X.509 certificate with SPIFFE ID", Auto: true},
				{Order: 5, Name: "SVID Delivery", Description: "Agent delivers SVID to workload", Auto: true},
			},
		},
		{
			ID:          "jwt-svid-issuance",
			Name:        "JWT-SVID Issuance",
			Description: "Demonstrate JWT-SVID creation for API authentication",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Token Request", Description: "Workload requests JWT-SVID with audience", Auto: false},
				{Order: 2, Name: "Identity Verification", Description: "Agent verifies workload is authorized", Auto: true},
				{Order: 3, Name: "JWT Generation", Description: "Server signs JWT with SPIFFE claims", Auto: true},
				{Order: 4, Name: "Token Delivery", Description: "JWT-SVID returned to workload", Auto: true},
			},
		},
		{
			ID:          "mtls-service-call",
			Name:        "mTLS Service-to-Service Call",
			Description: "Demonstrate mutual TLS authentication between services using X.509-SVIDs",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Client Initiates Connection", Description: "Client presents X.509-SVID certificate", Auto: false},
				{Order: 2, Name: "Server Certificate", Description: "Server responds with its X.509-SVID", Auto: true},
				{Order: 3, Name: "Mutual Verification", Description: "Both sides verify certificates against trust bundle", Auto: true},
				{Order: 4, Name: "SPIFFE ID Extraction", Description: "Extract SPIFFE IDs from SAN URI extension", Auto: true},
				{Order: 5, Name: "Authorization Check", Description: "Verify SPIFFE ID is authorized", Auto: true},
				{Order: 6, Name: "Secure Communication", Description: "Encrypted channel established", Auto: true},
			},
		},
		{
			ID:          "jwt-api-auth",
			Name:        "JWT-SVID API Authentication",
			Description: "Demonstrate API authentication using JWT-SVIDs",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Obtain JWT-SVID", Description: "Client requests JWT-SVID for target audience", Auto: false},
				{Order: 2, Name: "API Request", Description: "Include JWT-SVID in Authorization header", Auto: true},
				{Order: 3, Name: "Token Validation", Description: "API validates JWT signature against trust bundle", Auto: true},
				{Order: 4, Name: "Claims Verification", Description: "Verify SPIFFE ID and audience claims", Auto: true},
				{Order: 5, Name: "Authorization", Description: "Grant or deny access based on SPIFFE ID", Auto: true},
			},
		},
		{
			ID:          "certificate-rotation",
			Name:        "Automatic Certificate Rotation",
			Description: "Demonstrate automatic X.509-SVID rotation",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Current SVID", Description: "Display current X.509-SVID details", Auto: true},
				{Order: 2, Name: "Rotation Trigger", Description: "SVID approaches expiration threshold", Auto: true},
				{Order: 3, Name: "New SVID Request", Description: "Agent requests fresh SVID from server", Auto: true},
				{Order: 4, Name: "Seamless Update", Description: "New SVID delivered without service disruption", Auto: true},
				{Order: 5, Name: "Connection Migration", Description: "Active connections gracefully transition", Auto: true},
			},
		},
		{
			ID:          "workload-attestation",
			Name:        "Workload Attestation",
			Description: "Demonstrate how SPIRE identifies workloads",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Workload API Call", Description: "Workload connects to agent socket", Auto: true},
				{Order: 2, Name: "Process Inspection", Description: "Agent inspects calling process", Auto: true},
				{Order: 3, Name: "Selector Collection", Description: "Gather selectors (docker labels, unix uid, etc.)", Auto: true},
				{Order: 4, Name: "Registration Lookup", Description: "Match selectors against registration entries", Auto: true},
				{Order: 5, Name: "Identity Assignment", Description: "Assign SPIFFE ID based on matching entry", Auto: true},
			},
		},
		{
			ID:          "trust-bundle",
			Name:        "Trust Bundle Distribution",
			Description: "Demonstrate trust bundle management and distribution",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Bundle Generation", Description: "SPIRE Server generates root CA certificate", Auto: true},
				{Order: 2, Name: "Agent Sync", Description: "Agents receive trust bundle from server", Auto: true},
				{Order: 3, Name: "Workload Distribution", Description: "Workloads receive bundle via Workload API", Auto: true},
				{Order: 4, Name: "Bundle Endpoint", Description: "Bundle available at /.well-known/spiffe-bundle", Auto: true},
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

