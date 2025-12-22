package scim

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// Plugin implements the SCIM 2.0 protocol plugin
type Plugin struct {
	*plugin.BasePlugin
	storage      *Storage
	lookingGlass *lookingglass.Engine
	baseURL      string
	client       *Client
}

// NewPlugin creates a new SCIM 2.0 plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "scim",
			Name:        "SCIM 2.0",
			Version:     "1.0.0",
			Description: "System for Cross-domain Identity Management - RFC 7642, 7643, 7644",
			Tags:        []string{"provisioning", "identity", "lifecycle", "users", "groups"},
			RFCs:        []string{"RFC 7642", "RFC 7643", "RFC 7644"},
		}),
	}
}

// Initialize initializes the SCIM plugin
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = config.BaseURL

	// Set up Looking Glass
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	// Initialize SQLite storage
	dataDir := getDataDir()
	storage, err := NewStorage(dataDir)
	if err != nil {
		return err
	}
	p.storage = storage

	// Seed demo data
	if err := p.storage.SeedDemoData(ctx, p.baseURL); err != nil {
		log.Printf("Warning: failed to seed SCIM demo data: %v", err)
	}

	// Initialize SCIM client for outbound provisioning
	p.client = NewClient("", "") // Empty URL, configured per-request

	log.Printf("SCIM 2.0 plugin initialized with storage at %s", dataDir)
	return nil
}

// Shutdown cleans up plugin resources
func (p *Plugin) Shutdown(ctx context.Context) error {
	if p.storage != nil {
		return p.storage.Close()
	}
	return nil
}

// RegisterRoutes registers SCIM HTTP endpoints
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// SCIM 2.0 routes at /v2/* (mounted under /scim by server)
	router.Route("/v2", func(r chi.Router) {
		// Apply authentication middleware to all SCIM endpoints
		// This validates Bearer tokens from Okta/Azure AD/etc.
		r.Use(AuthMiddleware)

		// Discovery endpoints (these are typically public in SCIM spec)
		r.Get("/ServiceProviderConfig", p.handleServiceProviderConfig)
		r.Get("/ResourceTypes", p.handleResourceTypes)
		r.Get("/ResourceTypes/{id}", p.handleResourceType)
		r.Get("/Schemas", p.handleSchemas)
		r.Get("/Schemas/{id}", p.handleSchema)

		// User endpoints - protected, require valid Bearer token
		r.Get("/Users", p.handleListUsers)
		r.Post("/Users", p.handleCreateUser)
		r.Get("/Users/{id}", p.handleGetUser)
		r.Put("/Users/{id}", p.handleReplaceUser)
		r.Patch("/Users/{id}", p.handlePatchUser)
		r.Delete("/Users/{id}", p.handleDeleteUser)

		// Group endpoints - protected
		r.Get("/Groups", p.handleListGroups)
		r.Post("/Groups", p.handleCreateGroup)
		r.Get("/Groups/{id}", p.handleGetGroup)
		r.Put("/Groups/{id}", p.handleReplaceGroup)
		r.Patch("/Groups/{id}", p.handlePatchGroup)
		r.Delete("/Groups/{id}", p.handleDeleteGroup)

		// Bulk operations - protected
		r.Post("/Bulk", p.handleBulk)

		// Search via POST - protected
		r.Post("/.search", p.handleSearch)
	})

	// API info endpoint (mounted under /scim, so this becomes /scim/info)
	router.Get("/info", p.handleInfo)

	// Provisioning events log (for Looking Glass to display)
	router.Get("/events", p.handleProvisioningEvents)

	// Connection status (for frontend to check Okta connection)
	router.Get("/status", p.handleConnectionStatus)

	// Internal token endpoint for Looking Glass (same-origin only)
	// This allows the frontend to autofill the bearer token for SCIM flows
	router.Get("/internal/token", HandleInternalToken)

	// Client provisioning endpoints (for demo)
	router.Route("/client", func(r chi.Router) {
		r.Post("/provision", p.handleClientProvision)
		r.Post("/sync", p.handleClientSync)
	})
}

// GetInspectors returns SCIM inspectors for Looking Glass
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "scim-resource",
			Name:        "SCIM Resource Inspector",
			Description: "Inspect SCIM User and Group resources with schema validation",
			Type:        "request",
		},
		{
			ID:          "scim-filter",
			Name:        "SCIM Filter Inspector",
			Description: "Parse and visualize SCIM filter expressions",
			Type:        "request",
		},
		{
			ID:          "scim-patch",
			Name:        "SCIM PATCH Inspector",
			Description: "Visualize PATCH operations and attribute changes",
			Type:        "request",
		},
	}
}

// GetFlowDefinitions returns SCIM flow definitions
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "user-lifecycle",
			Name:        "User Lifecycle",
			Description: "Complete user provisioning lifecycle: Create → Update → Deactivate → Delete",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Create User", Description: "POST /Users - Create a new user account", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"method": "POST", "endpoint": "/Users"}},
				{Order: 2, Name: "User Created", Description: "201 Created with user resource and ID", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 3, Name: "Update User", Description: "PATCH /Users/{id} - Modify user attributes", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"method": "PATCH", "endpoint": "/Users/{id}"}},
				{Order: 4, Name: "User Updated", Description: "200 OK with updated user resource", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 5, Name: "Deactivate User", Description: "PATCH /Users/{id} - Set active=false", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"method": "PATCH", "path": "active", "value": "false"}},
				{Order: 6, Name: "User Deactivated", Description: "200 OK with deactivated user", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 7, Name: "Delete User", Description: "DELETE /Users/{id} - Permanently remove user", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"method": "DELETE", "endpoint": "/Users/{id}"}},
				{Order: 8, Name: "User Deleted", Description: "204 No Content", From: "SCIM Server", To: "IdP", Type: "response"},
			},
		},
		{
			ID:          "group-membership",
			Name:        "Group Membership Management",
			Description: "Add and remove users from groups using PATCH operations",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Create Group", Description: "POST /Groups - Create a new group", From: "IdP", To: "SCIM Server", Type: "request"},
				{Order: 2, Name: "Group Created", Description: "201 Created with group resource", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 3, Name: "Add Member", Description: "PATCH /Groups/{id} - Add user to group members", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"op": "add", "path": "members"}},
				{Order: 4, Name: "Member Added", Description: "200 OK with updated group", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 5, Name: "Remove Member", Description: "PATCH /Groups/{id} - Remove user from group", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"op": "remove", "path": "members[value eq \"user-id\"]"}},
				{Order: 6, Name: "Member Removed", Description: "200 OK with updated group", From: "SCIM Server", To: "IdP", Type: "response"},
			},
		},
		{
			ID:          "user-discovery",
			Name:        "User Discovery with Filters",
			Description: "Query users using SCIM filter expressions",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "List All Users", Description: "GET /Users - Retrieve all users", From: "IdP", To: "SCIM Server", Type: "request"},
				{Order: 2, Name: "Users List", Description: "200 OK with ListResponse containing users", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 3, Name: "Filter by Username", Description: "GET /Users?filter=userName eq \"alice@example.com\"", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"filter": "userName eq \"alice@example.com\""}},
				{Order: 4, Name: "Filtered Results", Description: "200 OK with matching users", From: "SCIM Server", To: "IdP", Type: "response"},
				{Order: 5, Name: "Complex Filter", Description: "GET /Users?filter=emails.type eq \"work\" and active eq true", From: "IdP", To: "SCIM Server", Type: "request"},
				{Order: 6, Name: "Complex Results", Description: "200 OK with matching users", From: "SCIM Server", To: "IdP", Type: "response"},
			},
		},
		{
			ID:          "bulk-operations",
			Name:        "Bulk Operations",
			Description: "Execute multiple SCIM operations in a single request",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Bulk Request", Description: "POST /Bulk - Submit multiple operations", From: "IdP", To: "SCIM Server", Type: "request", Parameters: map[string]string{"operations": "multiple"}},
				{Order: 2, Name: "Process Operations", Description: "Server processes each operation sequentially", From: "SCIM Server", To: "SCIM Server", Type: "internal"},
				{Order: 3, Name: "Bulk Response", Description: "200 OK with operation results", From: "SCIM Server", To: "IdP", Type: "response"},
			},
		},
		{
			ID:          "schema-discovery",
			Name:        "Schema Discovery",
			Description: "Discover SCIM server capabilities and schemas",
			Executable:  true,
			Category:    "discovery",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Get Config", Description: "GET /ServiceProviderConfig - Server capabilities", From: "Client", To: "SCIM Server", Type: "request"},
				{Order: 2, Name: "Config Response", Description: "Supported features: patch, bulk, filter, etc.", From: "SCIM Server", To: "Client", Type: "response"},
				{Order: 3, Name: "Get Resource Types", Description: "GET /ResourceTypes - Available resource types", From: "Client", To: "SCIM Server", Type: "request"},
				{Order: 4, Name: "Resource Types", Description: "User, Group definitions", From: "SCIM Server", To: "Client", Type: "response"},
				{Order: 5, Name: "Get Schemas", Description: "GET /Schemas - Full schema definitions", From: "Client", To: "SCIM Server", Type: "request"},
				{Order: 6, Name: "Schemas Response", Description: "Complete attribute definitions", From: "SCIM Server", To: "Client", Type: "response"},
			},
		},
		{
			ID:          "outbound-provisioning",
			Name:        "Outbound Provisioning",
			Description: "Provision users to an external SCIM server",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{Order: 1, Name: "Configure Target", Description: "Set external SCIM server URL and credentials", From: "Admin", To: "SCIM Client", Type: "internal"},
				{Order: 2, Name: "Discover Target", Description: "GET /ServiceProviderConfig on target", From: "SCIM Client", To: "External Server", Type: "request"},
				{Order: 3, Name: "Create User", Description: "POST /Users to external server", From: "SCIM Client", To: "External Server", Type: "request"},
				{Order: 4, Name: "User Created", Description: "201 Created from external server", From: "External Server", To: "SCIM Client", Type: "response"},
				{Order: 5, Name: "Record Mapping", Description: "Store local-to-external ID mapping", From: "SCIM Client", To: "Database", Type: "internal"},
			},
		},
	}
}

// GetDemoScenarios returns interactive demo scenarios
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "basic-provisioning",
			Name:        "Basic User Provisioning",
			Description: "Create, read, update, and delete a user via SCIM",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create User", Description: "Create a new user with POST /Users", Endpoint: "/scim/v2/Users", Method: "POST", Auto: false},
				{Order: 2, Name: "Get User", Description: "Retrieve the created user", Endpoint: "/scim/v2/Users/{id}", Method: "GET", Auto: true},
				{Order: 3, Name: "Update User", Description: "Modify user attributes with PATCH", Endpoint: "/scim/v2/Users/{id}", Method: "PATCH", Auto: false},
				{Order: 4, Name: "Delete User", Description: "Remove the user", Endpoint: "/scim/v2/Users/{id}", Method: "DELETE", Auto: false},
			},
		},
		{
			ID:          "filter-demo",
			Name:        "Filter Expression Demo",
			Description: "Explore SCIM filter syntax with live examples",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Simple Equality", Description: "Filter: userName eq \"alice@example.com\"", Endpoint: "/scim/v2/Users", Method: "GET", Auto: false},
				{Order: 2, Name: "Contains", Description: "Filter: emails.value co \"@example.com\"", Endpoint: "/scim/v2/Users", Method: "GET", Auto: false},
				{Order: 3, Name: "Logical AND", Description: "Filter: active eq true and userType eq \"Employee\"", Endpoint: "/scim/v2/Users", Method: "GET", Auto: false},
				{Order: 4, Name: "Value Path", Description: "Filter: emails[type eq \"work\"].value sw \"admin\"", Endpoint: "/scim/v2/Users", Method: "GET", Auto: false},
			},
		},
		{
			ID:          "patch-operations",
			Name:        "PATCH Operations Demo",
			Description: "Demonstrate add, remove, and replace operations",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Add Email", Description: "Add a new email address to user", Endpoint: "/scim/v2/Users/{id}", Method: "PATCH", Auto: false},
				{Order: 2, Name: "Replace Name", Description: "Replace the user's name", Endpoint: "/scim/v2/Users/{id}", Method: "PATCH", Auto: false},
				{Order: 3, Name: "Remove Phone", Description: "Remove a phone number by filter", Endpoint: "/scim/v2/Users/{id}", Method: "PATCH", Auto: false},
			},
		},
	}
}

// getDataDir returns the data directory for SCIM storage
func getDataDir() string {
	// Check environment variable
	if dir := os.Getenv("SCIM_DATA_DIR"); dir != "" {
		return dir
	}

	// Default to ./data in current directory
	cwd, err := os.Getwd()
	if err != nil {
		return "./data"
	}
	return filepath.Join(cwd, "data")
}

