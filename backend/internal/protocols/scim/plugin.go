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
			Description: "Create and manage groups with member add/remove operations using SCIM PATCH (RFC 7644 §3.5.2). Groups use the urn:ietf:params:scim:schemas:core:2.0:Group schema and contain a multi-valued 'members' attribute referencing User resources by their SCIM ID.",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create Group",
					Description: "POST /Groups creates a new group resource (RFC 7644 §3.3). The request body contains the group's displayName and optionally an initial set of members. The server assigns a unique 'id' and returns the full resource.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "POST",
						"endpoint":     "/Groups",
						"Content-Type": "application/scim+json (REQUIRED)",
						"schemas":      "urn:ietf:params:scim:schemas:core:2.0:Group (REQUIRED)",
						"displayName":  "Human-readable group name (REQUIRED)",
						"members":      "Array of {value, display, $ref} objects (OPTIONAL on create)",
					},
					Security: []string{
						"Client MUST be authorized to create groups - typically requires admin scope",
						"displayName SHOULD be unique but uniqueness is server-defined (RFC 7643 §4.2)",
					},
				},
				{
					Order:       2,
					Name:        "Group Created",
					Description: "Server returns 201 Created with the full group resource including server-assigned 'id', 'meta' (created, lastModified, version), and location header (RFC 7644 §3.3).",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":   "201 Created",
						"Location": "Full URL of the new group resource (REQUIRED)",
						"ETag":     "Resource version for concurrency control (RECOMMENDED)",
						"id":       "Server-assigned unique identifier (REQUIRED)",
						"meta":     "Resource metadata: resourceType, created, lastModified, location, version",
					},
					Security: []string{
						"Store the returned 'id' for subsequent operations on this group",
						"Use ETag value for If-Match headers on future updates to prevent lost updates",
					},
				},
				{
					Order:       3,
					Name:        "Add Member to Group",
					Description: "PATCH /Groups/{id} adds a user to the group's members list (RFC 7644 §3.5.2). Uses the 'add' operation on the 'members' path. The member 'value' is the SCIM ID of the User resource to add.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "PATCH",
						"endpoint":     "/Groups/{id}",
						"Content-Type": "application/scim+json",
						"schemas":      "urn:ietf:params:scim:api:messages:2.0:PatchOp (REQUIRED)",
						"op":           "add (REQUIRED)",
						"path":         "members (targets the multi-valued members attribute)",
						"value":        "[{\"value\": \"user-scim-id\"}] - array of member references",
					},
					Security: []string{
						"Server MUST validate that referenced user IDs exist (RFC 7644 §3.5.2)",
						"If member already exists, server SHOULD NOT produce an error per spec",
						"Use If-Match header with ETag for optimistic concurrency control",
					},
				},
				{
					Order:       4,
					Name:        "Member Added",
					Description: "Server returns 200 OK with the complete updated group resource reflecting the new member (RFC 7644 §3.5.2). The members array now includes the newly added user.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":  "200 OK",
						"ETag":    "Updated resource version",
						"members": "Updated array including new member with value, display, and $ref",
					},
				},
				{
					Order:       5,
					Name:        "Remove Member from Group",
					Description: "PATCH /Groups/{id} removes a specific user from the group (RFC 7644 §3.5.2). Uses the 'remove' operation with a value selection filter on the members path to target a specific member by their SCIM ID.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "PATCH",
						"endpoint": "/Groups/{id}",
						"schemas":  "urn:ietf:params:scim:api:messages:2.0:PatchOp (REQUIRED)",
						"op":       "remove (REQUIRED)",
						"path":     "members[value eq \"{user-scim-id}\"] - value filter selects specific member",
					},
					Security: []string{
						"Path filter MUST correctly identify the member to remove",
						"Removing a non-existent member SHOULD NOT produce an error per spec",
						"Consider using replace operation on entire members list for bulk changes",
					},
				},
				{
					Order:       6,
					Name:        "Member Removed",
					Description: "Server returns 200 OK with the updated group resource. The members array no longer contains the removed user (RFC 7644 §3.5.2).",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":  "200 OK",
						"ETag":    "Updated resource version",
						"members": "Updated array with member removed",
					},
					Security: []string{
						"Verify the response confirms member removal before updating local state",
						"Group deletion (DELETE /Groups/{id}) removes the group entirely - returns 204 No Content",
					},
				},
			},
		},
		{
			ID:          "user-discovery",
			Name:        "User Discovery with Filters",
			Description: "Query and discover users using SCIM filter expressions, pagination, and attribute projection (RFC 7644 §3.4.2). SCIM filtering uses a SQL-like syntax supporting comparison operators (eq, ne, co, sw, ew, gt, lt, ge, le), presence checks (pr), and logical operators (and, or, not).",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "List All Users",
					Description: "GET /Users retrieves all user resources with server-side pagination (RFC 7644 §3.4.1). Without filters, the server returns all accessible users wrapped in a ListResponse. Large datasets SHOULD use pagination via startIndex and count parameters.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":     "GET",
						"endpoint":   "/Users",
						"startIndex": "1-based index of first result (default: 1, RFC 7644 §3.4.2.4)",
						"count":      "Maximum number of results per page (server may impose a cap)",
						"attributes": "Comma-separated list of attribute names to return (projection)",
					},
					Security: []string{
						"Server SHOULD enforce a maximum page size to prevent resource exhaustion",
						"Omitting 'attributes' returns the full resource - use projection to limit data exposure",
						"HTTPS is REQUIRED for all SCIM operations (RFC 7644 §2)",
					},
				},
				{
					Order:       2,
					Name:        "Paginated User List",
					Description: "Server returns a ListResponse containing the requested page of users (RFC 7644 §3.4.2). The response includes totalResults for the complete dataset and itemsPerPage for the current page.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":       "200 OK",
						"schemas":      "urn:ietf:params:scim:api:messages:2.0:ListResponse",
						"totalResults": "Total number of matching resources across all pages (REQUIRED)",
						"startIndex":   "1-based index of first result in this page (REQUIRED)",
						"itemsPerPage": "Number of resources in this page (REQUIRED)",
						"Resources":    "Array of User resources for this page",
					},
					Security: []string{
						"Client MUST iterate through pages using startIndex + itemsPerPage until all results are fetched",
						"totalResults may be approximate for large datasets per spec",
					},
				},
				{
					Order:       3,
					Name:        "Simple Equality Filter",
					Description: "GET /Users?filter= queries users matching a specific attribute value (RFC 7644 §3.4.2.2). The 'eq' operator performs exact case-insensitive matching for strings. This is the most common filter for user lookup by known identifiers.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "GET",
						"endpoint": "/Users?filter=userName eq \"alice@example.com\"",
						"filter":   "userName eq \"value\" - exact match (case-insensitive for strings)",
						"eq":       "Equal - exact match comparison (RFC 7644 §3.4.2.2)",
						"ne":       "Not equal",
						"co":       "Contains - substring match",
						"sw":       "Starts with - prefix match",
						"ew":       "Ends with - suffix match",
					},
					Security: []string{
						"Filter values MUST be URL-encoded in query parameters",
						"Server MUST NOT expose users the client is not authorized to see",
						"String comparisons are case-insensitive per RFC 7644 §3.4.2.2",
					},
				},
				{
					Order:       4,
					Name:        "Filtered Results",
					Description: "Server returns a ListResponse containing only users matching the filter criteria. If no users match, Resources is an empty array with totalResults of 0 (RFC 7644 §3.4.2).",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":       "200 OK",
						"totalResults": "Number of users matching the filter",
						"Resources":    "Array of matching User resources (empty if no matches)",
					},
					Security: []string{
						"A 200 response with empty Resources and totalResults=0 means no match, not an error",
						"Server MAY return 400 Bad Request for malformed filter expressions",
					},
				},
				{
					Order:       5,
					Name:        "Complex Filter with Logical Operators",
					Description: "Combine multiple filter conditions using logical operators 'and', 'or', and 'not' (RFC 7644 §3.4.2.2). Supports nested attribute paths (e.g., emails.type) and the 'pr' (present) operator to check for attribute existence.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "GET",
						"endpoint": "/Users?filter=emails.type eq \"work\" and active eq true",
						"and":      "Logical AND - both conditions must be true",
						"or":       "Logical OR - either condition must be true",
						"not":      "Logical NOT - negates the condition",
						"pr":       "Present - attribute has a non-empty value",
						"gt/lt":    "Greater than / Less than - for date and numeric comparisons",
						"ge/le":    "Greater or equal / Less or equal",
					},
					Security: []string{
						"Complex filters may be expensive - server SHOULD enforce query complexity limits",
						"Grouping with parentheses is NOT supported in SCIM filter syntax",
						"Operator precedence: NOT > AND > OR (RFC 7644 §3.4.2.2)",
					},
				},
				{
					Order:       6,
					Name:        "Complex Filter Results",
					Description: "Server evaluates the compound filter expression and returns matching users. The same ListResponse pagination applies to filtered results (RFC 7644 §3.4.2).",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":       "200 OK",
						"totalResults": "Number of users matching compound filter",
						"Resources":    "Array of matching User resources with all requested attributes",
					},
					Security: []string{
						"Server SHOULD return 400 with scimType 'invalidFilter' for unsupported filter expressions",
						"sortBy and sortOrder parameters can be combined with filters for ordered results (RFC 7644 §3.4.2.3)",
					},
				},
			},
		},
		{
			ID:          "bulk-operations",
			Name:        "Bulk Operations",
			Description: "Execute multiple SCIM operations in a single request (reference only - creates orphan data)",
			Executable:  false, // Disabled: creates multiple users without cleanup
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
			Description: "Provision users to an external SCIM server (reference only - requires external configuration)",
			Executable:  false, // Disabled: requires external SCIM server configuration
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
