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
			Description: "Complete user provisioning lifecycle covering the four core SCIM operations: Create (POST), Update (PATCH), Deactivate (PATCH active=false), and Delete (DELETE) as defined in RFC 7644 §3. This flow represents the standard identity lifecycle pattern used by IdPs like Okta, Azure AD, and OneLogin to synchronize user accounts to downstream applications.",
			Executable:  true,
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create User",
					Description: "POST /Users creates a new user resource (RFC 7644 §3.3). The request body MUST include the urn:ietf:params:scim:schemas:core:2.0:User schema and the userName attribute. The server assigns a unique 'id' and returns the complete resource with server-generated metadata.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "POST",
						"endpoint":     "/Users",
						"Content-Type": "application/scim+json (REQUIRED)",
						"schemas":      "urn:ietf:params:scim:schemas:core:2.0:User (REQUIRED)",
						"userName":     "Unique identifier for the user (REQUIRED, RFC 7643 §4.1.1)",
						"name":         "{givenName, familyName} - user's name components (RECOMMENDED)",
						"emails":       "Array of {value, type, primary} objects (RECOMMENDED)",
						"active":       "true (default) - account status flag",
					},
					Security: []string{
						"Client MUST be authorized with a valid Bearer token (RFC 7644 §2)",
						"userName uniqueness MUST be enforced by the server (RFC 7643 §4.1.1)",
						"HTTPS is REQUIRED for all SCIM operations to protect PII in transit",
					},
				},
				{
					Order:       2,
					Name:        "User Created",
					Description: "Server returns 201 Created with the full user resource including server-assigned 'id', 'meta' block (resourceType, created, lastModified, location, version), and a Location header pointing to the new resource (RFC 7644 §3.3).",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":   "201 Created",
						"Location": "Full URL of the new user resource (REQUIRED)",
						"ETag":     "Resource version for concurrency control (RECOMMENDED)",
						"id":       "Server-assigned unique identifier (REQUIRED, immutable)",
						"meta":     "resourceType, created, lastModified, location, version",
					},
					Security: []string{
						"Store the returned 'id' - it is the permanent reference for this user",
						"Use ETag for If-Match headers on subsequent updates to prevent lost updates",
					},
				},
				{
					Order:       3,
					Name:        "Update User",
					Description: "PATCH /Users/{id} modifies specific attributes without replacing the entire resource (RFC 7644 §3.5.2). Uses the PatchOp schema with 'replace' operations to update individual fields. This is preferred over PUT for partial updates as it reduces payload size and avoids accidentally clearing unspecified attributes.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "PATCH",
						"endpoint":     "/Users/{id}",
						"Content-Type": "application/scim+json",
						"schemas":      "urn:ietf:params:scim:api:messages:2.0:PatchOp (REQUIRED)",
						"op":           "replace (for updating existing attribute values)",
						"path":         "Attribute path to modify (e.g., 'name.familyName', 'emails[type eq \"work\"].value')",
						"value":        "New attribute value",
					},
					Security: []string{
						"Use If-Match with ETag to prevent concurrent modification conflicts (RFC 7644 §3.5.2)",
						"PATCH is atomic - all operations in a request succeed or fail together",
						"Validate that the user {id} exists before sending PATCH to avoid 404 errors",
					},
				},
				{
					Order:       4,
					Name:        "User Updated",
					Description: "Server returns 200 OK with the complete updated user resource reflecting all applied changes (RFC 7644 §3.5.2). The meta.lastModified timestamp and ETag version are updated to reflect the modification.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status": "200 OK",
						"ETag":   "Updated resource version",
						"meta":   "lastModified updated to current timestamp",
					},
					Security: []string{
						"Verify the response body reflects expected changes before updating local state",
						"If server returns 412 Precondition Failed, re-fetch and retry the update",
					},
				},
				{
					Order:       5,
					Name:        "Deactivate User",
					Description: "PATCH /Users/{id} with 'active' set to false disables the user account without deleting it (RFC 7643 §4.1.1). This is the standard SCIM pattern for suspension - the user record is preserved but the account is marked inactive. IdPs use this for offboarding users who may be re-enabled later.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "PATCH",
						"endpoint": "/Users/{id}",
						"schemas":  "urn:ietf:params:scim:api:messages:2.0:PatchOp",
						"op":       "replace",
						"path":     "active",
						"value":    "false",
					},
					Security: []string{
						"Deactivation SHOULD immediately revoke access to downstream applications",
						"Prefer deactivation over deletion for audit trail preservation",
						"The user's group memberships are typically preserved during deactivation",
					},
				},
				{
					Order:       6,
					Name:        "User Deactivated",
					Description: "Server returns 200 OK with the user resource showing active=false. The server SHOULD enforce that deactivated users cannot authenticate or access resources. Applications receiving this update should terminate active sessions for this user.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status": "200 OK",
						"active": "false - user account is now disabled",
						"ETag":   "Updated resource version",
					},
					Security: []string{
						"Downstream applications SHOULD terminate active sessions for deactivated users",
						"Re-activation requires another PATCH with active=true",
					},
				},
				{
					Order:       7,
					Name:        "Delete User",
					Description: "DELETE /Users/{id} permanently removes the user resource (RFC 7644 §3.6). This is irreversible - the user's data, group memberships, and all associated resources are destroyed. Most IdPs only issue DELETE after a grace period following deactivation.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "DELETE",
						"endpoint": "/Users/{id}",
						"If-Match": "ETag value for concurrency safety (RECOMMENDED)",
					},
					Security: []string{
						"DELETE is permanent and irreversible - implement a grace period before hard deletion",
						"Server SHOULD remove the user from all groups (RFC 7644 §3.6)",
						"Consider data retention policies before implementing hard delete",
					},
				},
				{
					Order:       8,
					Name:        "User Deleted",
					Description: "Server returns 204 No Content with an empty body confirming permanent deletion (RFC 7644 §3.6). Subsequent GET requests for this user MUST return 404 Not Found. The user's 'id' SHOULD NOT be reused.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status": "204 No Content",
						"body":   "Empty (no response body)",
					},
					Security: []string{
						"Any subsequent requests for this user ID MUST return 404",
						"The user's SCIM ID SHOULD NOT be reassigned to prevent identity confusion",
						"Audit log should record the deletion event with timestamp and actor",
					},
				},
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
			Description: "Execute multiple SCIM create, update, patch, and delete operations in a single HTTP request (RFC 7644 §3.7). Bulk operations reduce round trips and enable atomic provisioning of related resources. The server advertises its bulk capabilities (maxOperations, maxPayloadSize) via the ServiceProviderConfig endpoint.",
			Executable:  false, // Disabled: creates multiple users without cleanup
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Bulk Request",
					Description: "POST /Bulk submits an array of SCIM operations in a single HTTP request (RFC 7644 §3.7). Each operation specifies a method (POST, PUT, PATCH, DELETE), a path (e.g., /Users), and optionally a bulkId for cross-referencing newly created resources within the same batch.",
					From:        "IdP",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "POST",
						"endpoint":     "/Bulk",
						"Content-Type": "application/scim+json (REQUIRED)",
						"schemas":      "urn:ietf:params:scim:api:messages:2.0:BulkRequest (REQUIRED)",
						"Operations":   "Array of {method, path, bulkId, data} objects (REQUIRED)",
						"failOnErrors": "Number of errors before aborting remaining operations (OPTIONAL)",
					},
					Security: []string{
						"Server MUST enforce maxOperations limit from ServiceProviderConfig (RFC 7644 §3.7)",
						"Server MUST enforce maxPayloadSize to prevent resource exhaustion",
						"Each operation within the bulk is authorized independently",
						"bulkId values enable cross-referencing (e.g., create user then add to group in same batch)",
					},
				},
				{
					Order:       2,
					Name:        "Process Operations",
					Description: "Server processes each operation sequentially in array order (RFC 7644 §3.7). Operations referencing a bulkId from a prior operation in the same request have the bulkId replaced with the server-assigned resource ID. If failOnErrors is set and that many errors occur, remaining operations are skipped.",
					From:        "SCIM Server",
					To:          "SCIM Server",
					Type:        "internal",
					Parameters: map[string]string{
						"processing_order": "Sequential - array index order (RFC 7644 §3.7)",
						"bulkId_resolution": "bulkId:value references replaced with actual resource IDs",
						"error_handling":   "Continue or abort based on failOnErrors threshold",
					},
					Security: []string{
						"Failed operations MUST NOT affect already-completed operations (no rollback per spec)",
						"Server SHOULD validate all operations before processing when possible",
						"Circular bulkId references are invalid and MUST be rejected",
					},
				},
				{
					Order:       3,
					Name:        "Bulk Response",
					Description: "Server returns 200 OK with a BulkResponse containing the result of each operation (RFC 7644 §3.7). Each operation result includes the HTTP status code, location of created resources, and any error details. The response preserves the same ordering as the request.",
					From:        "SCIM Server",
					To:          "IdP",
					Type:        "response",
					Parameters: map[string]string{
						"status":     "200 OK (overall request succeeded)",
						"schemas":    "urn:ietf:params:scim:api:messages:2.0:BulkResponse",
						"Operations": "Array of {method, location, bulkId, status, response} per operation",
						"status_per_op": "Individual HTTP status codes (201, 200, 204, 4xx, etc.)",
					},
					Security: []string{
						"Client MUST check individual operation status codes - overall 200 does not mean all succeeded",
						"Failed operations include scimType error detail for diagnosis",
						"Location headers in responses provide permanent URLs for created resources",
					},
				},
			},
		},
		{
			ID:          "schema-discovery",
			Name:        "Schema Discovery",
			Description: "Discover SCIM server capabilities, supported resource types, and full schema definitions using the three discovery endpoints defined in RFC 7644 §4. These endpoints allow clients to dynamically adapt to server capabilities without hardcoding assumptions about supported features, attributes, or extensions.",
			Executable:  true,
			Category:    "discovery",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Get ServiceProviderConfig",
					Description: "GET /ServiceProviderConfig retrieves the server's capability declaration (RFC 7644 §4). This is typically the first call a SCIM client makes to understand what operations and features the server supports. The response is a singleton resource - it does not use ListResponse wrapping.",
					From:        "Client",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "GET",
						"endpoint": "/ServiceProviderConfig",
					},
					Security: []string{
						"This endpoint SHOULD be publicly accessible without authentication (RFC 7644 §4)",
						"Response is read-only - clients cannot modify server configuration via SCIM",
					},
				},
				{
					Order:       2,
					Name:        "ServiceProviderConfig Response",
					Description: "Server returns its feature support matrix (RFC 7643 §5). Each feature has a 'supported' boolean and feature-specific configuration. Clients MUST check these capabilities before using optional features like PATCH, bulk, or filter operations.",
					From:        "SCIM Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"patch.supported":          "Boolean - whether PATCH operations are supported (RFC 7644 §3.5.2)",
						"bulk.supported":           "Boolean - whether bulk operations are supported",
						"bulk.maxOperations":       "Maximum number of operations per bulk request",
						"bulk.maxPayloadSize":      "Maximum payload size in bytes for bulk requests",
						"filter.supported":         "Boolean - whether filter expressions are supported",
						"filter.maxResults":        "Maximum number of resources returned per query",
						"changePassword.supported": "Boolean - whether password changes via SCIM are supported",
						"sort.supported":           "Boolean - whether sortBy/sortOrder parameters are supported",
						"etag.supported":           "Boolean - whether ETags for concurrency control are supported",
						"authenticationSchemes":    "Array of supported auth methods (e.g., Bearer token, Basic)",
					},
					Security: []string{
						"Client MUST respect server-declared limits (maxOperations, maxResults, maxPayloadSize)",
						"authenticationSchemes describes supported methods - OAuth 2.0 Bearer (RFC 6750) is RECOMMENDED",
					},
				},
				{
					Order:       3,
					Name:        "Get ResourceTypes",
					Description: "GET /ResourceTypes retrieves the list of resource types supported by the server (RFC 7644 §4). Each ResourceType defines the endpoint, core schema, and any schema extensions for a particular resource kind (e.g., User, Group, Enterprise User).",
					From:        "Client",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "GET",
						"endpoint": "/ResourceTypes",
					},
					Security: []string{
						"This endpoint SHOULD be publicly accessible without authentication",
						"Individual resource types can be fetched via GET /ResourceTypes/{name}",
					},
				},
				{
					Order:       4,
					Name:        "ResourceTypes Response",
					Description: "Server returns an array of ResourceType definitions (RFC 7643 §6). Each entry maps a resource name to its endpoint path, required core schema, and optional schema extensions. This tells the client which endpoints exist and what schemas they use.",
					From:        "SCIM Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"User.endpoint":           "/Users",
						"User.schema":             "urn:ietf:params:scim:schemas:core:2.0:User (REQUIRED)",
						"User.schemaExtensions":   "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User (OPTIONAL)",
						"Group.endpoint":          "/Groups",
						"Group.schema":            "urn:ietf:params:scim:schemas:core:2.0:Group (REQUIRED)",
					},
					Security: []string{
						"schemaExtensions[].required indicates whether an extension MUST be present in resources",
						"Custom resource types may expose additional endpoints beyond the standard User/Group",
					},
				},
				{
					Order:       5,
					Name:        "Get Schemas",
					Description: "GET /Schemas retrieves the complete attribute definitions for all supported schemas (RFC 7644 §4). Each schema defines every attribute's name, type, mutability, returned behavior, uniqueness constraint, and sub-attributes. This is essential for building dynamic SCIM clients.",
					From:        "Client",
					To:          "SCIM Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "GET",
						"endpoint": "/Schemas",
					},
					Security: []string{
						"This endpoint SHOULD be publicly accessible without authentication",
						"Individual schemas can be fetched via GET /Schemas/{schemaUri}",
					},
				},
				{
					Order:       6,
					Name:        "Schemas Response",
					Description: "Server returns full attribute definitions for each schema (RFC 7643 §7). Each attribute includes metadata: type (String, Boolean, Complex, etc.), mutability (readOnly, readWrite, immutable, writeOnly), returned (always, never, default, request), uniqueness (none, server, global), and whether it is required or multi-valued.",
					From:        "SCIM Server",
					To:          "Client",
					Type:        "response",
					Parameters: map[string]string{
						"attribute.name":        "Attribute identifier (e.g., 'userName', 'emails')",
						"attribute.type":        "String, Boolean, Decimal, Integer, DateTime, Binary, Reference, Complex",
						"attribute.mutability":  "readOnly | readWrite | immutable | writeOnly (RFC 7643 §7)",
						"attribute.returned":    "always | never | default | request (controls inclusion in responses)",
						"attribute.uniqueness":  "none | server | global (uniqueness constraint scope)",
						"attribute.multiValued": "Boolean - whether attribute holds an array of values",
						"attribute.required":    "Boolean - whether attribute MUST be present",
					},
					Security: []string{
						"writeOnly attributes (like passwords) are never returned in responses",
						"Clients SHOULD cache schema definitions to avoid repeated discovery calls",
						"Custom schemas can extend the standard User/Group schemas with additional attributes",
					},
				},
			},
		},
		{
			ID:          "outbound-provisioning",
			Name:        "Outbound Provisioning",
			Description: "Provision users from an Identity Provider to an external SCIM-compliant application (RFC 7644 §3). This is the standard pattern used by IdPs like Okta, Azure AD, and Google Workspace to push user identity data to SaaS applications. The IdP acts as a SCIM client, and the target application exposes a SCIM server endpoint.",
			Executable:  false, // Disabled: requires external SCIM server configuration
			Category:    "provisioning",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Configure Target",
					Description: "Administrator configures the SCIM client with the target application's SCIM endpoint URL and authentication credentials. This typically involves generating a long-lived Bearer token or configuring OAuth 2.0 client credentials for the SCIM client to authenticate with the target server.",
					From:        "Admin",
					To:          "SCIM Client",
					Type:        "internal",
					Parameters: map[string]string{
						"base_url":      "Target SCIM server URL (e.g., https://app.example.com/scim/v2)",
						"auth_type":     "Bearer token or OAuth 2.0 client credentials",
						"bearer_token":  "Long-lived API token for SCIM authentication",
						"mapping_rules": "Attribute mappings from source to target schema",
					},
					Security: []string{
						"Bearer tokens for SCIM provisioning should be long-lived but rotatable",
						"Store credentials securely using a secrets vault, not in configuration files",
						"HTTPS is REQUIRED for the target endpoint (RFC 7644 §2)",
					},
				},
				{
					Order:       2,
					Name:        "Discover Target Capabilities",
					Description: "SCIM client queries the target server's /ServiceProviderConfig endpoint to discover supported features (RFC 7644 §4). This determines whether the target supports PATCH, bulk operations, filtering, and what authentication schemes are accepted.",
					From:        "SCIM Client",
					To:          "External Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "GET",
						"endpoint":     "/ServiceProviderConfig",
						"check_patch":  "Verify PATCH support before using partial updates",
						"check_bulk":   "Verify bulk support before sending batch operations",
						"check_filter": "Verify filter support for incremental sync queries",
					},
					Security: []string{
						"Client MUST adapt behavior based on server capabilities",
						"If PATCH is unsupported, fall back to PUT for updates (full resource replacement)",
					},
				},
				{
					Order:       3,
					Name:        "Create User at Target",
					Description: "SCIM client sends POST /Users to create the user at the target application (RFC 7644 §3.3). The client maps source user attributes to the target schema based on configured mapping rules. The request body follows the target's declared User schema.",
					From:        "SCIM Client",
					To:          "External Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":       "POST",
						"endpoint":     "/Users",
						"Content-Type": "application/scim+json",
						"body":         "User resource mapped to target schema",
						"Authorization": "Bearer {token}",
					},
					Security: []string{
						"Map only necessary attributes - follow least-privilege for data sharing",
						"Validate that sensitive attributes (e.g., passwords) are only sent when required",
						"Handle 409 Conflict if user already exists at target (idempotency)",
					},
				},
				{
					Order:       4,
					Name:        "User Created at Target",
					Description: "External server returns 201 Created with the user resource including the server-assigned 'id' at the target (RFC 7644 §3.3). This target ID is different from the source system's ID and must be stored for subsequent operations.",
					From:        "External Server",
					To:          "SCIM Client",
					Type:        "response",
					Parameters: map[string]string{
						"status":   "201 Created",
						"id":       "Target server's unique identifier for this user",
						"Location": "Full URL of the user resource at the target",
						"ETag":     "Resource version at the target",
					},
					Security: []string{
						"Store both the target 'id' and 'Location' for future operations",
						"Handle non-201 responses: 400 (schema error), 409 (conflict), 401 (auth failure)",
					},
				},
				{
					Order:       5,
					Name:        "Record ID Mapping",
					Description: "SCIM client stores the mapping between the source system's user ID and the target system's user ID. This mapping is essential for subsequent update, deactivate, and delete operations to target the correct resource at the external server.",
					From:        "SCIM Client",
					To:          "Database",
					Type:        "internal",
					Parameters: map[string]string{
						"source_id": "User ID in the IdP / source system",
						"target_id": "User ID assigned by the external SCIM server",
						"target_location": "Full URL for the user at the target",
						"last_synced": "Timestamp of last successful provisioning",
					},
					Security: []string{
						"ID mappings enable incremental sync - only changed users are updated",
						"Orphaned mappings (deleted at source but not target) should be periodically reconciled",
						"Store mapping data securely - it links identities across systems",
					},
				},
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
