package scim

import (
	"encoding/json"
	"net/http"
)

// GetServiceProviderConfig returns the SCIM service provider configuration
func GetServiceProviderConfig(baseURL string) *ServiceProviderConfig {
	return &ServiceProviderConfig{
		Schemas:          []string{SchemaURNServiceProviderConfig},
		DocumentationURI: "https://tools.ietf.org/html/rfc7644",
		Patch: SupportedConfig{
			Supported: true,
		},
		Bulk: BulkConfig{
			Supported:      true,
			MaxOperations:  1000,
			MaxPayloadSize: 1048576, // 1MB
		},
		Filter: FilterConfig{
			Supported:  true,
			MaxResults: 200,
		},
		ChangePassword: SupportedConfig{
			Supported: true,
		},
		Sort: SupportedConfig{
			Supported: true,
		},
		ETag: SupportedConfig{
			Supported: true,
		},
		AuthenticationSchemes: []AuthScheme{
			{
				Type:             "oauthbearertoken",
				Name:             "OAuth Bearer Token",
				Description:      "Authentication scheme using the OAuth 2.0 Bearer Token standard",
				SpecURI:          "https://tools.ietf.org/html/rfc6750",
				DocumentationURI: baseURL + "/docs/scim/auth",
				Primary:          true,
			},
			{
				Type:        "httpbasic",
				Name:        "HTTP Basic",
				Description: "Authentication scheme using HTTP Basic authentication (for testing)",
				SpecURI:     "https://tools.ietf.org/html/rfc7617",
			},
		},
		Meta: &Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     baseURL + "/scim/v2/ServiceProviderConfig",
		},
	}
}

// GetResourceTypes returns the supported resource types
func GetResourceTypes(baseURL string) []*ResourceType {
	return []*ResourceType{
		{
			Schemas:     []string{SchemaURNResourceType},
			ID:          "User",
			Name:        "User",
			Description: "User Account",
			Endpoint:    "/Users",
			Schema:      SchemaURNUser,
			SchemaExtensions: []SchemaExtension{
				{
					Schema:   SchemaURNEnterpriseUser,
					Required: false,
				},
			},
			Meta: &Meta{
				ResourceType: "ResourceType",
				Location:     baseURL + "/scim/v2/ResourceTypes/User",
			},
		},
		{
			Schemas:     []string{SchemaURNResourceType},
			ID:          "Group",
			Name:        "Group",
			Description: "Group",
			Endpoint:    "/Groups",
			Schema:      SchemaURNGroup,
			Meta: &Meta{
				ResourceType: "ResourceType",
				Location:     baseURL + "/scim/v2/ResourceTypes/Group",
			},
		},
	}
}

// GetSchemas returns all supported schemas
func GetSchemas(baseURL string) []*Schema {
	return []*Schema{
		getUserSchema(baseURL),
		getGroupSchema(baseURL),
		getEnterpriseUserSchema(baseURL),
	}
}

// GetSchema returns a specific schema by ID
func GetSchema(baseURL, schemaID string) *Schema {
	switch schemaID {
	case SchemaURNUser:
		return getUserSchema(baseURL)
	case SchemaURNGroup:
		return getGroupSchema(baseURL)
	case SchemaURNEnterpriseUser:
		return getEnterpriseUserSchema(baseURL)
	default:
		return nil
	}
}

func getUserSchema(baseURL string) *Schema {
	return &Schema{
		Schemas:     []string{SchemaURNSchema},
		ID:          SchemaURNUser,
		Name:        "User",
		Description: "User Account",
		Attributes: []Attribute{
			{
				Name:        "userName",
				Type:        "string",
				MultiValued: false,
				Description: "Unique identifier for the User, typically used by the user to directly authenticate.",
				Required:    true,
				CaseExact:   false,
				Mutability:  "readWrite",
				Returned:    "default",
				Uniqueness:  "server",
			},
			{
				Name:        "name",
				Type:        "complex",
				MultiValued: false,
				Description: "The components of the user's name.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "formatted", Type: "string", Description: "The full name", Mutability: "readWrite", Returned: "default"},
					{Name: "familyName", Type: "string", Description: "The family name", Mutability: "readWrite", Returned: "default"},
					{Name: "givenName", Type: "string", Description: "The given name", Mutability: "readWrite", Returned: "default"},
					{Name: "middleName", Type: "string", Description: "The middle name", Mutability: "readWrite", Returned: "default"},
					{Name: "honorificPrefix", Type: "string", Description: "Honorific prefix", Mutability: "readWrite", Returned: "default"},
					{Name: "honorificSuffix", Type: "string", Description: "Honorific suffix", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "displayName",
				Type:        "string",
				MultiValued: false,
				Description: "The name of the User, suitable for display.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "nickName",
				Type:        "string",
				MultiValued: false,
				Description: "The casual way to address the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "profileUrl",
				Type:        "reference",
				MultiValued: false,
				Description: "A fully qualified URL to a page representing the User.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				ReferenceTypes: []string{"external"},
			},
			{
				Name:        "title",
				Type:        "string",
				MultiValued: false,
				Description: "The user's title, such as 'Vice President'.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "userType",
				Type:        "string",
				MultiValued: false,
				Description: "Used to identify the relationship between the organization and the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "preferredLanguage",
				Type:        "string",
				MultiValued: false,
				Description: "Indicates the User's preferred written or spoken language.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "locale",
				Type:        "string",
				MultiValued: false,
				Description: "Used for purposes of localizing items such as currency.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "timezone",
				Type:        "string",
				MultiValued: false,
				Description: "The User's time zone in IANA format.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "active",
				Type:        "boolean",
				MultiValued: false,
				Description: "Indicates whether the user's account is active.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "password",
				Type:        "string",
				MultiValued: false,
				Description: "The User's cleartext password.",
				Required:    false,
				Mutability:  "writeOnly",
				Returned:    "never",
			},
			{
				Name:        "emails",
				Type:        "complex",
				MultiValued: true,
				Description: "Email addresses for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Email address value", Mutability: "readWrite", Returned: "default"},
					{Name: "display", Type: "string", Description: "Display name", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Type (work, home, other)", CanonicalValues: []string{"work", "home", "other"}, Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary email", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "phoneNumbers",
				Type:        "complex",
				MultiValued: true,
				Description: "Phone numbers for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Phone number value", Mutability: "readWrite", Returned: "default"},
					{Name: "display", Type: "string", Description: "Display name", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Type (work, home, mobile, fax, pager, other)", CanonicalValues: []string{"work", "home", "mobile", "fax", "pager", "other"}, Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary number", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "addresses",
				Type:        "complex",
				MultiValued: true,
				Description: "Physical mailing addresses for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "formatted", Type: "string", Description: "Full address formatted", Mutability: "readWrite", Returned: "default"},
					{Name: "streetAddress", Type: "string", Description: "Street address", Mutability: "readWrite", Returned: "default"},
					{Name: "locality", Type: "string", Description: "City or locality", Mutability: "readWrite", Returned: "default"},
					{Name: "region", Type: "string", Description: "State or region", Mutability: "readWrite", Returned: "default"},
					{Name: "postalCode", Type: "string", Description: "Postal code", Mutability: "readWrite", Returned: "default"},
					{Name: "country", Type: "string", Description: "Country", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Type (work, home, other)", CanonicalValues: []string{"work", "home", "other"}, Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary address", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "groups",
				Type:        "complex",
				MultiValued: true,
				Description: "Groups the user belongs to.",
				Required:    false,
				Mutability:  "readOnly",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Group ID", Mutability: "readOnly", Returned: "default"},
					{Name: "$ref", Type: "reference", Description: "Group URI", Mutability: "readOnly", Returned: "default", ReferenceTypes: []string{"User", "Group"}},
					{Name: "display", Type: "string", Description: "Group display name", Mutability: "readOnly", Returned: "default"},
					{Name: "type", Type: "string", Description: "Group type", CanonicalValues: []string{"direct", "indirect"}, Mutability: "readOnly", Returned: "default"},
				},
			},
			{
				Name:        "entitlements",
				Type:        "complex",
				MultiValued: true,
				Description: "Entitlements for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Entitlement value", Mutability: "readWrite", Returned: "default"},
					{Name: "display", Type: "string", Description: "Display name", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Entitlement type", Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "roles",
				Type:        "complex",
				MultiValued: true,
				Description: "Roles for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Role value", Mutability: "readWrite", Returned: "default"},
					{Name: "display", Type: "string", Description: "Display name", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Role type", Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary", Mutability: "readWrite", Returned: "default"},
				},
			},
			{
				Name:        "x509Certificates",
				Type:        "complex",
				MultiValued: true,
				Description: "X.509 certificates for the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "binary", Description: "Base64-encoded certificate", Mutability: "readWrite", Returned: "default"},
					{Name: "display", Type: "string", Description: "Display name", Mutability: "readWrite", Returned: "default"},
					{Name: "type", Type: "string", Description: "Certificate type", Mutability: "readWrite", Returned: "default"},
					{Name: "primary", Type: "boolean", Description: "Is primary", Mutability: "readWrite", Returned: "default"},
				},
			},
		},
		Meta: &Meta{
			ResourceType: "Schema",
			Location:     baseURL + "/scim/v2/Schemas/" + SchemaURNUser,
		},
	}
}

func getGroupSchema(baseURL string) *Schema {
	return &Schema{
		Schemas:     []string{SchemaURNSchema},
		ID:          SchemaURNGroup,
		Name:        "Group",
		Description: "Group",
		Attributes: []Attribute{
			{
				Name:        "displayName",
				Type:        "string",
				MultiValued: false,
				Description: "A human-readable name for the Group.",
				Required:    true,
				CaseExact:   false,
				Mutability:  "readWrite",
				Returned:    "default",
				Uniqueness:  "none",
			},
			{
				Name:        "members",
				Type:        "complex",
				MultiValued: true,
				Description: "A list of members of the Group.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Member ID", Mutability: "immutable", Returned: "default"},
					{Name: "$ref", Type: "reference", Description: "Member URI", Mutability: "immutable", Returned: "default", ReferenceTypes: []string{"User", "Group"}},
					{Name: "display", Type: "string", Description: "Member display name", Mutability: "readOnly", Returned: "default"},
					{Name: "type", Type: "string", Description: "Member type", CanonicalValues: []string{"User", "Group"}, Mutability: "immutable", Returned: "default"},
				},
			},
		},
		Meta: &Meta{
			ResourceType: "Schema",
			Location:     baseURL + "/scim/v2/Schemas/" + SchemaURNGroup,
		},
	}
}

func getEnterpriseUserSchema(baseURL string) *Schema {
	return &Schema{
		Schemas:     []string{SchemaURNSchema},
		ID:          SchemaURNEnterpriseUser,
		Name:        "EnterpriseUser",
		Description: "Enterprise User Extension",
		Attributes: []Attribute{
			{
				Name:        "employeeNumber",
				Type:        "string",
				MultiValued: false,
				Description: "Numeric or alphanumeric identifier assigned to the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "costCenter",
				Type:        "string",
				MultiValued: false,
				Description: "Cost center assigned to the user.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "organization",
				Type:        "string",
				MultiValued: false,
				Description: "Name of the organization.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "division",
				Type:        "string",
				MultiValued: false,
				Description: "Name of the division.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "department",
				Type:        "string",
				MultiValued: false,
				Description: "Name of the department.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
			},
			{
				Name:        "manager",
				Type:        "complex",
				MultiValued: false,
				Description: "The user's manager.",
				Required:    false,
				Mutability:  "readWrite",
				Returned:    "default",
				SubAttributes: []Attribute{
					{Name: "value", Type: "string", Description: "Manager's user ID", Mutability: "readWrite", Returned: "default"},
					{Name: "$ref", Type: "reference", Description: "Manager URI", Mutability: "readWrite", Returned: "default", ReferenceTypes: []string{"User"}},
					{Name: "displayName", Type: "string", Description: "Manager's display name", Mutability: "readOnly", Returned: "default"},
				},
			},
		},
		Meta: &Meta{
			ResourceType: "Schema",
			Location:     baseURL + "/scim/v2/Schemas/" + SchemaURNEnterpriseUser,
		},
	}
}

// HandleServiceProviderConfig handles GET /ServiceProviderConfig
func HandleServiceProviderConfig(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeSCIM)
		json.NewEncoder(w).Encode(GetServiceProviderConfig(baseURL))
	}
}

// HandleResourceTypes handles GET /ResourceTypes
func HandleResourceTypes(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeSCIM)
		
		resourceTypes := GetResourceTypes(baseURL)
		
		// Return as list response
		response := &ListResponse{
			Schemas:      []string{SchemaURNListResponse},
			TotalResults: len(resourceTypes),
			StartIndex:   1,
			ItemsPerPage: len(resourceTypes),
		}
		
		for _, rt := range resourceTypes {
			data, _ := json.Marshal(rt)
			response.Resources = append(response.Resources, data)
		}
		
		json.NewEncoder(w).Encode(response)
	}
}

// HandleResourceType handles GET /ResourceTypes/{id}
func HandleResourceType(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract ID from path
		// Path is /scim/v2/ResourceTypes/{id}
		parts := splitPath(r.URL.Path)
		if len(parts) < 4 {
			WriteError(w, ErrResourceNotFound("ResourceType", ""))
			return
		}
		id := parts[3]
		
		resourceTypes := GetResourceTypes(baseURL)
		for _, rt := range resourceTypes {
			if rt.ID == id {
				w.Header().Set("Content-Type", ContentTypeSCIM)
				json.NewEncoder(w).Encode(rt)
				return
			}
		}
		
		WriteError(w, ErrResourceNotFound("ResourceType", id))
	}
}

// HandleSchemas handles GET /Schemas
func HandleSchemas(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeSCIM)
		
		schemas := GetSchemas(baseURL)
		
		response := &ListResponse{
			Schemas:      []string{SchemaURNListResponse},
			TotalResults: len(schemas),
			StartIndex:   1,
			ItemsPerPage: len(schemas),
		}
		
		for _, s := range schemas {
			data, _ := json.Marshal(s)
			response.Resources = append(response.Resources, data)
		}
		
		json.NewEncoder(w).Encode(response)
	}
}

// HandleSchema handles GET /Schemas/{id}
func HandleSchema(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract ID from path (URL-encoded schema URN)
		parts := splitPath(r.URL.Path)
		if len(parts) < 4 {
			WriteError(w, ErrResourceNotFound("Schema", ""))
			return
		}
		id := parts[3]
		
		schema := GetSchema(baseURL, id)
		if schema == nil {
			WriteError(w, ErrResourceNotFound("Schema", id))
			return
		}
		
		w.Header().Set("Content-Type", ContentTypeSCIM)
		json.NewEncoder(w).Encode(schema)
	}
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range splitString(path, '/') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitString(s string, sep rune) []string {
	var parts []string
	var current string
	for _, c := range s {
		if c == sep {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

