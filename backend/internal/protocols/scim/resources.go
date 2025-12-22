// Package scim implements SCIM 2.0 (RFC 7642, 7643, 7644)
// System for Cross-domain Identity Management
package scim

import (
	"encoding/json"
	"fmt"
	"time"
)

// Schema URNs per RFC 7643
const (
	SchemaURNUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaURNGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaURNEnterpriseUser        = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaURNServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaURNResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaURNSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SchemaURNListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaURNPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaURNBulkRequest           = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SchemaURNBulkResponse          = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	SchemaURNError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaURNSearchRequest         = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
)

// ContentType for SCIM responses
const ContentTypeSCIM = "application/scim+json"

// Meta contains resource metadata per RFC 7643 Section 3.1
type Meta struct {
	ResourceType string     `json:"resourceType,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
	Version      string     `json:"version,omitempty"` // ETag value
}

// Resource is the base interface for all SCIM resources
type Resource interface {
	GetID() string
	GetSchemas() []string
	GetMeta() *Meta
	SetMeta(meta *Meta)
}

// BaseResource contains common fields for all SCIM resources
type BaseResource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	Meta       *Meta    `json:"meta,omitempty"`
}

func (r *BaseResource) GetID() string        { return r.ID }
func (r *BaseResource) GetSchemas() []string { return r.Schemas }
func (r *BaseResource) GetMeta() *Meta       { return r.Meta }
func (r *BaseResource) SetMeta(meta *Meta)   { r.Meta = meta }

// ================== User Resource (RFC 7643 Section 4.1) ==================

// User represents a SCIM User resource
type User struct {
	BaseResource
	UserName          string          `json:"userName"`
	Name              *Name           `json:"name,omitempty"`
	DisplayName       string          `json:"displayName,omitempty"`
	NickName          string          `json:"nickName,omitempty"`
	ProfileURL        string          `json:"profileUrl,omitempty"`
	Title             string          `json:"title,omitempty"`
	UserType          string          `json:"userType,omitempty"`
	PreferredLanguage string          `json:"preferredLanguage,omitempty"`
	Locale            string          `json:"locale,omitempty"`
	Timezone          string          `json:"timezone,omitempty"`
	Active            *bool           `json:"active,omitempty"`
	Password          string          `json:"password,omitempty"` // Write-only, never returned
	Emails            []MultiValue    `json:"emails,omitempty"`
	PhoneNumbers      []MultiValue    `json:"phoneNumbers,omitempty"`
	IMs               []MultiValue    `json:"ims,omitempty"`
	Photos            []MultiValue    `json:"photos,omitempty"`
	Addresses         []Address       `json:"addresses,omitempty"`
	Groups            []GroupRef      `json:"groups,omitempty"` // Read-only
	Entitlements      []MultiValue    `json:"entitlements,omitempty"`
	Roles             []MultiValue    `json:"roles,omitempty"`
	X509Certificates  []MultiValue    `json:"x509Certificates,omitempty"`
	EnterpriseUser    *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// NewUser creates a new User with required schemas
func NewUser() *User {
	return &User{
		BaseResource: BaseResource{
			Schemas: []string{SchemaURNUser},
		},
	}
}

// Name represents a user's name per RFC 7643 Section 4.1.1
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// MultiValue represents a multi-valued attribute per RFC 7643 Section 2.4
type MultiValue struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// Address represents a physical address per RFC 7643 Section 4.1.2
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Type          string `json:"type,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

// GroupRef represents a group membership reference
type GroupRef struct {
	Value   string `json:"value,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// EnterpriseUser represents the Enterprise User extension (RFC 7643 Section 4.3)
type EnterpriseUser struct {
	EmployeeNumber string   `json:"employeeNumber,omitempty"`
	CostCenter     string   `json:"costCenter,omitempty"`
	Organization   string   `json:"organization,omitempty"`
	Division       string   `json:"division,omitempty"`
	Department     string   `json:"department,omitempty"`
	Manager        *Manager `json:"manager,omitempty"`
}

// Manager represents a user's manager
type Manager struct {
	Value       string `json:"value,omitempty"`
	Ref         string `json:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// ================== Group Resource (RFC 7643 Section 4.2) ==================

// Group represents a SCIM Group resource
type Group struct {
	BaseResource
	DisplayName string      `json:"displayName"`
	Members     []MemberRef `json:"members,omitempty"`
}

// NewGroup creates a new Group with required schemas
func NewGroup() *Group {
	return &Group{
		BaseResource: BaseResource{
			Schemas: []string{SchemaURNGroup},
		},
	}
}

// MemberRef represents a group member reference
type MemberRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"` // "User" or "Group"
}

// ================== List Response (RFC 7644 Section 3.4.2) ==================

// ListResponse represents a SCIM list response
type ListResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex,omitempty"`
	ItemsPerPage int               `json:"itemsPerPage,omitempty"`
	Resources    []json.RawMessage `json:"Resources,omitempty"`
}

// NewListResponse creates a new list response
func NewListResponse() *ListResponse {
	return &ListResponse{
		Schemas:    []string{SchemaURNListResponse},
		StartIndex: 1,
	}
}

// ================== Service Provider Config (RFC 7643 Section 5) ==================

// ServiceProviderConfig describes SCIM service provider capabilities
type ServiceProviderConfig struct {
	Schemas               []string             `json:"schemas"`
	DocumentationURI      string               `json:"documentationUri,omitempty"`
	Patch                 SupportedConfig      `json:"patch"`
	Bulk                  BulkConfig           `json:"bulk"`
	Filter                FilterConfig         `json:"filter"`
	ChangePassword        SupportedConfig      `json:"changePassword"`
	Sort                  SupportedConfig      `json:"sort"`
	ETag                  SupportedConfig      `json:"etag"`
	AuthenticationSchemes []AuthScheme         `json:"authenticationSchemes"`
	Meta                  *Meta                `json:"meta,omitempty"`
}

// SupportedConfig indicates whether a feature is supported
type SupportedConfig struct {
	Supported bool `json:"supported"`
}

// BulkConfig describes bulk operation support
type BulkConfig struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// FilterConfig describes filter support
type FilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthScheme describes an authentication scheme
type AuthScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}

// ================== Resource Type (RFC 7643 Section 6) ==================

// ResourceType describes a SCIM resource type
type ResourceType struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	Endpoint         string            `json:"endpoint"`
	Schema           string            `json:"schema"`
	SchemaExtensions []SchemaExtension `json:"schemaExtensions,omitempty"`
	Meta             *Meta             `json:"meta,omitempty"`
}

// SchemaExtension describes a schema extension
type SchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// ================== Schema (RFC 7643 Section 7) ==================

// Schema describes a SCIM schema
type Schema struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Attributes  []Attribute `json:"attributes,omitempty"`
	Meta        *Meta       `json:"meta,omitempty"`
}

// Attribute describes a schema attribute
type Attribute struct {
	Name            string      `json:"name"`
	Type            string      `json:"type"` // string, boolean, decimal, integer, dateTime, binary, reference, complex
	MultiValued     bool        `json:"multiValued"`
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required"`
	CanonicalValues []string    `json:"canonicalValues,omitempty"`
	CaseExact       bool        `json:"caseExact"`
	Mutability      string      `json:"mutability"` // readOnly, readWrite, immutable, writeOnly
	Returned        string      `json:"returned"`   // always, never, default, request
	Uniqueness      string      `json:"uniqueness"` // none, server, global
	ReferenceTypes  []string    `json:"referenceTypes,omitempty"`
	SubAttributes   []Attribute `json:"subAttributes,omitempty"`
}

// ================== PATCH Operation (RFC 7644 Section 3.5.2) ==================

// PatchRequest represents a SCIM PATCH request
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation represents a single PATCH operation
type PatchOperation struct {
	Op    string      `json:"op"`              // add, remove, replace
	Path  string      `json:"path,omitempty"`  // Attribute path
	Value interface{} `json:"value,omitempty"` // Value for add/replace
}

// ================== Bulk Operations (RFC 7644 Section 3.7) ==================

// BulkRequest represents a SCIM bulk request
type BulkRequest struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors int             `json:"failOnErrors,omitempty"`
	Operations   []BulkOperation `json:"Operations"`
}

// BulkOperation represents a single bulk operation
type BulkOperation struct {
	Method  string          `json:"method"` // POST, PUT, PATCH, DELETE
	BulkID  string          `json:"bulkId,omitempty"`
	Version string          `json:"version,omitempty"`
	Path    string          `json:"path"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// BulkResponse represents a SCIM bulk response
type BulkResponse struct {
	Schemas    []string              `json:"schemas"`
	Operations []BulkOperationResult `json:"Operations"`
}

// BulkOperationResult represents the result of a bulk operation
type BulkOperationResult struct {
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Version  string          `json:"version,omitempty"`
	Location string          `json:"location,omitempty"`
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

// ================== Search Request (RFC 7644 Section 3.4.3) ==================

// SearchRequest represents a SCIM search request via POST
type SearchRequest struct {
	Schemas            []string `json:"schemas"`
	Attributes         []string `json:"attributes,omitempty"`
	ExcludedAttributes []string `json:"excludedAttributes,omitempty"`
	Filter             string   `json:"filter,omitempty"`
	SortBy             string   `json:"sortBy,omitempty"`
	SortOrder          string   `json:"sortOrder,omitempty"` // ascending, descending
	StartIndex         int      `json:"startIndex,omitempty"`
	Count              int      `json:"count,omitempty"`
}

// ================== Error Response (RFC 7644 Section 3.12) ==================

// ErrorResponse represents a SCIM error response
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

// SCIM error types per RFC 7644 Section 3.12
const (
	ErrorTypeInvalidFilter    = "invalidFilter"
	ErrorTypeTooMany          = "tooMany"
	ErrorTypeUniqueness       = "uniqueness"
	ErrorTypeMutability       = "mutability"
	ErrorTypeInvalidSyntax    = "invalidSyntax"
	ErrorTypeInvalidPath      = "invalidPath"
	ErrorTypeNoTarget         = "noTarget"
	ErrorTypeInvalidValue     = "invalidValue"
	ErrorTypeInvalidVers      = "invalidVers"
	ErrorTypeSensitive        = "sensitive"
)

// NewErrorResponse creates a SCIM error response
func NewErrorResponse(status int, scimType, detail string) *ErrorResponse {
	return &ErrorResponse{
		Schemas:  []string{SchemaURNError},
		ScimType: scimType,
		Detail:   detail,
		Status:   fmt.Sprintf("%d", status),
	}
}

// ================== Helper Functions ==================

// ClearPassword removes the password from a user before returning
func (u *User) ClearPassword() {
	u.Password = ""
}

// HasSchema checks if a resource includes a specific schema
func (r *BaseResource) HasSchema(schemaURN string) bool {
	for _, s := range r.Schemas {
		if s == schemaURN {
			return true
		}
	}
	return false
}

// AddSchema adds a schema URN if not already present
func (r *BaseResource) AddSchema(schemaURN string) {
	if !r.HasSchema(schemaURN) {
		r.Schemas = append(r.Schemas, schemaURN)
	}
}

// GenerateETag creates an ETag from a version number
func GenerateETag(version int) string {
	return fmt.Sprintf("W/\"%d\"", version)
}

// ParseETag extracts version from an ETag
func ParseETag(etag string) (int, error) {
	var version int
	_, err := fmt.Sscanf(etag, "W/\"%d\"", &version)
	if err != nil {
		_, err = fmt.Sscanf(etag, "\"%d\"", &version)
	}
	return version, err
}

