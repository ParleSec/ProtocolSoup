package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/go-chi/chi/v5"
)

// timeNow returns the current time (can be mocked for testing)
var timeNow = time.Now

// ================== Discovery Handlers ==================

func (p *Plugin) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "ServiceProviderConfig", map[string]interface{}{
		"method": "GET",
		"path":   "/ServiceProviderConfig",
	}, "RFC 7644 Section 4")

	config := GetServiceProviderConfig(p.baseURL)

	p.emitEvent(r, lookingglass.EventTypeFlowStep, "ServiceProviderConfig", map[string]interface{}{
		"status": 200,
	}, "RFC 7644 Section 4")

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(config)
}

// refuseDiscoveryFilter answers a filtered query of ResourceTypes or Schemas.
// RFC 7644 Section 4: "If a "filter" is provided, the service provider SHOULD
// respond with HTTP status code 403 (Forbidden) to ensure that clients cannot
// incorrectly assume that any matching conditions specified in a filter are
// true."
func refuseDiscoveryFilter(w http.ResponseWriter, r *http.Request) bool {
	if !r.URL.Query().Has("filter") {
		return false
	}
	WriteError(w, ErrForbidden("a filter is not applied to this endpoint (RFC 7644 Section 4)"))
	return true
}

func (p *Plugin) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if refuseDiscoveryFilter(w, r) {
		return
	}
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "ResourceTypes", map[string]interface{}{
		"method": "GET",
		"path":   "/ResourceTypes",
	}, "RFC 7644 Section 4")

	resourceTypes := GetResourceTypes(p.baseURL)

	response := NewListResponse()
	response.TotalResults = len(resourceTypes)
	response.ItemsPerPage = len(resourceTypes)

	for _, rt := range resourceTypes {
		data, _ := json.Marshal(rt)
		response.Resources = append(response.Resources, data)
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
}

func (p *Plugin) handleResourceType(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	resourceTypes := GetResourceTypes(p.baseURL)
	for _, rt := range resourceTypes {
		if rt.ID == id {
			w.Header().Set("Content-Type", ContentTypeSCIM)
			json.NewEncoder(w).Encode(rt)
			return
		}
	}

	WriteError(w, ErrResourceNotFound("ResourceType", id))
}

func (p *Plugin) handleSchemas(w http.ResponseWriter, r *http.Request) {
	if refuseDiscoveryFilter(w, r) {
		return
	}
	schemas := GetSchemas(p.baseURL)

	response := NewListResponse()
	response.TotalResults = len(schemas)
	response.ItemsPerPage = len(schemas)

	for _, s := range schemas {
		data, _ := json.Marshal(s)
		response.Resources = append(response.Resources, data)
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
}

func (p *Plugin) handleSchema(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// URL-decode the schema ID (URNs contain colons which are URL-encoded)
	decodedID, err := url.PathUnescape(id)
	if err != nil {
		WriteError(w, ErrInvalidValue("Invalid schema ID URL encoding"))
		return
	}

	schema := GetSchema(p.baseURL, decodedID)
	if schema == nil {
		WriteError(w, ErrResourceNotFound("Schema", decodedID))
		return
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(schema)
}

// ================== Resource Requests And Responses ==================

// checkSchemas validates the "schemas" attribute of a resource or message a
// client sent. RFC 7643 Section 3: "The "schemas" attribute is a REQUIRED
// attribute", it "MUST only contain values defined as "schema" and
// "schemaExtensions" for the resource's defined "resourceType"", and
// "Duplicate values MUST NOT be included." The core schema URI is one of
// them: "This same value is also present in the resource's "schemas"
// attribute."
func checkSchemas(schemas []string, core string, extensions ...string) *SCIMError {
	if len(schemas) == 0 {
		return ErrInvalidValue("schemas is required")
	}
	seen := map[string]bool{}
	for _, uri := range schemas {
		defined := uri == core
		for _, extension := range extensions {
			defined = defined || uri == extension
		}
		if !defined {
			return ErrInvalidSyntax(fmt.Sprintf("schemas value %q is not a schema of this resource type", uri))
		}
		if seen[uri] {
			return ErrInvalidSyntax(fmt.Sprintf("schemas repeats %q", uri))
		}
		seen[uri] = true
	}
	if !seen[core] {
		return ErrInvalidSyntax(fmt.Sprintf("schemas does not include %q", core))
	}
	return nil
}

// checkUser validates a User a client sent with POST or PUT, or that a PATCH
// produced. RFC 7643 Section 4.1.1: "Each User MUST include a non-empty
// userName value." Extended attributes sit under the schema extension URI
// (Section 3), which "schemas" must then name.
func checkUser(user *User) *SCIMError {
	if scimErr := checkSchemas(user.Schemas, SchemaURNUser, SchemaURNEnterpriseUser); scimErr != nil {
		return scimErr
	}
	if user.UserName == "" {
		return ErrInvalidValue("userName is required")
	}
	if user.EnterpriseUser != nil {
		for _, uri := range user.Schemas {
			if uri == SchemaURNEnterpriseUser {
				return nil
			}
		}
		return ErrInvalidSyntax(fmt.Sprintf("the resource carries %q attributes and schemas does not name that schema", SchemaURNEnterpriseUser))
	}
	return nil
}

// checkGroup validates a Group a client sent, or that a PATCH produced. RFC
// 7643 Section 4.2 on displayName: "A human-readable name for the Group.
// REQUIRED." A member is a resource of this service provider, and its type is
// one this service provider keeps as a member: a User.
func (p *Plugin) checkGroup(ctx context.Context, group *Group) *SCIMError {
	if scimErr := checkSchemas(group.Schemas, SchemaURNGroup); scimErr != nil {
		return scimErr
	}
	if group.DisplayName == "" {
		return ErrInvalidValue("displayName is required")
	}
	seen := map[string]bool{}
	members := group.Members[:0]
	for _, member := range group.Members {
		if member.Type != "" && member.Type != "User" {
			return ErrInvalidValue(fmt.Sprintf("member type %q is not supported: members of a Group here are Users", member.Type))
		}
		if _, err := p.storage.GetUser(ctx, member.Value); err != nil {
			return ErrInvalidValue(fmt.Sprintf("member %q is not a User of this service provider", member.Value))
		}
		if !seen[member.Value] {
			seen[member.Value] = true
			members = append(members, member)
		}
	}
	group.Members = members
	return nil
}

// storeError maps a storage failure to its SCIM error. unique names the
// attribute a conflict is about.
func storeError(resourceType, id, unique string, err error) *SCIMError {
	switch {
	case errors.Is(err, ErrNotFound):
		return ErrResourceNotFound(resourceType, id)
	case errors.Is(err, ErrVersionConflict):
		return ErrPreconditionFailed("the resource has changed on the server")
	case errors.Is(err, ErrConflict):
		// RFC 7644 Section 3.3: "the service provider MUST return HTTP status
		// code 409 (Conflict) with a "scimType" error code of "uniqueness"".
		return ErrConflictUniqueness(unique)
	case errors.Is(err, ErrUserNameNotAllowed):
		return ErrInvalidValue(err.Error())
	default:
		return ErrInternalServer(err.Error())
	}
}

// describeUser completes a stored User for a response: its location, and the
// groups it belongs to, which are derived from group membership. RFC 7643
// Section 4.1.2 defines the type "direct" for membership through the Group
// itself.
func (p *Plugin) describeUser(ctx context.Context, user *User) {
	user.Meta.Location = p.baseURL + "/scim/v2/Users/" + user.ID
	groups, _ := p.storage.GetUserGroups(ctx, user.ID)
	for i := range groups {
		groups[i].Ref = p.baseURL + "/scim/v2/Groups/" + groups[i].Value
		groups[i].Type = "direct"
	}
	user.Groups = groups
}

// describeGroup completes a stored Group for a response: its location and the
// URI of each member.
func (p *Plugin) describeGroup(group *Group) {
	group.Meta.Location = p.baseURL + "/scim/v2/Groups/" + group.ID
	for i := range group.Members {
		group.Members[i].Type = "User"
		group.Members[i].Ref = p.baseURL + "/scim/v2/Users/" + group.Members[i].Value
	}
}

// requestProjection reads the attributes a client asked to have returned
// (RFC 7644 Section 3.9), before the operation runs. It answers the request
// itself when they are not valid.
func requestProjection(w http.ResponseWriter, r *http.Request) (projection, bool) {
	p, scimErr := projectionOf(r.URL.Query())
	if scimErr != nil {
		WriteError(w, scimErr)
		return p, false
	}
	return p, true
}

// writeResource writes one resource representation.
//
// RFC 7643 Section 3.1 on meta.location: "This value MUST be the same as the
// "Content-Location" HTTP response header". On meta.version: "This value must
// be the same as the entity-tag (ETag) HTTP response header". RFC 7644 Section
// 3.3 on a created resource: "The URI of the created resource SHALL include,
// in the HTTP "Location" header and the HTTP body, a JSON representation
// [RFC7159] with the attribute "meta.location"."
func writeResource(w http.ResponseWriter, status int, meta *Meta, resource interface{}, selected projection) {
	body := resource
	if !selected.empty() {
		item, err := newQueryItem(resource)
		if err != nil {
			WriteError(w, ErrInternalServer(err.Error()))
			return
		}
		body = selected.apply(item.object)
	}
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("Content-Location", meta.Location)
	w.Header().Set("ETag", meta.Version)
	if status == http.StatusCreated {
		w.Header().Set("Location", meta.Location)
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// notModified answers a conditional retrieval of a resource that has not
// changed. RFC 7644 Section 3.14: "If the resource has not changed, the
// service provider simply returns an empty body with a 304 (Not Modified)
// response code." RFC 7232 Section 3.2 has If-None-Match compared with the
// weak comparison function, which ignores the "W/" prefix.
func notModified(w http.ResponseWriter, r *http.Request, meta *Meta) bool {
	header := r.Header.Get("If-None-Match")
	if header == "" {
		return false
	}
	current := strings.TrimPrefix(meta.Version, "W/")
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == current {
			w.Header().Set("Content-Location", meta.Location)
			w.Header().Set("ETag", meta.Version)
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	return false
}

// preconditionFailed refuses a change the client made conditional on a
// version the resource no longer has. RFC 7644 Section 3.14: "the client MAY
// supply an If-Match header (Section 3.1 of [RFC7232]) for PUT and PATCH
// operations to ensure that the requested operation succeeds only if the
// supplied ETag matches the latest service provider resource". Table 8 gives
// 412 (Precondition Failed) for PUT, PATCH and DELETE: "Failed to update.
// Resource has changed on the server."
func preconditionFailed(w http.ResponseWriter, r *http.Request, meta *Meta) bool {
	header := r.Header.Get("If-Match")
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		if candidate = strings.TrimSpace(candidate); candidate == "*" || candidate == meta.Version {
			return false
		}
	}
	WriteError(w, ErrPreconditionFailed(fmt.Sprintf("the If-Match entity-tag is not the resource's current version %s", meta.Version)))
	return true
}

// acceptJSON labels responses application/json for a client that asks for
// that media type and not for application/scim+json. RFC 7644 Section 3.8:
// "Service providers MUST support the "Accept" header "Accept:
// application/scim+json" and SHOULD support the header "Accept:
// application/json", both of which specify JSON documents conforming to
// [RFC7159]. The format defaults to "application/scim+json" if no format is
// specified."
func acceptJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain, scim := false, false
		for _, value := range r.Header.Values("Accept") {
			for _, item := range strings.Split(value, ",") {
				mediaType, _, _ := strings.Cut(item, ";")
				switch strings.ToLower(strings.TrimSpace(mediaType)) {
				case "application/json":
					plain = true
				case ContentTypeSCIM, "*/*", "application/*":
					scim = true
				}
			}
		}
		if plain && !scim {
			w = &jsonLabel{ResponseWriter: w}
		}
		next.ServeHTTP(w, r)
	})
}

// jsonLabel replaces the application/scim+json Content-Type of a response
// with application/json as the header is written.
type jsonLabel struct {
	http.ResponseWriter
	labelled bool
}

func (w *jsonLabel) label() {
	if !w.labelled {
		w.labelled = true
		if w.Header().Get("Content-Type") == ContentTypeSCIM {
			w.Header().Set("Content-Type", "application/json")
		}
	}
}

func (w *jsonLabel) WriteHeader(status int) {
	w.label()
	w.ResponseWriter.WriteHeader(status)
}

func (w *jsonLabel) Write(body []byte) (int, error) {
	w.label()
	return w.ResponseWriter.Write(body)
}

// handleNotFound answers a request for an endpoint that does not exist. RFC
// 7644 Section 3.12: "implementers MUST return the errors in the body of the
// response in a JSON format", and Table 8 gives 404 when the "Specified
// resource (e.g., User) or endpoint does not exist."
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, &SCIMError{Status: http.StatusNotFound, Detail: fmt.Sprintf("%s is not an endpoint of this service provider", r.URL.Path)})
}

// handleMethodNotAllowed answers a method an endpoint does not take.
func handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	WriteError(w, &SCIMError{Status: http.StatusMethodNotAllowed, Detail: fmt.Sprintf("%s is not a method of %s", r.Method, r.URL.Path)})
}

// handleMe answers the "/Me" alias, which this service provider does not
// offer. RFC 7644 Section 3.11: "A service provider that does NOT support
// this feature SHOULD respond with HTTP status code 501 (Not Implemented)."
func handleMe(w http.ResponseWriter, r *http.Request) {
	WriteError(w, ErrNotImplemented("The /Me authenticated subject alias"))
}

// ================== Query Handlers ==================

// queryItems loads every resource of the types a query covers, as returned
// to a client.
func (p *Plugin) queryItems(ctx context.Context, users, groups bool) ([]queryItem, error) {
	var items []queryItem
	add := func(resource interface{}) error {
		item, err := newQueryItem(resource)
		items = append(items, item)
		return err
	}
	if users {
		all, err := p.storage.ListAllUsers(ctx)
		if err != nil {
			return nil, err
		}
		for _, user := range all {
			p.describeUser(ctx, user)
			if err := add(user); err != nil {
				return nil, err
			}
		}
	}
	if groups {
		all, err := p.storage.ListAllGroups(ctx)
		if err != nil {
			return nil, err
		}
		for _, group := range all {
			p.describeGroup(group)
			if err := add(group); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}

// answerQuery runs a query and writes the list response (RFC 7644 Section
// 3.4.2).
func (p *Plugin) answerQuery(w http.ResponseWriter, r *http.Request, q query, scimErr *SCIMError, users, groups bool) {
	data := map[string]interface{}{"endpoint": r.Method + " " + r.URL.Path}
	if scimErr == nil {
		var items []queryItem
		items, err := p.queryItems(r.Context(), users, groups)
		if err != nil {
			WriteError(w, ErrInternalServer(err.Error()))
			return
		}
		var response *ListResponse
		if response, scimErr = q.run(items); scimErr == nil {
			if q.filter != nil {
				data["filter"] = q.filter.String()
			}
			data["totalResults"] = response.TotalResults
			data["startIndex"] = response.StartIndex
			data["itemsPerPage"] = response.ItemsPerPage
			p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM Query Evaluated", data, "RFC 7644 Section 3.4.2")
			w.Header().Set("Content-Type", ContentTypeSCIM)
			json.NewEncoder(w).Encode(response)
			return
		}
	}
	data["scimType"] = scimErr.ScimType
	data["detail"] = scimErr.Detail
	p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "SCIM Query Refused", data, "RFC 7644 Section 3.4.2.2")
	WriteError(w, scimErr)
}

// handleQuery answers a GET query of one resource type, or of the Base URI
// when both types are covered: "A query against a server root indicates that
// all resources within the server SHALL be included, subject to filtering."
func (p *Plugin) handleQuery(users, groups bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q, scimErr := queryFromURL(r.URL.Query())
		p.answerQuery(w, r, q, scimErr, users, groups)
	}
}

// handleSearch answers a POST query (RFC 7644 Section 3.4.3): 'The inclusion
// of "/.search" on the end of a valid SCIM endpoint SHALL be used to indicate
// that the HTTP POST verb is intended to be a query operation.'
func (p *Plugin) handleSearch(users, groups bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteError(w, ErrBadRequest("Failed to read request body"))
			return
		}
		q, scimErr := queryFromSearchRequest(body)
		p.answerQuery(w, r, q, scimErr, users, groups)
	}
}

// ================== User Handlers ==================

func (p *Plugin) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}
	if scimErr := checkUser(&user); scimErr != nil {
		WriteError(w, scimErr)
		return
	}
	// RFC 7644 Section 3.3: "In the request body, attributes whose mutability
	// is "readOnly" (see Sections 2.2 and 7 of [RFC7643]) SHALL be ignored."
	// The store issues "id" and "meta" itself and drops "groups".
	created, err := p.storage.CreateUser(ctx, &user)
	if err != nil {
		scimErr := storeError("User", "", "userName", err)
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "SCIM User Not Created", map[string]interface{}{
			"userName": user.UserName, "status": scimErr.Status, "scimType": scimErr.ScimType, "detail": scimErr.Detail,
		}, "RFC 7644 Section 3.3")
		WriteError(w, scimErr)
		return
	}
	p.describeUser(ctx, created)

	p.logProvisioningAction(r, "create", "User", created.ID, map[string]interface{}{
		"userName":    created.UserName,
		"displayName": created.DisplayName,
		"active":      created.Active,
	})
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM User Created", map[string]interface{}{
		"id": created.ID, "userName": created.UserName, "location": created.Meta.Location, "version": created.Meta.Version,
	}, "RFC 7644 Section 3.3")
	writeResource(w, http.StatusCreated, created.Meta, created, selected)
}

func (p *Plugin) handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	user, err := p.storage.GetUser(ctx, id)
	if err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	p.describeUser(ctx, user)
	if notModified(w, r, user.Meta) {
		return
	}
	writeResource(w, http.StatusOK, user.Meta, user, selected)
}

func (p *Plugin) handleReplaceUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}
	// RFC 7644 Section 3.5.1: "Because SCIM resource identifiers are assigned
	// by the service provider, HTTP PUT MUST NOT be used to create new
	// resources."
	current, err := p.storage.GetUser(ctx, id)
	if err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}
	// 'If an attribute is "required", clients MUST specify the attribute in
	// the PUT request', and for readOnly attributes "Any values provided
	// SHALL be ignored." The store keeps "id" and "meta" and drops "groups".
	if scimErr := checkUser(&user); scimErr != nil {
		WriteError(w, scimErr)
		return
	}
	expected, _ := ParseETag(current.Meta.Version)
	updated, err := p.storage.UpdateUser(ctx, id, &user, expected)
	if err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	p.describeUser(ctx, updated)

	p.logProvisioningAction(r, "update", "User", updated.ID, map[string]interface{}{"userName": updated.UserName})
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM User Replaced", map[string]interface{}{
		"id": updated.ID, "userName": updated.UserName, "version": updated.Meta.Version,
	}, "RFC 7644 Section 3.5.1")
	writeResource(w, http.StatusOK, updated.Meta, updated, selected)
}

func (p *Plugin) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	current, err := p.storage.GetUser(ctx, id)
	if err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}

	var patched User
	scimErr := patchResource(body, current, &patched, userResourceSchema)
	if scimErr == nil {
		// The password attribute is not kept, so it changes nothing here.
		patched.Password = ""
		scimErr = checkUser(&patched)
	}
	if scimErr != nil {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "SCIM PATCH Refused", map[string]interface{}{
			"id": id, "status": scimErr.Status, "scimType": scimErr.ScimType, "detail": scimErr.Detail, "resource": "unchanged",
		}, "RFC 7644 Section 3.5.2")
		WriteError(w, scimErr)
		return
	}

	updated := current
	changed := !sameResource(current, &patched)
	if changed {
		expected, _ := ParseETag(current.Meta.Version)
		if updated, err = p.storage.UpdateUser(ctx, id, &patched, expected); err != nil {
			WriteError(w, storeError("User", id, "userName", err))
			return
		}
		p.logProvisioningAction(r, "update", "User", updated.ID, map[string]interface{}{"userName": updated.UserName})
	}
	p.describeUser(ctx, updated)
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM PATCH Applied", map[string]interface{}{
		"id": updated.ID, "changed": changed, "version": updated.Meta.Version,
	}, "RFC 7644 Section 3.5.2")
	// "On successful completion, the server either MUST return a 200 OK
	// response code and the entire resource within the response body, subject
	// to the "attributes" query parameter (see Section 3.9), or MAY return
	// HTTP status code 204 (No Content)".
	writeResource(w, http.StatusOK, updated.Meta, updated, selected)
}

// patchResource applies the PATCH request in body to current and decodes the
// result into patched. current is not changed.
func patchResource(body []byte, current, patched interface{}, schema *resourceSchema) *SCIMError {
	operations, scimErr := parsePatchRequest(body)
	if scimErr != nil {
		return scimErr
	}
	item, err := newQueryItem(current)
	if err != nil {
		return ErrInternalServer(err.Error())
	}
	if scimErr := applyPatch(item.object, schema, operations); scimErr != nil {
		return scimErr
	}
	result, err := json.Marshal(item.object)
	if err != nil {
		return ErrInternalServer(err.Error())
	}
	if err := json.Unmarshal(result, patched); err != nil {
		return ErrInvalidValue(err.Error())
	}
	return nil
}

// sameResource reports whether two resources have the same representation.
// RFC 7644 Section 3.5.2.1: "If the target location already contains the
// value specified, no changes SHOULD be made to the resource, and a success
// response SHOULD be returned. Unless other operations change the resource,
// this operation SHALL NOT change the modify timestamp of the resource."
func sameResource(a, b interface{}) bool {
	left, errLeft := newQueryItem(a)
	right, errRight := newQueryItem(b)
	return errLeft == nil && errRight == nil && reflect.DeepEqual(left.object, right.object)
}

func (p *Plugin) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	current, err := p.storage.GetUser(ctx, id)
	if err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}
	if err := p.storage.DeleteUser(ctx, id); err != nil {
		WriteError(w, storeError("User", id, "userName", err))
		return
	}
	p.logProvisioningAction(r, "delete", "User", id, nil)
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM User Deleted", map[string]interface{}{"id": id}, "RFC 7644 Section 3.6")
	// "In response to a successful DELETE, the server SHALL return a
	// successful HTTP status code 204 (No Content)."
	w.WriteHeader(http.StatusNoContent)
}

// ================== Group Handlers ==================

func (p *Plugin) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}
	if scimErr := p.checkGroup(ctx, &group); scimErr != nil {
		WriteError(w, scimErr)
		return
	}
	created, err := p.storage.CreateGroup(ctx, &group)
	if err != nil {
		WriteError(w, storeError("Group", "", "displayName", err))
		return
	}
	p.describeGroup(created)
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM Group Created", map[string]interface{}{
		"id": created.ID, "displayName": created.DisplayName, "members": len(created.Members), "location": created.Meta.Location,
	}, "RFC 7644 Section 3.3")
	writeResource(w, http.StatusCreated, created.Meta, created, selected)
}

func (p *Plugin) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	group, err := p.storage.GetGroup(r.Context(), id)
	if err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	p.describeGroup(group)
	if notModified(w, r, group.Meta) {
		return
	}
	writeResource(w, http.StatusOK, group.Meta, group, selected)
}

func (p *Plugin) handleReplaceGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}
	current, err := p.storage.GetGroup(ctx, id)
	if err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}
	if scimErr := p.checkGroup(ctx, &group); scimErr != nil {
		WriteError(w, scimErr)
		return
	}
	expected, _ := ParseETag(current.Meta.Version)
	updated, err := p.storage.UpdateGroup(ctx, id, &group, expected)
	if err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	p.describeGroup(updated)
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM Group Replaced", map[string]interface{}{
		"id": updated.ID, "displayName": updated.DisplayName, "members": len(updated.Members), "version": updated.Meta.Version,
	}, "RFC 7644 Section 3.5.1")
	writeResource(w, http.StatusOK, updated.Meta, updated, selected)
}

func (p *Plugin) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	selected, ok := requestProjection(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	current, err := p.storage.GetGroup(ctx, id)
	if err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}

	var patched Group
	scimErr := patchResource(body, current, &patched, groupResourceSchema)
	if scimErr == nil {
		scimErr = p.checkGroup(ctx, &patched)
	}
	if scimErr != nil {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "SCIM PATCH Refused", map[string]interface{}{
			"id": id, "status": scimErr.Status, "scimType": scimErr.ScimType, "detail": scimErr.Detail, "resource": "unchanged",
		}, "RFC 7644 Section 3.5.2")
		WriteError(w, scimErr)
		return
	}

	updated := current
	changed := !sameMembers(current, &patched) || current.DisplayName != patched.DisplayName || current.ExternalID != patched.ExternalID
	if changed {
		expected, _ := ParseETag(current.Meta.Version)
		if updated, err = p.storage.UpdateGroup(ctx, id, &patched, expected); err != nil {
			WriteError(w, storeError("Group", id, "displayName", err))
			return
		}
	}
	p.describeGroup(updated)
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM PATCH Applied", map[string]interface{}{
		"id": updated.ID, "changed": changed, "members": len(updated.Members), "version": updated.Meta.Version,
	}, "RFC 7644 Section 3.5.2")
	writeResource(w, http.StatusOK, updated.Meta, updated, selected)
}

// sameMembers reports whether two Groups have the same members.
func sameMembers(a, b *Group) bool {
	if len(a.Members) != len(b.Members) {
		return false
	}
	members := map[string]bool{}
	for _, member := range a.Members {
		members[member.Value] = true
	}
	for _, member := range b.Members {
		if !members[member.Value] {
			return false
		}
	}
	return true
}

func (p *Plugin) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	current, err := p.storage.GetGroup(ctx, id)
	if err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	if preconditionFailed(w, r, current.Meta) {
		return
	}
	if err := p.storage.DeleteGroup(ctx, id); err != nil {
		WriteError(w, storeError("Group", id, "displayName", err))
		return
	}
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM Group Deleted", map[string]interface{}{"id": id}, "RFC 7644 Section 3.6")
	w.WriteHeader(http.StatusNoContent)
}

// ================== Info Handler ==================

func (p *Plugin) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"protocol":    "SCIM 2.0",
		"rfcs":        []string{"RFC 7642", "RFC 7643", "RFC 7644"},
		"description": "System for Cross-domain Identity Management",
		"endpoints": map[string]string{
			"serviceProviderConfig": "/scim/v2/ServiceProviderConfig",
			"resourceTypes":         "/scim/v2/ResourceTypes",
			"schemas":               "/scim/v2/Schemas",
			"users":                 "/scim/v2/Users",
			"groups":                "/scim/v2/Groups",
			"bulk":                  "/scim/v2/Bulk",
			"search":                "/scim/v2/.search",
		},
		"features": map[string]bool{
			"patch":          true,
			"bulk":           true,
			"filter":         true,
			"sort":           true,
			"etag":           true,
			"changePassword": false,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// ================== Client Provisioning Handlers ==================

func (p *Plugin) handleClientProvision(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	var req struct {
		TargetURL string `json:"targetUrl"`
		AuthToken string `json:"authToken"`
		User      *User  `json:"user"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	if req.TargetURL == "" || req.User == nil {
		WriteError(w, ErrInvalidValue("targetUrl and user are required"))
		return
	}
	if strings.TrimSpace(req.User.UserName) == "" {
		WriteError(w, ErrInvalidValue("user.userName is required"))
		return
	}

	targetURL, err := normalizeSCIMTargetURL(req.TargetURL, p.Config().Environment)
	if err != nil {
		WriteError(w, ErrInvalidValue(err.Error()))
		return
	}

	p.emitEvent(r, lookingglass.EventTypeFlowStep, "Outbound Provision", map[string]interface{}{
		"target":   targetURL,
		"userName": req.User.UserName,
	}, "RFC 7644 Section 3")

	client := NewClient(targetURL, req.AuthToken)
	created, err := client.CreateUser(r.Context(), outboundUserCopy(req.User))
	if err != nil {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "Provision Failed", map[string]interface{}{
			"target": targetURL,
			"error":  err.Error(),
		}, "RFC 7644 Section 3")
		WriteError(w, &SCIMError{Status: http.StatusBadGateway, Detail: "target SCIM provisioning failed: " + err.Error()})
		return
	}
	if created.ID == "" {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "Provision Failed", map[string]interface{}{
			"target": targetURL,
			"error":  "target returned a created user without the required id attribute",
		}, "RFC 7644 Section 3")
		WriteError(w, &SCIMError{Status: http.StatusBadGateway, Detail: "target SCIM service returned a created user without the required id attribute"})
		return
	}

	p.emitEvent(r, lookingglass.EventTypeFlowStep, "Outbound User Created", map[string]interface{}{
		"localId":   req.User.ID,
		"remoteId":  created.ID,
		"targetUrl": targetURL,
	}, "RFC 7644 Section 3")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(created)
}

func (p *Plugin) handleClientSync(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	var req struct {
		TargetURL string `json:"targetUrl"`
		AuthToken string `json:"authToken"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	targetURL, err := normalizeSCIMTargetURL(req.TargetURL, p.Config().Environment)
	if err != nil {
		WriteError(w, ErrInvalidValue(err.Error()))
		return
	}

	startedAt := timeNow().UTC()
	client := NewClient(targetURL, req.AuthToken)
	capabilities, err := client.GetServiceProviderConfig(r.Context())
	if err != nil {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "Target Discovery Failed", map[string]interface{}{
			"target": targetURL,
			"error":  err.Error(),
		}, "RFC 7644 Section 3")
		WriteError(w, &SCIMError{Status: http.StatusBadGateway, Detail: "target SCIM discovery failed: " + err.Error()})
		return
	}

	users, err := p.storage.ListAllUsers(r.Context())
	if err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}
	previousSync, _, err := p.storage.GetSyncState(r.Context(), targetURL)
	if err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}
	mappings, err := p.storage.GetSyncMappings(r.Context(), targetURL)
	if err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	p.emitEvent(r, lookingglass.EventTypeFlowStep, "Sync Started", map[string]interface{}{
		"target":               targetURL,
		"sourceUserCount":      len(users),
		"existingMappingCount": len(mappings),
		"previousLastSync":     previousSync,
		"capabilities":         capabilities,
	}, "RFC 7644 Section 3")

	result, err := client.SyncUsers(r.Context(), users, mappings)
	if err != nil {
		p.emitEvent(r, lookingglass.EventTypeSecurityWarning, "Sync Failed", map[string]interface{}{
			"target": targetURL,
			"error":  err.Error(),
		}, "RFC 7644 Section 3")
		WriteError(w, &SCIMError{Status: http.StatusBadGateway, Detail: "target SCIM sync failed: " + err.Error()})
		return
	}

	completedAt := timeNow().UTC()
	successfulMappings := make(map[string]string)
	for _, detail := range result.Details {
		if detail.Status == "success" && result.Mappings[detail.LocalID] != "" {
			successfulMappings[detail.LocalID] = result.Mappings[detail.LocalID]
		}
	}
	if err := p.storage.UpsertSyncMappings(r.Context(), targetURL, successfulMappings, completedAt); err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	usersByID := make(map[string]*User, len(users))
	for _, user := range users {
		usersByID[user.ID] = outboundUserCopy(user)
	}
	for _, detail := range result.Details {
		p.emitEvent(r, lookingglass.EventTypeFlowStep, "Outbound User Operation", map[string]interface{}{
			"target":      targetURL,
			"localId":     detail.LocalID,
			"remoteId":    detail.RemoteID,
			"operation":   detail.Operation,
			"status":      detail.Status,
			"error":       detail.Error,
			"requestBody": usersByID[detail.LocalID],
		}, "RFC 7644 Section 3")
	}

	status := "completed"
	statusCode := http.StatusOK
	var lastSuccessfulSync *time.Time
	if result.Errors == 0 {
		if err := p.storage.UpdateSyncState(r.Context(), targetURL, completedAt, ""); err != nil {
			WriteError(w, ErrInternalServer(err.Error()))
			return
		}
		lastSuccessfulSync = &completedAt
	} else {
		status = "partial"
		statusCode = http.StatusMultiStatus
		if !previousSync.IsZero() {
			lastSuccessfulSync = &previousSync
		}
	}

	response := ClientSyncResponse{
		Status:             status,
		TargetURL:          targetURL,
		StartedAt:          startedAt,
		CompletedAt:        completedAt,
		SourceUserCount:    len(users),
		LastSuccessfulSync: lastSuccessfulSync,
		Result:             result,
	}
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "Sync Completed", map[string]interface{}{
		"target":   targetURL,
		"response": response,
	}, "RFC 7644 Section 3")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// ClientSyncResponse reports the real outcome of a one-way source-to-target
// reconciliation. Deletions are deliberately not inferred: removing a remote
// identity requires an explicit deprovisioning policy.
type ClientSyncResponse struct {
	Status             string      `json:"status"`
	TargetURL          string      `json:"targetUrl"`
	StartedAt          time.Time   `json:"startedAt"`
	CompletedAt        time.Time   `json:"completedAt"`
	SourceUserCount    int         `json:"sourceUserCount"`
	LastSuccessfulSync *time.Time  `json:"lastSuccessfulSync,omitempty"`
	Result             *SyncResult `json:"result"`
}

func normalizeSCIMTargetURL(raw, environment string) (string, error) {
	target := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("targetUrl must be an absolute SCIM base URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("targetUrl must not contain credentials, a query, or a fragment")
	}
	if parsed.Scheme != "https" && (environment == "production" || parsed.Scheme != "http") {
		return "", fmt.Errorf("targetUrl must use HTTPS (HTTP is allowed only outside production)")
	}
	if environment == "production" {
		if err := rejectPrivateSCIMTarget(parsed.Hostname()); err != nil {
			return "", err
		}
	}
	return target, nil
}

// rejectPrivateSCIMTarget resolves the target host and rejects loopback,
// private, link-local, unspecified, and multicast addresses. Without this,
// an authenticated caller could point the outbound sync/provision endpoints
// at internal infrastructure (SSRF) instead of a real external SCIM service.
// Only enforced in production: local/demo environments intentionally target
// docker-compose networks and local IdP emulators on private addresses.
func rejectPrivateSCIMTarget(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedSCIMTargetIP(ip) {
			return fmt.Errorf("targetUrl must not be a private, loopback, or link-local address")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("targetUrl host could not be resolved: %w", err)
	}
	for _, ip := range ips {
		if isDisallowedSCIMTargetIP(ip) {
			return fmt.Errorf("targetUrl must not resolve to a private, loopback, or link-local address")
		}
	}
	return nil
}

func isDisallowedSCIMTargetIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// ================== Status & Events Handlers ==================

// handleProvisioningEvents returns recent provisioning events from external IdPs
func (p *Plugin) handleProvisioningEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events := GetProvisioningEvents(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

// handleConnectionStatus returns the current SCIM connection configuration
func (p *Plugin) handleConnectionStatus(w http.ResponseWriter, r *http.Request) {
	// Count recent events to determine if IdP is actively connecting
	events := GetProvisioningEvents(10)
	activeConnection := len(events) > 0

	// Determine IdP from recent events
	detectedIdP := "none"
	if len(events) > 0 {
		detectedIdP = events[0].Source
	}

	status := map[string]interface{}{
		"authentication": map[string]interface{}{
			"scheme":              "oauthbearertoken",
			"authorizationServer": p.asIssuer,
			"resource":            p.resource,
			"scopes":              []string{ScopeRead, ScopeWrite},
		},
		"activeConnection": activeConnection,
		"detectedIdP":      detectedIdP,
		"scimEndpoint":     p.baseURL + "/scim/v2",
		"supportedFeatures": map[string]bool{
			"patch":          true,
			"bulk":           true,
			"filter":         true,
			"etag":           true,
			"sort":           true,
			"changePassword": false,
		},
		"recentEventsCount": len(events),
		"configuration": map[string]string{
			"usersEndpoint":   p.baseURL + "/scim/v2/Users",
			"groupsEndpoint":  p.baseURL + "/scim/v2/Groups",
			"schemasEndpoint": p.baseURL + "/scim/v2/Schemas",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ================== Helper Functions ==================

// emitEvent records a SCIM operation in the Looking Glass session the request
// belongs to, with the specification section that governs it.
func (p *Plugin) emitEvent(r *http.Request, eventType lookingglass.EventType, title string, data map[string]interface{}, reference string) {
	sessionID := r.Header.Get("X-Looking-Glass-Session")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("lg_session")
	}
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	p.lookingGlass.NewEventBroadcaster(sessionID).Emit(eventType, title, data, lookingglass.Annotation{
		Type:      lookingglass.AnnotationTypeRFCReference,
		Title:     title,
		Reference: reference,
	})
}

// logProvisioningAction logs a provisioning action from an external IdP
func (p *Plugin) logProvisioningAction(r *http.Request, action, resource, resourceID string, data map[string]interface{}) {
	source := DetectIdPSource(r)

	event := ProvisioningEvent{
		ID:        resourceID,
		Timestamp: timeNow(),
		Source:    source,
		Action:    action,
		Resource:  resource,
		UserAgent: r.Header.Get("User-Agent"),
		Data:      data,
	}

	LogProvisioningEvent(event)
}
