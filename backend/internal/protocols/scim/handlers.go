package scim

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// timeNow returns the current time (can be mocked for testing)
var timeNow = time.Now

// ================== Discovery Handlers ==================

func (p *Plugin) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	p.emitEvent("scim.request", "ServiceProviderConfig", map[string]interface{}{
		"method": "GET",
		"path":   "/ServiceProviderConfig",
	})

	config := GetServiceProviderConfig(p.baseURL)
	
	p.emitEvent("scim.response", "ServiceProviderConfig", map[string]interface{}{
		"status": 200,
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(config)
}

func (p *Plugin) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	p.emitEvent("scim.request", "ResourceTypes", map[string]interface{}{
		"method": "GET",
		"path":   "/ResourceTypes",
	})

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

// ================== User Handlers ==================

func (p *Plugin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Parse query parameters
	filter := r.URL.Query().Get("filter")
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}

	p.emitEvent("scim.request", "List Users", map[string]interface{}{
		"method":     "GET",
		"path":       "/Users",
		"filter":     filter,
		"startIndex": startIndex,
		"count":      count,
	})

	// Parse and emit filter analysis
	if filter != "" {
		parsed, err := ParseFilter(filter)
		if err != nil {
			p.emitEvent("scim.error", "Invalid Filter", map[string]interface{}{
				"filter": filter,
				"error":  err.Error(),
			})
			WriteError(w, ErrInvalidFilter(err.Error()))
			return
		}
		
		translator := NewSQLTranslator("user")
		sql, params, _ := translator.Translate(parsed)
		p.emitEvent("scim.filter.parsed", "Filter Analysis", map[string]interface{}{
			"filter":     filter,
			"ast":        parsed.String(),
			"sql":        sql,
			"parameters": params,
		})
	}

	users, total, err := p.storage.ListUsers(ctx, filter, startIndex, count)
	if err != nil {
		if scimErr, ok := err.(*SCIMError); ok {
			WriteError(w, scimErr)
		} else {
			WriteError(w, ErrInternalServer(err.Error()))
		}
		return
	}

	// Build list response
	response := NewListResponse()
	response.TotalResults = total
	response.StartIndex = startIndex
	response.ItemsPerPage = len(users)

	for _, user := range users {
		// Add location to meta
		if user.Meta != nil {
			user.Meta.Location = p.baseURL + "/scim/v2/Users/" + user.ID
		}
		// Add groups
		groups, _ := p.storage.GetUserGroups(ctx, user.ID)
		if len(groups) > 0 {
			for i := range groups {
				groups[i].Ref = p.baseURL + "/scim/v2/Groups/" + groups[i].Value
			}
			user.Groups = groups
		}
		data, _ := json.Marshal(user)
		response.Resources = append(response.Resources, data)
	}

	p.emitEvent("scim.response", "Users Listed", map[string]interface{}{
		"status":       200,
		"totalResults": total,
		"returned":     len(users),
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
}

func (p *Plugin) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
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

	// Validate required fields
	if user.UserName == "" {
		WriteError(w, ErrInvalidValue("userName is required"))
		return
	}

	// Ensure schemas are set
	if len(user.Schemas) == 0 {
		user.Schemas = []string{SchemaURNUser}
	}

	p.emitEvent("scim.request", "Create User", map[string]interface{}{
		"method":   "POST",
		"path":     "/Users",
		"userName": user.UserName,
	})

	created, err := p.storage.CreateUser(ctx, &user)
	if err != nil {
		if err == ErrConflict {
			p.emitEvent("scim.error", "Uniqueness Violation", map[string]interface{}{
				"userName": user.UserName,
			})
			WriteError(w, ErrConflictUniqueness("userName"))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	// Set location
	created.Meta.Location = p.baseURL + "/scim/v2/Users/" + created.ID

	// Log provisioning event from external IdP
	p.logProvisioningAction(r, "create", "User", created.ID, map[string]interface{}{
		"userName":    created.UserName,
		"displayName": created.DisplayName,
		"active":      created.Active,
	})

	p.emitEvent("scim.user.created", "User Created", map[string]interface{}{
		"id":       created.ID,
		"userName": created.UserName,
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("Location", created.Meta.Location)
	w.Header().Set("ETag", created.Meta.Version)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (p *Plugin) handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	p.emitEvent("scim.request", "Get User", map[string]interface{}{
		"method": "GET",
		"path":   "/Users/" + id,
	})

	user, err := p.storage.GetUser(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("User", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	// Set location
	user.Meta.Location = p.baseURL + "/scim/v2/Users/" + user.ID

	// Add groups
	groups, _ := p.storage.GetUserGroups(ctx, user.ID)
	if len(groups) > 0 {
		for i := range groups {
			groups[i].Ref = p.baseURL + "/scim/v2/Groups/" + groups[i].Value
		}
		user.Groups = groups
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", user.Meta.Version)
	json.NewEncoder(w).Encode(user)
}

func (p *Plugin) handleReplaceUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

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

	// Check If-Match header for optimistic locking
	expectedVersion := 0
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		expectedVersion, _ = ParseETag(ifMatch)
	}

	p.emitEvent("scim.request", "Replace User", map[string]interface{}{
		"method": "PUT",
		"path":   "/Users/" + id,
		"etag":   r.Header.Get("If-Match"),
	})

	updated, err := p.storage.UpdateUser(ctx, id, &user, expectedVersion)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("User", id))
			return
		}
		if err == ErrVersionConflict {
			WriteError(w, ErrPreconditionFailed("ETag mismatch"))
			return
		}
		if err == ErrConflict {
			WriteError(w, ErrConflictUniqueness("userName"))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	updated.Meta.Location = p.baseURL + "/scim/v2/Users/" + updated.ID

	p.emitEvent("scim.user.updated", "User Replaced", map[string]interface{}{
		"id":       updated.ID,
		"userName": updated.UserName,
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", updated.Meta.Version)
	json.NewEncoder(w).Encode(updated)
}

func (p *Plugin) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	var patchReq PatchRequest
	if err := json.Unmarshal(body, &patchReq); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	p.emitEvent("scim.request", "Patch User", map[string]interface{}{
		"method":     "PATCH",
		"path":       "/Users/" + id,
		"operations": len(patchReq.Operations),
	})

	// Get current user
	user, err := p.storage.GetUser(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("User", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	// Apply patch operations
	changes, err := ApplyPatchToUser(user, &patchReq)
	if err != nil {
		if scimErr, ok := err.(*SCIMError); ok {
			WriteError(w, scimErr)
		} else {
			WriteError(w, ErrInvalidValue(err.Error()))
		}
		return
	}

	p.emitEvent("scim.patch.applied", "Patch Applied", map[string]interface{}{
		"userId":  id,
		"changes": changes,
	})

	// Save updated user
	expectedVersion, _ := ParseETag(user.Meta.Version)
	updated, err := p.storage.UpdateUser(ctx, id, user, expectedVersion)
	if err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	updated.Meta.Location = p.baseURL + "/scim/v2/Users/" + updated.ID

	// Log provisioning event from external IdP
	p.logProvisioningAction(r, "update", "User", updated.ID, map[string]interface{}{
		"userName": updated.UserName,
		"changes":  changes,
	})

	p.emitEvent("scim.user.updated", "User Patched", map[string]interface{}{
		"id":      updated.ID,
		"changes": changes,
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", updated.Meta.Version)
	json.NewEncoder(w).Encode(updated)
}

func (p *Plugin) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	p.emitEvent("scim.request", "Delete User", map[string]interface{}{
		"method": "DELETE",
		"path":   "/Users/" + id,
	})

	err := p.storage.DeleteUser(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("User", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	// Log provisioning event from external IdP
	p.logProvisioningAction(r, "delete", "User", id, nil)

	p.emitEvent("scim.user.deleted", "User Deleted", map[string]interface{}{
		"id": id,
	})

	w.WriteHeader(http.StatusNoContent)
}

// ================== Group Handlers ==================

func (p *Plugin) handleListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	filter := r.URL.Query().Get("filter")
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 || count > 200 {
		count = 100
	}

	groups, total, err := p.storage.ListGroups(ctx, filter, startIndex, count)
	if err != nil {
		if scimErr, ok := err.(*SCIMError); ok {
			WriteError(w, scimErr)
		} else {
			WriteError(w, ErrInternalServer(err.Error()))
		}
		return
	}

	response := NewListResponse()
	response.TotalResults = total
	response.StartIndex = startIndex
	response.ItemsPerPage = len(groups)

	for _, group := range groups {
		if group.Meta != nil {
			group.Meta.Location = p.baseURL + "/scim/v2/Groups/" + group.ID
		}
		// Add member refs
		for i := range group.Members {
			if group.Members[i].Type == "User" || group.Members[i].Type == "" {
				group.Members[i].Ref = p.baseURL + "/scim/v2/Users/" + group.Members[i].Value
			}
		}
		data, _ := json.Marshal(group)
		response.Resources = append(response.Resources, data)
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
}

func (p *Plugin) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
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

	if group.DisplayName == "" {
		WriteError(w, ErrInvalidValue("displayName is required"))
		return
	}

	if len(group.Schemas) == 0 {
		group.Schemas = []string{SchemaURNGroup}
	}

	created, err := p.storage.CreateGroup(ctx, &group)
	if err != nil {
		if err == ErrConflict {
			WriteError(w, ErrConflictUniqueness("displayName"))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	created.Meta.Location = p.baseURL + "/scim/v2/Groups/" + created.ID

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("Location", created.Meta.Location)
	w.Header().Set("ETag", created.Meta.Version)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (p *Plugin) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	group, err := p.storage.GetGroup(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("Group", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	group.Meta.Location = p.baseURL + "/scim/v2/Groups/" + group.ID
	for i := range group.Members {
		if group.Members[i].Type == "User" || group.Members[i].Type == "" {
			group.Members[i].Ref = p.baseURL + "/scim/v2/Users/" + group.Members[i].Value
		}
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", group.Meta.Version)
	json.NewEncoder(w).Encode(group)
}

func (p *Plugin) handleReplaceGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

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

	expectedVersion := 0
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		expectedVersion, _ = ParseETag(ifMatch)
	}

	updated, err := p.storage.UpdateGroup(ctx, id, &group, expectedVersion)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("Group", id))
			return
		}
		if err == ErrVersionConflict {
			WriteError(w, ErrPreconditionFailed("ETag mismatch"))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	updated.Meta.Location = p.baseURL + "/scim/v2/Groups/" + updated.ID

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", updated.Meta.Version)
	json.NewEncoder(w).Encode(updated)
}

func (p *Plugin) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	var patchReq PatchRequest
	if err := json.Unmarshal(body, &patchReq); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	group, err := p.storage.GetGroup(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("Group", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	changes, err := ApplyPatchToGroup(group, &patchReq)
	if err != nil {
		if scimErr, ok := err.(*SCIMError); ok {
			WriteError(w, scimErr)
		} else {
			WriteError(w, ErrInvalidValue(err.Error()))
		}
		return
	}

	p.emitEvent("scim.patch.applied", "Group Patch Applied", map[string]interface{}{
		"groupId": id,
		"changes": changes,
	})

	expectedVersion, _ := ParseETag(group.Meta.Version)
	updated, err := p.storage.UpdateGroup(ctx, id, group, expectedVersion)
	if err != nil {
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	updated.Meta.Location = p.baseURL + "/scim/v2/Groups/" + updated.ID

	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.Header().Set("ETag", updated.Meta.Version)
	json.NewEncoder(w).Encode(updated)
}

func (p *Plugin) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	err := p.storage.DeleteGroup(ctx, id)
	if err != nil {
		if err == ErrNotFound {
			WriteError(w, ErrResourceNotFound("Group", id))
			return
		}
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ================== Bulk Handler ==================

func (p *Plugin) handleBulk(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	// Check payload size
	if len(body) > 1048576 { // 1MB
		WriteError(w, ErrPayloadTooLarge(1048576))
		return
	}

	var bulkReq BulkRequest
	if err := json.Unmarshal(body, &bulkReq); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	if len(bulkReq.Operations) > 1000 {
		WriteError(w, ErrBadRequest("Too many operations (max 1000)"))
		return
	}

	p.emitEvent("scim.request", "Bulk Operation", map[string]interface{}{
		"method":       "POST",
		"path":         "/Bulk",
		"operations":   len(bulkReq.Operations),
		"failOnErrors": bulkReq.FailOnErrors,
	})

	response := &BulkResponse{
		Schemas:    []string{SchemaURNBulkResponse},
		Operations: make([]BulkOperationResult, 0, len(bulkReq.Operations)),
	}

	errorCount := 0
	for i, op := range bulkReq.Operations {
		p.emitEvent("scim.bulk.progress", "Processing Operation", map[string]interface{}{
			"index":  i + 1,
			"total":  len(bulkReq.Operations),
			"method": op.Method,
			"path":   op.Path,
		})

		result := p.executeBulkOperation(op)
		response.Operations = append(response.Operations, result)

		if strings.HasPrefix(result.Status, "4") || strings.HasPrefix(result.Status, "5") {
			errorCount++
			if bulkReq.FailOnErrors > 0 && errorCount >= bulkReq.FailOnErrors {
				break
			}
		}
	}

	p.emitEvent("scim.response", "Bulk Complete", map[string]interface{}{
		"status":     200,
		"operations": len(response.Operations),
		"errors":     errorCount,
	})

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
}

func (p *Plugin) executeBulkOperation(op BulkOperation) BulkOperationResult {
	result := BulkOperationResult{
		Method: op.Method,
		BulkID: op.BulkID,
	}

	// Parse path to determine resource type and ID
	path := strings.TrimPrefix(op.Path, "/")
	parts := strings.Split(path, "/")
	
	if len(parts) == 0 {
		result.Status = "400"
		errResp, _ := json.Marshal(NewErrorResponse(400, ErrorTypeInvalidPath, "Invalid path"))
		result.Response = errResp
		return result
	}

	resourceType := parts[0]
	var resourceID string
	if len(parts) > 1 {
		resourceID = parts[1]
	}

	switch strings.ToUpper(op.Method) {
	case "POST":
		result = p.bulkCreate(resourceType, op.Data, op.BulkID)
	case "PUT":
		result = p.bulkReplace(resourceType, resourceID, op.Data, op.BulkID)
	case "PATCH":
		result = p.bulkPatch(resourceType, resourceID, op.Data, op.BulkID)
	case "DELETE":
		result = p.bulkDelete(resourceType, resourceID, op.BulkID)
	default:
		result.Status = "400"
		errResp, _ := json.Marshal(NewErrorResponse(400, ErrorTypeInvalidValue, "Invalid method"))
		result.Response = errResp
	}

	return result
}

func (p *Plugin) bulkCreate(resourceType string, data json.RawMessage, bulkID string) BulkOperationResult {
	result := BulkOperationResult{Method: "POST", BulkID: bulkID}
	ctx := context.Background()

	switch resourceType {
	case "Users":
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			result.Status = "400"
			return result
		}
		created, err := p.storage.CreateUser(ctx, &user)
		if err != nil {
			result.Status = "409"
			return result
		}
		result.Status = "201"
		result.Location = p.baseURL + "/scim/v2/Users/" + created.ID
		result.Version = created.Meta.Version
		resp, _ := json.Marshal(created)
		result.Response = resp
	case "Groups":
		var group Group
		if err := json.Unmarshal(data, &group); err != nil {
			result.Status = "400"
			return result
		}
		created, err := p.storage.CreateGroup(ctx, &group)
		if err != nil {
			result.Status = "409"
			return result
		}
		result.Status = "201"
		result.Location = p.baseURL + "/scim/v2/Groups/" + created.ID
		result.Version = created.Meta.Version
		resp, _ := json.Marshal(created)
		result.Response = resp
	default:
		result.Status = "400"
	}

	return result
}

func (p *Plugin) bulkReplace(resourceType, id string, data json.RawMessage, bulkID string) BulkOperationResult {
	result := BulkOperationResult{Method: "PUT", BulkID: bulkID}
	ctx := context.Background()

	switch resourceType {
	case "Users":
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			result.Status = "400"
			return result
		}
		updated, err := p.storage.UpdateUser(ctx, id, &user, 0)
		if err != nil {
			if err == ErrNotFound {
				result.Status = "404"
			} else {
				result.Status = "500"
			}
			return result
		}
		result.Status = "200"
		result.Location = p.baseURL + "/scim/v2/Users/" + updated.ID
		result.Version = updated.Meta.Version
	case "Groups":
		var group Group
		if err := json.Unmarshal(data, &group); err != nil {
			result.Status = "400"
			return result
		}
		updated, err := p.storage.UpdateGroup(ctx, id, &group, 0)
		if err != nil {
			if err == ErrNotFound {
				result.Status = "404"
			} else {
				result.Status = "500"
			}
			return result
		}
		result.Status = "200"
		result.Location = p.baseURL + "/scim/v2/Groups/" + updated.ID
		result.Version = updated.Meta.Version
	default:
		result.Status = "400"
	}

	return result
}

func (p *Plugin) bulkPatch(resourceType, id string, data json.RawMessage, bulkID string) BulkOperationResult {
	result := BulkOperationResult{Method: "PATCH", BulkID: bulkID}
	ctx := context.Background()

	var patchReq PatchRequest
	if err := json.Unmarshal(data, &patchReq); err != nil {
		result.Status = "400"
		return result
	}

	switch resourceType {
	case "Users":
		user, err := p.storage.GetUser(ctx, id)
		if err != nil {
			result.Status = "404"
			return result
		}
		if _, err := ApplyPatchToUser(user, &patchReq); err != nil {
			result.Status = "400"
			return result
		}
		updated, err := p.storage.UpdateUser(ctx, id, user, 0)
		if err != nil {
			result.Status = "500"
			return result
		}
		result.Status = "200"
		result.Location = p.baseURL + "/scim/v2/Users/" + updated.ID
		result.Version = updated.Meta.Version
	case "Groups":
		group, err := p.storage.GetGroup(ctx, id)
		if err != nil {
			result.Status = "404"
			return result
		}
		if _, err := ApplyPatchToGroup(group, &patchReq); err != nil {
			result.Status = "400"
			return result
		}
		updated, err := p.storage.UpdateGroup(ctx, id, group, 0)
		if err != nil {
			result.Status = "500"
			return result
		}
		result.Status = "200"
		result.Location = p.baseURL + "/scim/v2/Groups/" + updated.ID
		result.Version = updated.Meta.Version
	default:
		result.Status = "400"
	}

	return result
}

func (p *Plugin) bulkDelete(resourceType, id, bulkID string) BulkOperationResult {
	result := BulkOperationResult{Method: "DELETE", BulkID: bulkID}
	ctx := context.Background()

	var err error
	switch resourceType {
	case "Users":
		err = p.storage.DeleteUser(ctx, id)
	case "Groups":
		err = p.storage.DeleteGroup(ctx, id)
	default:
		result.Status = "400"
		return result
	}

	if err != nil {
		if err == ErrNotFound {
			result.Status = "404"
		} else {
			result.Status = "500"
		}
		return result
	}

	result.Status = "204"
	return result
}

// ================== Search Handler ==================

func (p *Plugin) handleSearch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}

	var searchReq SearchRequest
	if err := json.Unmarshal(body, &searchReq); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}

	p.emitEvent("scim.request", "Search", map[string]interface{}{
		"method": "POST",
		"path":   "/.search",
		"filter": searchReq.Filter,
	})

	// For now, search both Users and Groups
	ctx := r.Context()
	
	startIndex := searchReq.StartIndex
	if startIndex < 1 {
		startIndex = 1
	}
	count := searchReq.Count
	if count < 1 || count > 200 {
		count = 100
	}

	users, userTotal, _ := p.storage.ListUsers(ctx, searchReq.Filter, startIndex, count)
	groups, groupTotal, _ := p.storage.ListGroups(ctx, searchReq.Filter, startIndex, count)

	response := NewListResponse()
	response.TotalResults = userTotal + groupTotal
	response.StartIndex = startIndex
	response.ItemsPerPage = len(users) + len(groups)

	for _, user := range users {
		if user.Meta != nil {
			user.Meta.Location = p.baseURL + "/scim/v2/Users/" + user.ID
		}
		data, _ := json.Marshal(user)
		response.Resources = append(response.Resources, data)
	}

	for _, group := range groups {
		if group.Meta != nil {
			group.Meta.Location = p.baseURL + "/scim/v2/Groups/" + group.ID
		}
		data, _ := json.Marshal(group)
		response.Resources = append(response.Resources, data)
	}

	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(response)
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
			"changePassword": true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// ================== Client Provisioning Handlers ==================

func (p *Plugin) handleClientProvision(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
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

	p.emitEvent("scim.client.request", "Outbound Provision", map[string]interface{}{
		"target":   req.TargetURL,
		"userName": req.User.UserName,
	})

	client := NewClient(req.TargetURL, req.AuthToken)
	created, err := client.CreateUser(r.Context(), req.User)
	if err != nil {
		p.emitEvent("scim.error", "Provision Failed", map[string]interface{}{
			"error": err.Error(),
		})
		WriteError(w, ErrInternalServer(err.Error()))
		return
	}

	p.emitEvent("scim.user.created", "Outbound User Created", map[string]interface{}{
		"localId":   req.User.ID,
		"remoteId":  created.ID,
		"targetUrl": req.TargetURL,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(created)
}

func (p *Plugin) handleClientSync(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
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

	p.emitEvent("scim.client.request", "Sync Started", map[string]interface{}{
		"target": req.TargetURL,
	})

	// TODO: Implement full sync logic
	response := map[string]interface{}{
		"status":  "not_implemented",
		"message": "Full sync is not yet implemented",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
	config := GetAuthConfig()

	// Count recent events to determine if IdP is actively connecting
	events := GetProvisioningEvents(10)
	activeConnection := len(events) > 0

	// Determine IdP from recent events
	detectedIdP := "none"
	if len(events) > 0 {
		detectedIdP = events[0].Source
	}

	status := map[string]interface{}{
		"authEnabled":      config.RequireAuth,
		"activeConnection": activeConnection,
		"detectedIdP":      detectedIdP,
		"scimEndpoint":     p.baseURL + "/scim/v2",
		"supportedFeatures": map[string]bool{
			"patch":      true,
			"bulk":       true,
			"filter":     true,
			"etag":       true,
			"sort":       true,
			"changePassword": true,
		},
		"recentEventsCount": len(events),
		"configuration": map[string]string{
			"usersEndpoint":    p.baseURL + "/scim/v2/Users",
			"groupsEndpoint":   p.baseURL + "/scim/v2/Groups",
			"schemasEndpoint":  p.baseURL + "/scim/v2/Schemas",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ================== Helper Functions ==================

func (p *Plugin) emitEvent(eventType, name string, data map[string]interface{}) {
	if p.lookingGlass != nil {
		// TODO: Integrate with looking glass event system
	}
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

	// Also emit to Looking Glass
	p.emitEvent("scim.provisioning."+action, action+" "+resource, map[string]interface{}{
		"source":     source,
		"resourceId": resourceID,
		"data":       data,
	})
}

