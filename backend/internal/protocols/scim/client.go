package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a SCIM 2.0 client for outbound provisioning
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new SCIM client
func NewClient(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetBaseURL sets the target SCIM server URL
func (c *Client) SetBaseURL(baseURL string) {
	c.baseURL = baseURL
}

// SetAuthToken sets the authentication token
func (c *Client) SetAuthToken(token string) {
	c.authToken = token
}

// ================== Service Provider Discovery ==================

// GetServiceProviderConfig retrieves the target server's configuration
func (c *Client) GetServiceProviderConfig(ctx context.Context) (*ServiceProviderConfig, error) {
	resp, err := c.doRequest(ctx, "GET", "/ServiceProviderConfig", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var config ServiceProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &config, nil
}

// GetResourceTypes retrieves the supported resource types
func (c *Client) GetResourceTypes(ctx context.Context) ([]*ResourceType, error) {
	resp, err := c.doRequest(ctx, "GET", "/ResourceTypes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var listResp ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var resourceTypes []*ResourceType
	for _, raw := range listResp.Resources {
		var rt ResourceType
		if err := json.Unmarshal(raw, &rt); err == nil {
			resourceTypes = append(resourceTypes, &rt)
		}
	}

	return resourceTypes, nil
}

// ================== User Operations ==================

// CreateUser creates a new user on the remote server
func (c *Client) CreateUser(ctx context.Context, user *User) (*User, error) {
	resp, err := c.doRequest(ctx, "POST", "/Users", user)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var created User
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &created, nil
}

// GetUser retrieves a user by ID
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	resp, err := c.doRequest(ctx, "GET", "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &user, nil
}

// UpdateUser replaces a user (PUT)
func (c *Client) UpdateUser(ctx context.Context, id string, user *User) (*User, error) {
	resp, err := c.doRequest(ctx, "PUT", "/Users/"+url.PathEscape(id), user)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var updated User
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updated, nil
}

// PatchUser modifies a user (PATCH)
func (c *Client) PatchUser(ctx context.Context, id string, operations []PatchOperation) (*User, error) {
	patchReq := PatchRequest{
		Schemas:    []string{SchemaURNPatchOp},
		Operations: operations,
	}

	resp, err := c.doRequest(ctx, "PATCH", "/Users/"+url.PathEscape(id), patchReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var updated User
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updated, nil
}

// DeleteUser deletes a user
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}

	return nil
}

// ListUsers retrieves users with optional filter
func (c *Client) ListUsers(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error) {
	path := "/Users"
	query := url.Values{}
	if filter != "" {
		query.Set("filter", filter)
	}
	if startIndex > 0 {
		query.Set("startIndex", fmt.Sprintf("%d", startIndex))
	}
	if count > 0 {
		query.Set("count", fmt.Sprintf("%d", count))
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var listResp ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// ================== Group Operations ==================

// CreateGroup creates a new group
func (c *Client) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	resp, err := c.doRequest(ctx, "POST", "/Groups", group)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var created Group
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &created, nil
}

// GetGroup retrieves a group by ID
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	resp, err := c.doRequest(ctx, "GET", "/Groups/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var group Group
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &group, nil
}

// UpdateGroup replaces a group (PUT)
func (c *Client) UpdateGroup(ctx context.Context, id string, group *Group) (*Group, error) {
	resp, err := c.doRequest(ctx, "PUT", "/Groups/"+url.PathEscape(id), group)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var updated Group
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updated, nil
}

// PatchGroup modifies a group (PATCH)
func (c *Client) PatchGroup(ctx context.Context, id string, operations []PatchOperation) (*Group, error) {
	patchReq := PatchRequest{
		Schemas:    []string{SchemaURNPatchOp},
		Operations: operations,
	}

	resp, err := c.doRequest(ctx, "PATCH", "/Groups/"+url.PathEscape(id), patchReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var updated Group
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updated, nil
}

// DeleteGroup deletes a group
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/Groups/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}

	return nil
}

// ListGroups retrieves groups with optional filter
func (c *Client) ListGroups(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error) {
	path := "/Groups"
	query := url.Values{}
	if filter != "" {
		query.Set("filter", filter)
	}
	if startIndex > 0 {
		query.Set("startIndex", fmt.Sprintf("%d", startIndex))
	}
	if count > 0 {
		query.Set("count", fmt.Sprintf("%d", count))
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var listResp ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// ================== Bulk Operations ==================

// Bulk executes multiple operations in a single request
func (c *Client) Bulk(ctx context.Context, request *BulkRequest) (*BulkResponse, error) {
	resp, err := c.doRequest(ctx, "POST", "/Bulk", request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var bulkResp BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &bulkResp, nil
}

// ================== Helper Methods ==================

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	fullURL := c.baseURL + "/scim/v2" + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeSCIM)
	req.Header.Set("Accept", ContentTypeSCIM)
	
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	return c.httpClient.Do(req)
}

func (c *Client) parseError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Detail != "" {
		return &SCIMError{
			Status:   resp.StatusCode,
			ScimType: errResp.ScimType,
			Detail:   errResp.Detail,
		}
	}

	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}

// ================== Sync Operations ==================

// SyncResult contains the result of a sync operation
type SyncResult struct {
	Created  int                 `json:"created"`
	Updated  int                 `json:"updated"`
	Deleted  int                 `json:"deleted"`
	Errors   int                 `json:"errors"`
	Mappings map[string]string   `json:"mappings"` // local ID -> remote ID
	Details  []SyncOperationDetail `json:"details,omitempty"`
}

// SyncOperationDetail contains details about a sync operation
type SyncOperationDetail struct {
	LocalID   string `json:"localId"`
	RemoteID  string `json:"remoteId,omitempty"`
	Operation string `json:"operation"` // create, update, delete
	Status    string `json:"status"`    // success, error
	Error     string `json:"error,omitempty"`
}

// SyncUsers synchronizes local users to the remote server
func (c *Client) SyncUsers(ctx context.Context, localUsers []*User, existingMappings map[string]string) (*SyncResult, error) {
	result := &SyncResult{
		Mappings: make(map[string]string),
		Details:  make([]SyncOperationDetail, 0),
	}

	// Copy existing mappings
	for k, v := range existingMappings {
		result.Mappings[k] = v
	}

	for _, user := range localUsers {
		detail := SyncOperationDetail{
			LocalID: user.ID,
		}

		// Check if user already synced
		if remoteID, exists := existingMappings[user.ID]; exists {
			// Update existing user
			detail.Operation = "update"
			detail.RemoteID = remoteID
			
			updated, err := c.UpdateUser(ctx, remoteID, user)
			if err != nil {
				detail.Status = "error"
				detail.Error = err.Error()
				result.Errors++
			} else {
				detail.Status = "success"
				detail.RemoteID = updated.ID
				result.Updated++
			}
		} else {
			// Create new user
			detail.Operation = "create"
			
			created, err := c.CreateUser(ctx, user)
			if err != nil {
				detail.Status = "error"
				detail.Error = err.Error()
				result.Errors++
			} else {
				detail.Status = "success"
				detail.RemoteID = created.ID
				result.Mappings[user.ID] = created.ID
				result.Created++
			}
		}

		result.Details = append(result.Details, detail)
	}

	return result, nil
}




