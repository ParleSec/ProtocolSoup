package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/go-chi/chi/v5"
)

// Bulk operations (RFC 7644 Section 3.7). "Each operation corresponds to a
// single HTTP request against a resource endpoint", so each one is sent
// through the same handlers a single request reaches, with the bulk request's
// own Authorization header: an operation gets the checks, the status code and
// the error body it would get on its own.

// The limits ServiceProviderConfig publishes as bulk.maxOperations and
// bulk.maxPayloadSize.
const (
	bulkMaxOperations  = 1000
	bulkMaxPayloadSize = 1048576
)

// bulkReference is a reference to a resource the same request creates: "The
// "bulkId" attribute value must be prepended with the literal "bulkId:"".
var bulkReference = regexp.MustCompile(`bulkId:([^"\\/\s]+)`)

// bulkPath is the path of an operation: a resource type endpoint, or a
// resource of one.
var bulkPath = regexp.MustCompile(`^/(Users|Groups)(/[^/?]+)?$`)

// recorder is the response of one operation.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *recorder) Write(body []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(body)
}

func (p *Plugin) handleBulk(w http.ResponseWriter, r *http.Request) {
	// "If either limit is exceeded, the service provider MUST return HTTP
	// response code 413 (Payload Too Large). The returned response MUST
	// specify the limit exceeded in the body of the error response."
	body, err := io.ReadAll(io.LimitReader(r.Body, bulkMaxPayloadSize+1))
	if err != nil {
		WriteError(w, ErrBadRequest("Failed to read request body"))
		return
	}
	if len(body) > bulkMaxPayloadSize {
		WriteError(w, &SCIMError{Status: http.StatusRequestEntityTooLarge,
			Detail: fmt.Sprintf("The size of the bulk operation exceeds the maxPayloadSize (%d).", bulkMaxPayloadSize)})
		return
	}
	var request BulkRequest
	if err := json.Unmarshal(body, &request); err != nil {
		WriteError(w, ErrInvalidSyntax("Invalid JSON: "+err.Error()))
		return
	}
	// 'Bulk requests are identified using the following schema URI:
	// "urn:ietf:params:scim:api:messages:2.0:BulkRequest".'
	if scimErr := checkSchemas(request.Schemas, SchemaURNBulkRequest); scimErr != nil {
		WriteError(w, scimErr)
		return
	}
	if len(request.Operations) == 0 {
		WriteError(w, ErrInvalidSyntax("Operations is required"))
		return
	}
	if len(request.Operations) > bulkMaxOperations {
		WriteError(w, &SCIMError{Status: http.StatusRequestEntityTooLarge,
			Detail: fmt.Sprintf("The number of operations in the bulk request exceeds maxOperations (%d).", bulkMaxOperations)})
		return
	}

	results := p.runBulk(r, request)
	failed := 0
	for _, result := range results {
		if !strings.HasPrefix(result.Status, "2") {
			failed++
		}
	}
	p.emitEvent(r, lookingglass.EventTypeFlowStep, "SCIM Bulk Request Processed", map[string]interface{}{
		"operations": len(request.Operations), "processed": len(results), "failed": failed, "failOnErrors": request.FailOnErrors,
	}, "RFC 7644 Section 3.7")

	// "If a bulk job is processed successfully, HTTP response code 200 OK
	// MUST be returned". "The service provider response MUST include the
	// result of all processed operations."
	w.Header().Set("Content-Type", ContentTypeSCIM)
	json.NewEncoder(w).Encode(BulkResponse{Schemas: []string{SchemaURNBulkResponse}, Operations: results})
}

// runBulk performs the operations of a bulk request and returns their
// results in the order the client sent them.
func (p *Plugin) runBulk(r *http.Request, request BulkRequest) []BulkOperationResult {
	operations := request.Operations
	results := make([]*BulkOperationResult, len(operations))
	created := map[string]string{} // bulkId -> the id of the resource it created
	defined := map[string]bool{}
	for _, operation := range operations {
		if strings.EqualFold(operation.Method, http.MethodPost) && operation.BulkID != "" {
			defined[operation.BulkID] = true
		}
	}
	errors := 0
	// "failOnErrors": "An integer specifying the number of errors that the
	// service provider will accept before the operation is terminated and an
	// error response is returned."
	stop := func() bool { return request.FailOnErrors > 0 && errors >= request.FailOnErrors }
	finish := func(i int, result BulkOperationResult) {
		results[i] = &result
		if !strings.HasPrefix(result.Status, "2") {
			errors++
		}
	}

	// An operation waits while it refers to a resource another operation of
	// the request has yet to create. Each pass performs the operations whose
	// references are resolved; "The service provider MUST try to resolve
	// circular cross-references between resources in a single bulk job but
	// MAY stop after a failed attempt and instead return HTTP status code 409
	// (Conflict)."
	for progress := true; progress && !stop(); {
		progress = false
		for i, operation := range operations {
			if results[i] != nil || stop() {
				continue
			}
			waiting, unknown := "", ""
			resolve := func(text string) string {
				return bulkReference.ReplaceAllStringFunc(text, func(reference string) string {
					bulkID := strings.TrimPrefix(reference, "bulkId:")
					if id, ok := created[bulkID]; ok {
						// "The service provider MUST replace the string
						// "bulkId:qwerty" with the permanent resource id once
						// created."
						return id
					}
					if defined[bulkID] {
						waiting = bulkID
					} else {
						unknown = bulkID
					}
					return reference
				})
			}
			path, data := resolve(operation.Path), []byte(resolve(string(operation.Data)))
			if unknown != "" {
				finish(i, bulkFailure(operation, p.baseURL, path, ErrInvalidValue(fmt.Sprintf("bulkId:%s refers to no POST operation of this request", unknown))))
				progress = true
				continue
			}
			if waiting != "" {
				continue
			}
			result, id := p.runBulkOperation(r, operation, path, data)
			if id != "" && operation.BulkID != "" {
				created[operation.BulkID] = id
			}
			finish(i, result)
			progress = true
		}
	}
	var processed []BulkOperationResult
	for i, result := range results {
		if result == nil {
			if stop() {
				continue
			}
			failure := bulkFailure(operations[i], p.baseURL, operations[i].Path,
				&SCIMError{Status: http.StatusConflict, Detail: "the operation refers to a bulkId whose resource was not created: a circular reference, or a reference to a failed operation"})
			result = &failure
		}
		processed = append(processed, *result)
	}
	return processed
}

// bulkFailure is the result of an operation that was refused. status: "When
// indicating an error, the "response" attribute MUST contain the detail error
// response as per Section 3.12." location is "REQUIRED in a response, except
// in the event of a POST failure."
func bulkFailure(operation BulkOperation, baseURL, path string, scimErr *SCIMError) BulkOperationResult {
	response, _ := json.Marshal(ErrorResponse{
		Schemas:  []string{SchemaURNError},
		ScimType: scimErr.ScimType,
		Detail:   scimErr.Detail,
		Status:   strconv.Itoa(scimErr.Status),
	})
	result := BulkOperationResult{Method: operation.Method, BulkID: operation.BulkID, Status: strconv.Itoa(scimErr.Status), Response: response}
	if !strings.EqualFold(operation.Method, http.MethodPost) && bulkPath.MatchString(path) {
		result.Location = baseURL + "/scim/v2" + path
	}
	return result
}

// runBulkOperation performs one operation and returns its result and, for a
// POST that succeeded, the id of the resource it created.
func (p *Plugin) runBulkOperation(r *http.Request, operation BulkOperation, path string, data []byte) (BulkOperationResult, string) {
	method := strings.ToUpper(operation.Method)
	match := bulkPath.FindStringSubmatch(path)
	// method: 'Possible values are "POST", "PUT", "PATCH", or "DELETE".' path:
	// 'If "method" is "POST", the value must specify a resource type
	// endpoint, e.g., /Users or /Groups, whereas all other "method" values
	// must specify the path to a specific resource'. bulkId is "REQUIRED when
	// "method" is "POST"", and data 'when "method" is "POST", "PUT", or
	// "PATCH"'.
	var refusal *SCIMError
	switch {
	case method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete:
		refusal = ErrInvalidSyntax(fmt.Sprintf("method %q is not POST, PUT, PATCH or DELETE", operation.Method))
	case match == nil:
		refusal = ErrInvalidSyntax(fmt.Sprintf("path %q is not /Users, /Groups or a resource of one of them", operation.Path))
	case method == http.MethodPost && match[2] != "":
		refusal = ErrInvalidSyntax("the path of a POST operation must be a resource type endpoint")
	case method != http.MethodPost && match[2] == "":
		refusal = ErrInvalidSyntax(fmt.Sprintf("the path of a %s operation must name a resource", method))
	case method == http.MethodPost && operation.BulkID == "":
		refusal = ErrInvalidValue("bulkId is required for a POST operation")
	case method != http.MethodDelete && len(bytes.TrimSpace(data)) == 0:
		refusal = ErrInvalidValue(fmt.Sprintf("data is required for a %s operation", method))
	}
	if refusal != nil {
		return bulkFailure(operation, p.baseURL, path, refusal), ""
	}

	// The operation is routed afresh: without this, the router would reuse
	// the route of the bulk request itself.
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, (*chi.Context)(nil))
	request, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(data))
	if err != nil {
		return bulkFailure(operation, p.baseURL, path, ErrInvalidSyntax(err.Error())), ""
	}
	request.Header.Set("Content-Type", ContentTypeSCIM)
	for _, name := range []string{"Authorization", "X-Looking-Glass-Session", "User-Agent"} {
		if value := r.Header.Get(name); value != "" {
			request.Header.Set(name, value)
		}
	}
	// version: "The current resource version. Version MAY be used if the
	// service provider supports entity-tags (ETags) (Section 2.3 of
	// [RFC7232]) and "method" is "PUT", "PATCH", or "DELETE"."
	if operation.Version != "" && method != http.MethodPost {
		request.Header.Set("If-Match", operation.Version)
	}
	response := &recorder{header: http.Header{}}
	p.resources.ServeHTTP(response, request)
	if response.status == 0 {
		response.status = http.StatusOK
	}

	result := BulkOperationResult{
		Method:  operation.Method,
		BulkID:  operation.BulkID,
		Version: response.header.Get("ETag"),
		Status:  strconv.Itoa(response.status),
	}
	succeeded := response.status >= 200 && response.status < 300
	if !succeeded {
		// response: "When indicating a response with an HTTP status other
		// than a 200-series response, the response body MUST be included."
		result.Response = json.RawMessage(bytes.TrimSpace(response.body.Bytes()))
	}
	id := ""
	if method == http.MethodPost {
		if succeeded {
			result.Location = response.header.Get("Location")
			id = result.Location[strings.LastIndex(result.Location, "/")+1:]
		}
	} else {
		result.Location = p.baseURL + "/scim/v2" + path
	}
	return result, id
}
