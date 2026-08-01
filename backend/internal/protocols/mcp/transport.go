package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// jsonRPCRequest is a single client-sent message. A message carrying no id is
// a notification and receives 202 Accepted rather than a response.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// callParams are the params of a tools/call request.
type callParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// handleRPC serves the single MCP endpoint.
func (p *Plugin) handleRPC(w http.ResponseWriter, r *http.Request) {
	if !p.originAllowed(r) {
		http.Error(w, "the Origin header names an origin this deployment does not serve", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		p.writeRPCError(w, http.StatusBadRequest, nil, codeParseError, "could not read the request body", nil)
		return
	}
	if len(body) > maxRequestBytes {
		p.writeRPCError(w, http.StatusRequestEntityTooLarge, nil, codeInvalidRequest, "request body is too large", nil)
		return
	}

	// The body must be a single message. JSON-RPC batching was removed from
	// the protocol, so an array is a well-formed document carrying an invalid
	// request rather than a parse failure.
	if firstToken(body) == '[' {
		p.writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest,
			"the body must be a single JSON-RPC message; batching is not part of this protocol revision", nil)
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		p.writeRPCError(w, http.StatusBadRequest, nil, codeParseError, "request body is not valid JSON", nil)
		return
	}
	if req.JSONRPC != "2.0" {
		p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidRequest, `"jsonrpc" must be "2.0"`, nil)
		return
	}
	if req.Method == "" {
		p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidRequest, `"method" is required`, nil)
		return
	}
	if isNullID(req.ID) {
		p.writeRPCError(w, http.StatusBadRequest, nil, codeInvalidRequest,
			`"id" must be a string or a number; a message with no id is a notification and omits the field entirely`, nil)
		return
	}

	meta := metaOf(req.Params)

	if !p.validateRequestMetadata(w, r, &req, meta) {
		return
	}

	// A notification carries no id. The transport requires 202 with no body.
	if isNotification(req.ID) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "server/discover":
		p.writeRPCResult(w, req.ID, p.discoverResult())

	case "tools/list":
		// The whole tool set fits in one page, so this server never issues a
		// cursor. Any cursor presented to it is therefore one it did not
		// mint, and saying so beats silently returning page one again.
		if cursor := cursorOf(req.Params); cursor != nil {
			p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidParams,
				"this server returns the whole tool list in one page and issues no cursor", nil)
			return
		}
		p.writeRPCResult(w, req.ID, p.listToolsResult())

	case "tools/call":
		p.handleToolCall(w, r, &req)

	default:
		// The spec pairs 404 with -32601 so a client can tell an unimplemented
		// method on a modern server apart from a 404 returned by a legacy
		// server that does not host this endpoint at all.
		p.writeRPCError(w, http.StatusNotFound, req.ID, codeMethodNotFound,
			fmt.Sprintf("method %q is not implemented by this server", req.Method), nil)
	}
}

// validateRequestMetadata enforces the transport's header rules and the
// required request metadata: the protocol version must be present in both the
// header and the body and must agree, the version must be one this server
// speaks, Mcp-Method must mirror the method in the body, and a request must
// declare the capabilities the server is allowed to assume of it. It writes
// the error response itself and reports whether the caller should continue.
func (p *Plugin) validateRequestMetadata(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest, meta map[string]interface{}) bool {
	headerVersion := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	bodyVersion, _ := meta[metaProtocolVersion].(string)

	// This server implements only modern revisions, so a request without the
	// header is rejected rather than being read as a pre-2025-06-18 client.
	if headerVersion == "" {
		return p.headerMismatch(w, req.ID, "the MCP-Protocol-Version header is required")
	}
	// An absent field is a malformed request rather than a header mismatch,
	// and the two carry different error codes.
	if bodyVersion == "" {
		return p.missingMetadata(w, req.ID, metaProtocolVersion)
	}
	if headerVersion != bodyVersion {
		return p.headerMismatch(w, req.ID, fmt.Sprintf(
			"Header mismatch: MCP-Protocol-Version header value %q does not match body value %q",
			headerVersion, bodyVersion))
	}
	if headerVersion != protocolVersion {
		p.writeRPCError(w, http.StatusBadRequest, req.ID, codeUnsupportedProtocolVersion,
			"Unsupported protocol version", map[string]interface{}{
				"supported": []string{protocolVersion},
				"requested": headerVersion,
			})
		return false
	}

	declaredMethod, err := decodeHeaderValue(r.Header.Get("Mcp-Method"))
	if err != nil {
		return p.headerMismatch(w, req.ID, "the Mcp-Method header is malformed: "+err.Error())
	}
	if declaredMethod == "" {
		return p.headerMismatch(w, req.ID, "the Mcp-Method header is required")
	}
	if declaredMethod != req.Method {
		return p.headerMismatch(w, req.ID, fmt.Sprintf(
			"Header mismatch: Mcp-Method header value %q does not match body value %q",
			declaredMethod, req.Method))
	}

	// Capabilities are declared per request rather than negotiated once for a
	// connection, so a server may never assume a capability it was not told
	// about. Only requests carry them; a notification expects no reply and so
	// has nothing to negotiate.
	if !isNotification(req.ID) {
		if _, declared := meta[metaClientCapabilities]; !declared {
			return p.missingMetadata(w, req.ID, metaClientCapabilities)
		}
	}

	return true
}

// missingMetadata rejects a request that omits a required _meta field.
func (p *Plugin) missingMetadata(w http.ResponseWriter, id json.RawMessage, key string) bool {
	p.writeRPCError(w, http.StatusBadRequest, id, codeInvalidParams,
		fmt.Sprintf("the request is missing the required _meta field %q", key), nil)
	return false
}

// handleToolCall validates the Mcp-Name mirror and runs the named tool.
func (p *Plugin) handleToolCall(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	var params callParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidParams, "params is not a valid tools/call object", nil)
			return
		}
	}
	if params.Name == "" {
		p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidParams, `"params.name" is required`, nil)
		return
	}

	declaredName, err := decodeHeaderValue(r.Header.Get("Mcp-Name"))
	if err != nil {
		p.headerMismatch(w, req.ID, "the Mcp-Name header is malformed: "+err.Error())
		return
	}
	if declaredName == "" {
		p.headerMismatch(w, req.ID, "the Mcp-Name header is required on tools/call")
		return
	}
	if declaredName != params.Name {
		p.headerMismatch(w, req.ID, fmt.Sprintf(
			"Header mismatch: Mcp-Name header value %q does not match body value %q",
			declaredName, params.Name))
		return
	}

	tool, ok := p.tool(params.Name)
	if !ok {
		// An unknown tool is a parameter problem, not an unimplemented method:
		// tools/call itself exists.
		p.writeRPCError(w, http.StatusBadRequest, req.ID, codeInvalidParams,
			fmt.Sprintf("Unknown tool: %s", params.Name), nil)
		return
	}

	// An argument the schema does not permit is a tool error, not a protocol
	// error, so the model sees what was wrong and can retry.
	if err := validateArguments(tool.InputSchema, params.Arguments); err != nil {
		p.writeRPCResult(w, req.ID, toolFailure(err))
		return
	}

	result, err := tool.execute(p, params.Arguments)
	if err != nil {
		// A tool that fails reports the failure inside the result so the model
		// can see and react to it, rather than as a protocol-level error.
		p.writeRPCResult(w, req.ID, toolFailure(err))
		return
	}

	p.writeRPCResult(w, req.ID, result)
}

// cursorOf reports the pagination cursor a list request carried, if any. An
// empty string is a valid cursor, so presence is what matters and the result
// is nil only when the field was absent.
func cursorOf(params json.RawMessage) *string {
	if len(params) == 0 {
		return nil
	}
	var envelope struct {
		Cursor *string `json:"cursor"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return nil
	}
	return envelope.Cursor
}

// metaOf extracts the _meta object from a params blob.
func metaOf(params json.RawMessage) map[string]interface{} {
	if len(params) == 0 {
		return map[string]interface{}{}
	}
	var envelope struct {
		Meta map[string]interface{} `json:"_meta"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil || envelope.Meta == nil {
		return map[string]interface{}{}
	}
	return envelope.Meta
}

// firstToken returns the first non-whitespace byte of a JSON document, or zero
// if there is none.
func firstToken(body []byte) byte {
	for _, character := range body {
		switch character {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return character
		}
	}
	return 0
}

// isNotification reports whether a message omits its id. An explicit null is
// not an omission: a notification carries no id at all, and a request's id may
// not be null, so null is neither and is rejected rather than silently
// accepted as a message expecting no reply.
func isNotification(id json.RawMessage) bool {
	return strings.TrimSpace(string(id)) == ""
}

// isNullID reports whether a message carried an explicit null id.
func isNullID(id json.RawMessage) bool {
	return strings.TrimSpace(string(id)) == "null"
}

// base64Sentinel wraps a header value whose plain form cannot travel safely in
// an HTTP field value.
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// decodeHeaderValue resolves a mirrored header value to the value it claims to
// mirror.
//
// A server must decode the sentinel form before comparing against the body, or
// a conforming client that encoded its value would be rejected. It must also
// reject a plain value carrying characters the client was required to encode:
// accepting one would let a value that no conforming client could have sent
// unencoded reach the comparison, which is the ambiguity the encoding rule
// exists to remove.
func decodeHeaderValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	if strings.HasPrefix(raw, sentinelPrefix) && strings.HasSuffix(raw, sentinelSuffix) {
		encoded := raw[len(sentinelPrefix) : len(raw)-len(sentinelSuffix)]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("value is not valid base64")
		}
		return string(decoded), nil
	}

	// RFC 9110 limits a field value to visible ASCII, space and tab. The
	// encoding rule narrows what may travel unencoded further still: anything
	// non-ASCII, any control character including tab, and any leading or
	// trailing whitespace has to use the sentinel form.
	if raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("value has leading or trailing whitespace and must use the base64 sentinel form")
	}
	for _, character := range raw {
		if character < 0x20 || character > 0x7E {
			return "", fmt.Errorf("value contains a character that must use the base64 sentinel form")
		}
	}

	return raw, nil
}

// originAllowed validates the Origin header against the deployment's known
// origins.
//
// The check exists to stop DNS rebinding, where a hostile page drives a
// victim's browser at a server the attacker cannot address directly. Only an
// allowlist actually prevents that, so a browser origin this deployment does
// not know is refused. A request without an Origin is not a browser request
// and has nothing to validate; the opaque origin `null`, sent by sandboxed
// documents, cannot be allowlisted and is refused.
func (p *Plugin) originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if origin == "null" {
		return false
	}

	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	return p.allowedOrigins[strings.ToLower(parsed.Scheme+"://"+parsed.Host)]
}

// headerMismatch writes the transport's header validation error. It always
// returns false so callers can `return p.headerMismatch(...)`.
func (p *Plugin) headerMismatch(w http.ResponseWriter, id json.RawMessage, message string) bool {
	p.writeRPCError(w, http.StatusBadRequest, id, codeHeaderMismatch, message, nil)
	return false
}

func (p *Plugin) writeRPCResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	// Every result identifies the server, so a client holding a response has
	// no need of prior connection state to know what answered it.
	switch typed := result.(type) {
	case map[string]interface{}:
		typed["_meta"] = serverInfoMeta()
	case *toolResult:
		typed.Meta = serverInfoMeta()
	}

	writeJSON(w, http.StatusOK, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Result:  result,
	})
}

func (p *Plugin) writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data interface{}) {
	writeJSON(w, status, jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	})
}

// normalizeID echoes the request id, using null when it could not be read.
func normalizeID(id json.RawMessage) json.RawMessage {
	if isNotification(id) {
		return json.RawMessage("null")
	}
	return id
}
