package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

const testIssuer = "https://sandbox.example"

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	idp.SetIssuer(testIssuer)

	p := NewPlugin()
	p.mockIdP = idp
	p.keySet = keySet
	p.baseURL = testIssuer
	p.allowedOrigins = map[string]bool{
		strings.ToLower(testIssuer): true,
		"https://client.example":    true,
	}

	// The catalog tools read the registry, so give the plugin a registry that
	// contains itself: a real plugin with real flow definitions.
	registry := plugin.NewRegistry()
	if err := registry.Register(p); err != nil {
		t.Fatal(err)
	}
	p.SetRegistry(registry)

	return p
}

// router builds the plugin's routes the way the core server mounts them.
func testRouter(t *testing.T, p *Plugin) chi.Router {
	t.Helper()

	router := chi.NewRouter()
	p.RegisterRoutes(router)
	return router
}

// rpc sends a JSON-RPC message with correctly mirrored headers unless an
// override replaces one. An override with an empty value removes the header.
func rpc(t *testing.T, p *Plugin, method string, params map[string]interface{}, overrides map[string]string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()

	if params == nil {
		params = map[string]interface{}{}
	}
	params["_meta"] = map[string]interface{}{
		metaProtocolVersion:    protocolVersion,
		metaClientInfo:         map[string]interface{}{"name": "TestClient", "version": "1.0.0"},
		metaClientCapabilities: map[string]interface{}{},
	}

	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "req-1",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		t.Fatal(err)
	}

	headers := map[string]string{
		"Content-Type":         "application/json",
		"MCP-Protocol-Version": protocolVersion,
		"Mcp-Method":           method,
	}
	if method == "tools/call" {
		if name, ok := params["name"].(string); ok {
			headers["Mcp-Name"] = name
		}
	}
	for key, value := range overrides {
		if value == "" {
			delete(headers, key)
			continue
		}
		headers[key] = value
	}

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(string(body)))
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	document := map[string]interface{}{}
	if response.Body.Len() > 0 {
		if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
			t.Fatalf("response was not JSON: %v (%s)", err, response.Body.String())
		}
	}
	return response, document
}

// post sends a body verbatim, for cases the mirroring helper would not build.
func post(t *testing.T, p *Plugin, body string, headers map[string]string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	document := map[string]interface{}{}
	if response.Body.Len() > 0 {
		if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
			t.Fatalf("response was not JSON: %v (%s)", err, response.Body.String())
		}
	}
	return response, document
}

// errorOf returns the JSON-RPC error object, failing if there is none.
func errorOf(t *testing.T, document map[string]interface{}) map[string]interface{} {
	t.Helper()

	raised, ok := document["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a JSON-RPC error, got %v", document)
	}
	return raised
}

func codeOf(t *testing.T, document map[string]interface{}) int {
	t.Helper()

	code, ok := errorOf(t, document)["code"].(float64)
	if !ok {
		t.Fatalf("error carried no numeric code: %v", document)
	}
	return int(code)
}

// The Streamable HTTP binding requires the mirrored headers to agree with the
// body, because intermediaries route on the headers while the body stays the
// source of truth. Every disagreement is a HeaderMismatch.

func TestProtocolVersionHeaderIsRequired(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/list", nil, map[string]string{"MCP-Protocol-Version": ""})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without the version header, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

func TestProtocolVersionHeaderMustMatchBody(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/list", nil, map[string]string{
		"MCP-Protocol-Version": "2025-11-25",
	})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a version that disagrees with the body, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

func TestUnsupportedVersionListsSupportedVersions(t *testing.T) {
	p := newTestPlugin(t)

	// Header and body agree, so this is a version the server does not speak
	// rather than a mismatch.
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%q:"1900-01-01"}}}`, metaProtocolVersion)
	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(body))
	request.Header.Set("MCP-Protocol-Version", "1900-01-01")
	request.Header.Set("Mcp-Method", "tools/list")

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unsupported version, got %d", response.Code)
	}

	var document map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if code := codeOf(t, document); code != codeUnsupportedProtocolVersion {
		t.Fatalf("expected UnsupportedProtocolVersion (%d), got %d", codeUnsupportedProtocolVersion, code)
	}

	// A client cannot fall forward without being told what to retry with.
	data, ok := errorOf(t, document)["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("the error carried no data object: %v", document)
	}
	supported, ok := data["supported"].([]interface{})
	if !ok || len(supported) == 0 {
		t.Fatalf("the error did not list supported versions: %v", data)
	}
	if supported[0] != protocolVersion {
		t.Fatalf("expected %q in the supported list, got %v", protocolVersion, supported)
	}
}

func TestMethodHeaderMustMatchBody(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/list", nil, map[string]string{"Mcp-Method": "tools/call"})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when Mcp-Method disagrees with the body, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

func TestToolNameHeaderMustMatchBody(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "list_protocols", "arguments": map[string]interface{}{}},
		map[string]string{"Mcp-Name": "decode_jwt"})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when Mcp-Name disagrees with the body, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

func TestToolNameHeaderIsRequiredOnToolCall(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "list_protocols", "arguments": map[string]interface{}{}},
		map[string]string{"Mcp-Name": ""})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without Mcp-Name, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

// A conforming client may send a mirrored value in the Base64 sentinel form.
// A server that compares the raw header against the body would reject it.
func TestBase64SentinelHeaderIsDecodedBeforeComparison(t *testing.T) {
	p := newTestPlugin(t)

	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("list_protocols")) + "?="
	response, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "list_protocols", "arguments": map[string]interface{}{}},
		map[string]string{"Mcp-Name": encoded})

	if response.Code != http.StatusOK {
		t.Fatalf("expected an encoded Mcp-Name to be accepted, got %d (%v)", response.Code, document)
	}
	if _, failed := document["error"]; failed {
		t.Fatalf("expected a result, got %v", document)
	}
}

// A plain header value carrying characters the client was required to encode
// is rejected. Accepting it would admit a value no conforming client could
// have sent unencoded, which is the ambiguity the encoding rule removes.
func TestUnencodedHeaderValueIsRejected(t *testing.T) {
	p := newTestPlugin(t)

	for name, value := range map[string]string{
		"non-ASCII":        "list_protocols\u00e9",
		"control charater": "list\tprotocols",
	} {
		t.Run(name, func(t *testing.T) {
			// Set the header directly: the helper would not build this.
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"_meta":{%q:%q,%q:{}}}}`,
				value, metaProtocolVersion, protocolVersion, metaClientCapabilities)
			request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(body))
			request.Header.Set("MCP-Protocol-Version", protocolVersion)
			request.Header.Set("Mcp-Method", "tools/call")
			request.Header["Mcp-Name"] = []string{value}

			response := httptest.NewRecorder()
			p.handleRPC(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for an unencoded %s, got %d", name, response.Code)
			}
			var document map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if code := codeOf(t, document); code != codeHeaderMismatch {
				t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
			}
		})
	}
}

func TestMalformedSentinelIsRejected(t *testing.T) {
	p := newTestPlugin(t)

	_, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "list_protocols", "arguments": map[string]interface{}{}},
		map[string]string{"Mcp-Name": "=?base64?not-valid-base64!!?="})

	if code := codeOf(t, document); code != codeHeaderMismatch {
		t.Fatalf("expected HeaderMismatch (%d), got %d", codeHeaderMismatch, code)
	}
}

// Batching was removed from the protocol, so an array is a well-formed
// document carrying an invalid request rather than a parse failure.
func TestBatchedBodyIsAnInvalidRequest(t *testing.T) {
	p := newTestPlugin(t)

	body := fmt.Sprintf(`[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{%q:%q}}}]`,
		metaProtocolVersion, protocolVersion)
	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(body))
	request.Header.Set("MCP-Protocol-Version", protocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a batched body, got %d", response.Code)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if code := codeOf(t, document); code != codeInvalidRequest {
		t.Fatalf("expected InvalidRequest (%d), got %d", codeInvalidRequest, code)
	}
}

// Clients must not send JSON-RPC responses. One carries no method, so it is
// rejected as an invalid request rather than dispatched.
func TestClientSentResponseIsRejected(t *testing.T) {
	p := newTestPlugin(t)

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	request.Header.Set("MCP-Protocol-Version", protocolVersion)

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a client-sent response, got %d", response.Code)
	}
}

func TestUnknownMethodIsNotFoundWithJSONRPCError(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "prompts/list", nil, nil)

	// The 404 and the JSON-RPC body together let a client tell an
	// unimplemented method apart from a server that does not host MCP here.
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unimplemented method, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeMethodNotFound {
		t.Fatalf("expected MethodNotFound (%d), got %d", codeMethodNotFound, code)
	}
}

func TestNotificationIsAcceptedWithoutBody(t *testing.T) {
	p := newTestPlugin(t)

	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"_meta":{%q:%q}}}`,
		metaProtocolVersion, protocolVersion)
	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(body))
	request.Header.Set("MCP-Protocol-Version", protocolVersion)
	request.Header.Set("Mcp-Method", "notifications/progress")

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for a notification, got %d", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("expected no body on 202, got %q", response.Body.String())
	}
}

// Revision 2026-07-28 removed the GET stream and the session, so a client from
// an older revision must be turned away rather than left waiting on a stream.
func TestGetAndDeleteAreRejected(t *testing.T) {
	p := newTestPlugin(t)
	router := testRouter(t, p)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		request := httptest.NewRequest(method, "/", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for %s on the MCP endpoint, got %d", method, response.Code)
		}
	}
}

// Only an allowlist actually prevents DNS rebinding, so an origin this
// deployment does not serve is refused even though it is well formed.
func TestOriginIsValidatedAgainstAnAllowlist(t *testing.T) {
	p := newTestPlugin(t)

	refused := map[string]string{
		"unknown origin":  "https://attacker.example",
		"malformed":       "not-an-origin",
		"opaque origin":   "null",
		"wrong scheme":    "file://attacker.example",
		"host mismatch":   "https://sandbox.example.attacker.test",
		"port mismatch":   "https://sandbox.example:8443",
		"scheme mismatch": "http://sandbox.example",
	}

	for name, origin := range refused {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
			request.Header.Set("Origin", origin)

			response := httptest.NewRecorder()
			p.handleRPC(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for %s (%q), got %d", name, origin, response.Code)
			}
		})
	}
}

func TestKnownOriginsAndNonBrowserClientsAreAccepted(t *testing.T) {
	p := newTestPlugin(t)

	// A configured browser origin passes the check.
	for _, origin := range []string{testIssuer, "https://client.example"} {
		request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
		request.Header.Set("Origin", origin)

		response := httptest.NewRecorder()
		p.handleRPC(response, request)

		if response.Code == http.StatusForbidden {
			t.Fatalf("origin %q is served by this deployment but was refused", origin)
		}
	}

	// A client that is not a browser sends no Origin and has nothing to
	// validate; refusing it would lock out every SDK and command-line caller.
	_, document := rpc(t, p, "tools/list", nil, nil)
	if _, failed := document["error"]; failed {
		t.Fatalf("a request without an Origin was refused: %v", document)
	}
}

func TestWildcardCORSDoesNotDisableOriginValidation(t *testing.T) {
	p := NewPlugin()
	p.baseURL = testIssuer
	if err := p.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:     testIssuer,
		CORSOrigins: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}

	if p.allowedOrigins["*"] {
		t.Fatal("a wildcard CORS entry must not become an allowed origin")
	}

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	request.Header.Set("Origin", "https://attacker.example")

	response := httptest.NewRecorder()
	p.handleRPC(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("a wildcard CORS configuration silently disabled the check, got %d", response.Code)
	}
}

// server/discover is mandatory: it is the one request that tells a client what
// the server speaks without probing each list method.

func TestDiscoverReportsVersionsCapabilitiesAndIdentity(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "server/discover", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%v)", response.Code, document)
	}

	result, ok := document["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a result, got %v", document)
	}

	supported, ok := result["supportedVersions"].([]interface{})
	if !ok || len(supported) == 0 || supported[0] != protocolVersion {
		t.Fatalf("expected supportedVersions to name %q, got %v", protocolVersion, result["supportedVersions"])
	}

	capabilities, ok := result["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected capabilities, got %v", result["capabilities"])
	}
	if _, declared := capabilities["tools"]; !declared {
		t.Fatalf("the server serves tools but did not declare the capability: %v", capabilities)
	}

	meta, ok := result["_meta"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected _meta, got %v", result["_meta"])
	}
	info, ok := meta[metaServerInfo].(map[string]interface{})
	if !ok {
		t.Fatalf("expected %s in _meta, got %v", metaServerInfo, meta)
	}
	if info["name"] != serverName || info["version"] != serverVersion {
		t.Fatalf("serverInfo did not match the server's identity: %v", info)
	}
}

func TestToolsListCarriesSchemasAndFreshness(t *testing.T) {
	p := newTestPlugin(t)

	_, document := rpc(t, p, "tools/list", nil, nil)
	result, ok := document["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a result, got %v", document)
	}

	listed, ok := result["tools"].([]interface{})
	if !ok || len(listed) == 0 {
		t.Fatalf("expected tools, got %v", result["tools"])
	}
	if len(listed) != len(tools) {
		t.Fatalf("expected %d tools, got %d", len(tools), len(listed))
	}

	for _, entry := range listed {
		tool, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("a tool was not an object: %v", entry)
		}
		for _, field := range []string{"name", "description", "inputSchema"} {
			if _, present := tool[field]; !present {
				t.Fatalf("tool %v is missing %q", tool["name"], field)
			}
		}
		schema, ok := tool["inputSchema"].(map[string]interface{})
		if !ok || schema["type"] != "object" {
			t.Fatalf("tool %v has no object input schema: %v", tool["name"], tool["inputSchema"])
		}
	}

	// Freshness metadata is what lets a client cache the list instead of
	// re-listing on every connection.
	if _, present := result["ttlMs"]; !present {
		t.Fatal("tools/list did not declare ttlMs")
	}
	if result["cacheScope"] != "public" {
		t.Fatalf("expected a public cacheScope, got %v", result["cacheScope"])
	}
}

// The tools must return live state, not a fixture. list_protocols reads the
// same registry that serves the site's own catalog.
func TestListProtocolsReadsTheLiveRegistry(t *testing.T) {
	p := newTestPlugin(t)

	_, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "list_protocols", "arguments": map[string]interface{}{}}, nil)

	payload := decodeToolPayload(t, document)
	protocols, ok := payload["protocols"].([]interface{})
	if !ok || len(protocols) == 0 {
		t.Fatalf("expected protocols from the registry, got %v", payload)
	}

	first, ok := protocols[0].(map[string]interface{})
	if !ok || first["id"] != p.Info().ID {
		t.Fatalf("expected the registered plugin to be listed, got %v", protocols)
	}
}

func TestListProtocolsFiltersOnQuery(t *testing.T) {
	p := newTestPlugin(t)

	_, document := rpc(t, p, "tools/call", map[string]interface{}{
		"name":      "list_protocols",
		"arguments": map[string]interface{}{"query": "no-protocol-matches-this"},
	}, nil)

	payload := decodeToolPayload(t, document)
	if count, ok := payload["count"].(float64); !ok || count != 0 {
		t.Fatalf("expected the filter to exclude everything, got %v", payload)
	}
}

func TestDescribeProtocolFlowReturnsOrderedSteps(t *testing.T) {
	p := newTestPlugin(t)

	_, document := rpc(t, p, "tools/call", map[string]interface{}{
		"name": "describe_protocol_flow",
		"arguments": map[string]interface{}{
			"protocolId": p.Info().ID,
			"flowId":     "mcp_tool_call",
		},
	}, nil)

	payload := decodeToolPayload(t, document)
	flow, ok := payload["flow"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a flow, got %v", payload)
	}
	steps, ok := flow["steps"].([]interface{})
	if !ok || len(steps) == 0 {
		t.Fatalf("expected steps, got %v", flow["steps"])
	}
}

// A tool that fails reports it in the result so the model can react, rather
// than as a protocol error that a client would treat as a transport fault.
func TestToolFailureIsReportedInTheResult(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/call", map[string]interface{}{
		"name":      "list_protocol_flows",
		"arguments": map[string]interface{}{"protocolId": "no-such-protocol"},
	}, nil)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for a tool-level failure, got %d", response.Code)
	}
	result, ok := document["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a result, got %v", document)
	}
	if isError, _ := result["isError"].(bool); !isError {
		t.Fatalf("expected isError on a failed tool call, got %v", result)
	}
}

func TestUnknownToolIsAParameterError(t *testing.T) {
	p := newTestPlugin(t)

	response, document := rpc(t, p, "tools/call",
		map[string]interface{}{"name": "no_such_tool", "arguments": map[string]interface{}{}}, nil)

	// tools/call exists; the tool does not. That is invalid params, not an
	// unimplemented method.
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown tool, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeInvalidParams {
		t.Fatalf("expected InvalidParams (%d), got %d", codeInvalidParams, code)
	}
}

// Capabilities are declared per request rather than negotiated once for a
// connection, so a request that omits them leaves the server with nothing it
// is permitted to assume. That is a malformed request, not a header problem.
func TestRequiredRequestMetadataIsEnforced(t *testing.T) {
	p := newTestPlugin(t)

	for _, missing := range []struct {
		name string
		meta map[string]interface{}
	}{
		{"clientCapabilities", map[string]interface{}{metaProtocolVersion: protocolVersion}},
		{"protocolVersion", map[string]interface{}{metaClientCapabilities: map[string]interface{}{}}},
	} {
		t.Run(missing.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "tools/list",
				"params": map[string]interface{}{"_meta": missing.meta},
			})
			if err != nil {
				t.Fatal(err)
			}

			response, document := post(t, p, string(body), map[string]string{
				"MCP-Protocol-Version": protocolVersion,
				"Mcp-Method":           "tools/list",
			})

			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 without %s, got %d", missing.name, response.Code)
			}
			if code := codeOf(t, document); code != codeInvalidParams {
				t.Fatalf("expected InvalidParams (%d) for a missing required field, got %d",
					codeInvalidParams, code)
			}
		})
	}
}

// A notification omits its id entirely. An explicit null is neither that nor a
// valid request id, so accepting it as a notification would silently swallow a
// malformed message.
func TestExplicitNullIDIsRejected(t *testing.T) {
	p := newTestPlugin(t)

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":null,"method":"tools/list","params":{"_meta":{%q:%q,%q:{}}}}`,
		metaProtocolVersion, protocolVersion, metaClientCapabilities)

	response, document := post(t, p, body, map[string]string{
		"MCP-Protocol-Version": protocolVersion,
		"Mcp-Method":           "tools/list",
	})

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a null id, got %d", response.Code)
	}
	if code := codeOf(t, document); code != codeInvalidRequest {
		t.Fatalf("expected InvalidRequest (%d), got %d", codeInvalidRequest, code)
	}
}

// This server pages nothing and mints no cursor, so a cursor it is handed is
// one it cannot have issued. An empty string is a valid cursor, so presence
// rather than emptiness is what decides.
func TestAnUnissuedCursorIsRejected(t *testing.T) {
	p := newTestPlugin(t)

	for _, cursor := range []string{"", "eyJwYWdlIjogMn0="} {
		response, document := rpc(t, p, "tools/list",
			map[string]interface{}{"cursor": cursor}, nil)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for cursor %q, got %d", cursor, response.Code)
		}
		if code := codeOf(t, document); code != codeInvalidParams {
			t.Fatalf("expected InvalidParams (%d) for cursor %q, got %d",
				codeInvalidParams, cursor, code)
		}
	}
}

// The tool set is fixed, so a client caching it must see the same order every
// time or its cache is worthless.
func TestToolOrderIsStable(t *testing.T) {
	p := newTestPlugin(t)

	names := func() []string {
		_, document := rpc(t, p, "tools/list", nil, nil)
		result, _ := document["result"].(map[string]interface{})
		listed, _ := result["tools"].([]interface{})

		ordered := make([]string, 0, len(listed))
		for _, entry := range listed {
			tool, _ := entry.(map[string]interface{})
			ordered = append(ordered, fmt.Sprint(tool["name"]))
		}
		return ordered
	}

	first, second := names(), names()
	if len(first) == 0 {
		t.Fatal("expected tools to be listed")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("tool order changed between calls: %v then %v", first, second)
	}
}

// A client that joins mid-conversation should be able to tell what answered
// it from the response alone.
func TestEveryResultIdentifiesTheServer(t *testing.T) {
	p := newTestPlugin(t)

	for _, call := range []struct {
		method string
		params map[string]interface{}
	}{
		{"server/discover", nil},
		{"tools/list", nil},
		{"tools/call", map[string]interface{}{
			"name": "list_protocols", "arguments": map[string]interface{}{},
		}},
	} {
		t.Run(call.method, func(t *testing.T) {
			_, document := rpc(t, p, call.method, call.params, nil)

			result, _ := document["result"].(map[string]interface{})
			meta, ok := result["_meta"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected _meta on the result, got %v", result)
			}
			if _, ok := meta[metaServerInfo].(map[string]interface{}); !ok {
				t.Fatalf("expected %s in _meta, got %v", metaServerInfo, meta)
			}
		})
	}
}

// Caching hints are only carried on complete results, so a client cannot tell
// a final result from one awaiting further input without resultType.
func TestCompleteResultsAreMarked(t *testing.T) {
	p := newTestPlugin(t)

	for _, call := range []struct {
		name   string
		method string
		params map[string]interface{}
	}{
		{"server/discover", "server/discover", nil},
		{"tools/list", "tools/list", nil},
		{"tools/call", "tools/call", map[string]interface{}{
			"name": "list_protocols", "arguments": map[string]interface{}{},
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			_, document := rpc(t, p, call.method, call.params, nil)

			result, ok := document["result"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected a result, got %v", document)
			}
			if result["resultType"] != "complete" {
				t.Fatalf("expected resultType complete, got %v", result["resultType"])
			}
		})
	}
}

// A server validates its tool inputs. An argument the schema does not permit
// comes back as a tool error the model can read and correct, not a protocol
// fault, and never reaches the tool.
func TestArgumentsAreValidatedAgainstTheSchema(t *testing.T) {
	p := newTestPlugin(t)

	for _, argument := range []struct {
		name string
		args map[string]interface{}
	}{
		{"undeclared argument", map[string]interface{}{"protocolId": "oauth", "sql": "DROP TABLE"}},
		{"missing required argument", map[string]interface{}{}},
		{"wrong type", map[string]interface{}{"protocolId": 42}},
	} {
		t.Run(argument.name, func(t *testing.T) {
			response, document := rpc(t, p, "tools/call", map[string]interface{}{
				"name": "list_protocol_flows", "arguments": argument.args,
			}, nil)

			if response.Code != http.StatusOK {
				t.Fatalf("expected 200 for a tool-level failure, got %d", response.Code)
			}
			result, ok := document["result"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected a result, got %v", document)
			}
			if isError, _ := result["isError"].(bool); !isError {
				t.Fatalf("expected isError for %s, got %v", argument.name, result)
			}
		})
	}
}

func TestDecodeJWTReportsSignatureStatus(t *testing.T) {
	p := newTestPlugin(t)

	token, err := p.mockIdP.JWTService().CreateAccessToken("agent-1", "test-client", "openid", 3600000000000, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, document := rpc(t, p, "tools/call", map[string]interface{}{
		"name":      "decode_jwt",
		"arguments": map[string]interface{}{"token": token},
	}, nil)

	payload := decodeToolPayload(t, document)
	signature, ok := payload["signature"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a signature report, got %v", payload)
	}
	if verified, _ := signature["verified"].(bool); !verified {
		t.Fatalf("a token signed by this key set did not verify: %v", signature)
	}

	header, ok := payload["header"].(map[string]interface{})
	if !ok || header["alg"] == nil {
		t.Fatalf("expected a decoded header, got %v", payload["header"])
	}
}

func TestDecodeJWTStillDecodesAnUnverifiableToken(t *testing.T) {
	p := newTestPlugin(t)

	// Decoding must not depend on the signature: an unverifiable token is
	// exactly the one an engineer most needs to read.
	foreign := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudCJ9.bm90LWEtcmVhbC1zaWduYXR1cmU"

	_, document := rpc(t, p, "tools/call", map[string]interface{}{
		"name":      "decode_jwt",
		"arguments": map[string]interface{}{"token": foreign},
	}, nil)

	payload := decodeToolPayload(t, document)
	claims, ok := payload["payload"].(map[string]interface{})
	if !ok || claims["sub"] != "agent" {
		t.Fatalf("expected the claims to be decoded anyway, got %v", payload)
	}
	signature, _ := payload["signature"].(map[string]interface{})
	if verified, _ := signature["verified"].(bool); verified {
		t.Fatalf("a foreign token must not report as verified: %v", signature)
	}
}

// The Server Card is a static document read before the client connects. It
// must be schema-shaped, must not enumerate primitives, and must not
// contradict what the live server reports.

func TestServerCardMatchesTheSchemaShape(t *testing.T) {
	p := newTestPlugin(t)
	router := testRouter(t, p)

	request := httptest.NewRequest(http.MethodGet, "/server-card", nil)
	request.Header.Set("Accept", serverCardMediaType)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 from the reserved card location, got %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != serverCardMediaType {
		t.Fatalf("expected the card media type, got %q", got)
	}

	var card map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &card); err != nil {
		t.Fatal(err)
	}

	if card["$schema"] != serverCardSchema {
		t.Fatalf("the card must pin the v1 schema URL, got %v", card["$schema"])
	}

	name, _ := card["name"].(string)
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$`).MatchString(name) {
		t.Fatalf("the name must be reverse-DNS with exactly one slash, got %q", name)
	}

	description, _ := card["description"].(string)
	if description == "" || len(description) > 100 {
		t.Fatalf("the description must be present and at most 100 characters, got %d", len(description))
	}

	if card["version"] != serverVersion {
		t.Fatalf("expected version %q, got %v", serverVersion, card["version"])
	}
}

func TestServerCardAdvertisesTheRealEndpoint(t *testing.T) {
	p := newTestPlugin(t)

	card := p.buildServerCard()
	if len(card.Remotes) != 1 {
		t.Fatalf("expected one remote, got %d", len(card.Remotes))
	}

	only := card.Remotes[0]
	if only.Type != "streamable-http" {
		t.Fatalf("expected the streamable-http transport, got %q", only.Type)
	}
	if only.URL != testIssuer+"/mcp" {
		t.Fatalf("the card must point at the endpoint this plugin serves, got %q", only.URL)
	}

	// The card's claims must not contradict the live connection.
	if len(only.SupportedProtocolVersions) != 1 || only.SupportedProtocolVersions[0] != protocolVersion {
		t.Fatalf("card versions %v disagree with the server's %q", only.SupportedProtocolVersions, protocolVersion)
	}

	discovered, _ := p.discoverResult()["supportedVersions"].([]string)
	if len(discovered) != len(only.SupportedProtocolVersions) || discovered[0] != only.SupportedProtocolVersions[0] {
		t.Fatalf("the card and server/discover disagree: %v vs %v", only.SupportedProtocolVersions, discovered)
	}
}

// Omitting primitives is a safety property, not an oversight: a document read
// before connecting must never become an access-control input.
func TestServerCardOmitsPrimitives(t *testing.T) {
	p := newTestPlugin(t)

	encoded, err := json.Marshal(p.buildServerCard())
	if err != nil {
		t.Fatal(err)
	}
	var card map[string]interface{}
	if err := json.Unmarshal(encoded, &card); err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range []string{"tools", "resources", "prompts", "capabilities"} {
		if _, present := card[forbidden]; present {
			t.Fatalf("the canonical card must not enumerate %q", forbidden)
		}
	}
}

func TestServerCardIsCacheableAndRevalidates(t *testing.T) {
	p := newTestPlugin(t)
	router := testRouter(t, p)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/server-card", nil))

	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("the card was served without an entity tag")
	}
	if first.Header().Get("Cache-Control") == "" {
		t.Fatal("the card was served without a freshness lifetime")
	}
	if first.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("the card must be reachable by browser-based clients")
	}

	second := httptest.NewRequest(http.MethodGet, "/server-card", nil)
	second.Header.Set("If-None-Match", etag)
	revalidated := httptest.NewRecorder()
	router.ServeHTTP(revalidated, second)

	if revalidated.Code != http.StatusNotModified {
		t.Fatalf("expected 304 when the entity tag still matches, got %d", revalidated.Code)
	}
	if revalidated.Body.Len() != 0 {
		t.Fatalf("a 304 must not carry a body, got %q", revalidated.Body.String())
	}
}

func TestAICatalogPointsAtTheCanonicalCard(t *testing.T) {
	p := newTestPlugin(t)
	router := testRouter(t, p)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/ai-catalog.json", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 from the catalog, got %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != aiCatalogMediaType {
		t.Fatalf("expected the catalog media type, got %q", got)
	}

	var catalog map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog["specVersion"] == nil {
		t.Fatal("the catalog did not declare a specVersion")
	}

	entries, ok := catalog["entries"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("expected one entry, got %v", catalog["entries"])
	}
	entry, _ := entries[0].(map[string]interface{})

	if entry["type"] != serverCardMediaType {
		t.Fatalf("the entry must be typed as a server card, got %v", entry["type"])
	}
	if !strings.HasPrefix(fmt.Sprint(entry["identifier"]), "urn:air:") {
		t.Fatalf("expected a domain-anchored URN, got %v", entry["identifier"])
	}

	// The url must resolve, or discovery dead-ends at the catalog.
	url, _ := entry["url"].(string)
	if url != testIssuer+"/mcp/server-card" {
		t.Fatalf("unexpected card url %q", url)
	}

	resolved := httptest.NewRecorder()
	router.ServeHTTP(resolved, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(url, testIssuer+"/mcp"), nil))
	if resolved.Code != http.StatusOK {
		t.Fatalf("the url the catalog advertises returned %d", resolved.Code)
	}
}

// RFC 8615 requires an application minting a well-known URI to register it.
// No specification defines a well-known location for a server card, and the
// MCP discovery document declines to create one, so this deployment must not
// invent it.
func TestNoUnregisteredWellKnownCardIsServed(t *testing.T) {
	p := newTestPlugin(t)
	router := testRouter(t, p)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/mcp/server-card.json", nil))

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from the unregistered well-known path, got %d", response.Code)
	}
}

// decodeToolPayload reads the JSON a tool returned as its text content.
func decodeToolPayload(t *testing.T, document map[string]interface{}) map[string]interface{} {
	t.Helper()

	result, ok := document["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a result, got %v", document)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("expected content, got %v", result)
	}
	block, ok := content[0].(map[string]interface{})
	if !ok || block["type"] != "text" {
		t.Fatalf("expected a text block, got %v", content[0])
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(fmt.Sprint(block["text"])), &payload); err != nil {
		t.Fatalf("the tool did not return JSON: %v (%v)", err, block["text"])
	}
	return payload
}
