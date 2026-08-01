// Package mcp implements a remote Model Context Protocol server over the
// Streamable HTTP transport of protocol revision 2026-07-28.
//
// That revision is stateless: the initialize handshake and the Mcp-Session-Id
// header are gone, and every request carries its own protocol version, client
// identity, and capabilities in _meta, mirrored into HTTP headers so
// intermediaries can route without parsing the body. The server exposes
// read-only tools over the protocol catalog this deployment already serves, so
// an agent that is not sitting in a browser tab can reach the same data the
// WebMCP tools expose to one that is.
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2026-07-28"

// Server identity. The name is reverse-DNS with exactly one slash, as the
// Server Card schema requires.
const (
	serverName    = "com.protocolsoup/protocol-sandbox"
	serverVersion = "1.0.0"
)

// JSON-RPC error codes. The first five are standard; the last two are
// allocated by MCP for protocol-defined errors.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	// codeHeaderMismatch is returned when the mirrored HTTP headers disagree
	// with the request body, or a required one is missing.
	codeHeaderMismatch = -32020

	// codeUnsupportedProtocolVersion is returned with the list of versions
	// this server does support.
	codeUnsupportedProtocolVersion = -32022
)

// Reserved _meta keys carrying per-request protocol metadata.
const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// maxRequestBytes bounds a single JSON-RPC message.
const maxRequestBytes = 1 << 20

// Plugin implements the MCP server.
type Plugin struct {
	*plugin.BasePlugin

	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string

	// allowedOrigins are the browser origins permitted to reach the MCP
	// endpoint, keyed in lowercase scheme://host form.
	allowedOrigins map[string]bool

	// registry is the source of truth for the protocol and flow tools. It is
	// injected after construction because the registry is what owns this
	// plugin.
	registry *plugin.Registry
}

// NewPlugin creates the MCP server plugin.
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "mcp",
			Name:        "Model Context Protocol",
			Version:     serverVersion,
			Description: "A remote MCP server over Streamable HTTP. Exposes the protocol catalog, flow definitions, and JWT decoding as tools an autonomous agent can call without a browser.",
			Tags:        []string{"agents", "mcp", "tools", "json-rpc"},
			RFCs:        []string{"MCP " + protocolVersion, "SEP-2127", "JSON-RPC 2.0"},
		}),
	}
}

// SetRegistry supplies the plugin registry the catalog tools read from.
func (p *Plugin) SetRegistry(registry *plugin.Registry) {
	p.registry = registry
}

// Initialize wires the plugin to shared infrastructure.
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = strings.TrimRight(config.BaseURL, "/")

	if idp, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIdP = idp
	}
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	// The transport requires the endpoint to validate Origin against a known
	// set. A wildcard entry is skipped rather than honoured, so a permissive
	// CORS configuration cannot silently turn the check off.
	p.allowedOrigins = map[string]bool{}
	for _, candidate := range append([]string{p.origin()}, config.CORSOrigins...) {
		if normalized := normalizeOrigin(candidate); normalized != "" {
			p.allowedOrigins[normalized] = true
		}
	}

	return nil
}

// normalizeOrigin reduces a configured value to lowercase scheme://host, or
// returns empty if it is not a usable origin.
func normalizeOrigin(candidate string) string {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" || trimmed == "*" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}

	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

// Shutdown shuts down the plugin.
func (p *Plugin) Shutdown(ctx context.Context) error {
	return nil
}

// RegisterRoutes registers the plugin's HTTP routes.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// The single MCP endpoint. Revision 2026-07-28 removed the GET stream, so
	// GET and DELETE are answered with 405 for the benefit of older clients
	// that would otherwise open an SSE stream or try to end a session.
	// Browser preflight is answered by the core CORS middleware, which is
	// configured with this deployment's allowed origins.
	router.Post("/", p.handleRPC)
	router.Get("/", methodNotAllowed)
	router.Delete("/", methodNotAllowed)

	// The Server Card. The discovery spec reserves the /server-card suffix on
	// the server's own Streamable HTTP URL as the recommended location.
	router.Get("/server-card", p.handleServerCard)

	// Site-wide discovery document, mounted at the root by the core router.
	router.Get("/.well-known/ai-catalog.json", p.handleAICatalog)
}

// origin is the deployment's public origin.
func (p *Plugin) origin() string {
	if p.mockIdP != nil {
		if issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/"); issuer != "" {
			return issuer
		}
	}
	return p.baseURL
}

// endpoint is this server's Streamable HTTP URL.
func (p *Plugin) endpoint() string {
	return p.origin() + "/mcp"
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	http.Error(w, "the MCP endpoint accepts POST only", http.StatusMethodNotAllowed)
}

// GetInspectors returns the protocol's inspectors.
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "mcp-server-card",
			Name:        "Server Card Inspector",
			Description: "Read an MCP Server Card and check it against the SEP-2127 schema",
			Type:        "response",
		},
		{
			ID:          "mcp-request-metadata",
			Name:        "Request Metadata Inspector",
			Description: "Compare the Mcp-Method, Mcp-Name and MCP-Protocol-Version headers against the JSON-RPC body they mirror",
			Type:        "request",
		},
	}
}

// GetFlowDefinitions returns the protocol's flow definitions.
//
// The flow is documented but not executable: driving it needs an MCP client
// speaking JSON-RPC, not the browser-based flow executor.
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "mcp_tool_call",
			Name:        "MCP Tool Discovery and Call",
			Description: "An agent discovers this server from the AI Catalog, reads its Server Card, asks what it can do with server/discover, lists tools, and calls one. Revision 2026-07-28 has no handshake: every request stands alone and carries its own protocol version and client identity.",
			Executable:  false,
			Category:    "agents",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Read the AI Catalog",
					Description: "The agent fetches /.well-known/ai-catalog.json and selects entries typed application/mcp-server-card+json. The catalog is the site-wide index; the card itself lives with the server it describes.",
					From:        "Agent",
					To:          "Origin",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/ai-catalog.json",
						"selects":  "entries with type application/mcp-server-card+json",
					},
				},
				{
					Order:       2,
					Name:        "Fetch the Server Card",
					Description: "The agent follows the entry's url to /mcp/server-card, sending Accept: application/mcp-server-card+json. The card gives identity, transport and supported protocol versions, and deliberately does not list tools.",
					From:        "Agent",
					To:          "MCP Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "GET /mcp/server-card",
						"accept":   "application/mcp-server-card+json",
					},
					Security: []string{
						"Card contents are advisory - a client MUST NOT treat them as authoritative for security decisions",
						"Verify the card's claims against the live connection and prefer the runtime values",
					},
				},
				{
					Order:       3,
					Name:        "Call server/discover",
					Description: "One request returns supported protocol versions, capabilities and server identity, so the agent does not have to probe tools/list, prompts/list and resources/list separately.",
					From:        "Agent",
					To:          "MCP Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":  "server/discover",
						"headers": "MCP-Protocol-Version, Mcp-Method",
						"returns": "supportedVersions, capabilities, serverInfo, instructions",
					},
				},
				{
					Order:       4,
					Name:        "List tools",
					Description: "tools/list returns the tool set with input schemas, plus ttlMs and cacheScope so the agent knows how long the list may be cached.",
					From:        "Agent",
					To:          "MCP Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":  "tools/list",
						"returns": "tools[], ttlMs, cacheScope",
					},
				},
				{
					Order:       5,
					Name:        "Call a tool",
					Description: "tools/call names the tool in the body and mirrors it into the Mcp-Name header. The server rejects the request with HeaderMismatch if the two disagree.",
					From:        "Agent",
					To:          "MCP Server",
					Type:        "request",
					Parameters: map[string]string{
						"method":   "tools/call",
						"headers":  "Mcp-Method: tools/call, Mcp-Name: {tool}",
						"mismatch": "400 with JSON-RPC error -32020",
					},
					Security: []string{
						"Headers are mirrors of the body, never a substitute for it - the body remains the source of truth",
						"A server MUST reject a request whose headers contradict its body",
					},
				},
			},
		},
	}
}

// GetDemoScenarios returns the protocol's demo scenarios.
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "mcp_discovery_walkthrough",
			Name:        "Discover and Call This Server",
			Description: "Follow the catalog to the card to a tool call",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Read the AI Catalog", Description: "Find the server card URL", Auto: true},
				{Order: 2, Name: "Fetch the Server Card", Description: "Read identity and transport", Auto: true},
				{Order: 3, Name: "server/discover", Description: "Read capabilities and versions", Auto: true},
				{Order: 4, Name: "tools/list", Description: "Enumerate the tool set", Auto: true},
				{Order: 5, Name: "tools/call", Description: "Run list_protocols", Auto: true},
			},
		},
	}
}

// writeJSON writes a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
