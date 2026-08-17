package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

// toolsListTTLMs is how long a client may cache tools/list. The tool set is
// fixed at build time, so an hour is comfortable; the descriptions of what
// each tool returns change only when a protocol plugin is added.
const toolsListTTLMs = 3600000

// toolContent is one piece of a tool result.
type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// resultTypeComplete marks a result as final rather than an interim one
// awaiting further input. Caching hints are only carried on complete results.
const resultTypeComplete = "complete"

// toolResult is what tools/call returns. A tool that fails reports it with
// isError so the model can see the failure and correct itself, rather than
// raising it as a protocol error the client would treat as a fault.
type toolResult struct {
	ResultType string                 `json:"resultType"`
	Content    []toolContent          `json:"content"`
	IsError    bool                   `json:"isError,omitempty"`
	Meta       map[string]interface{} `json:"_meta,omitempty"`
}

// serverInfoMeta identifies this server, carried on every result.
func serverInfoMeta() map[string]interface{} {
	return map[string]interface{}{
		metaServerInfo: map[string]interface{}{
			"name":    serverName,
			"version": serverVersion,
		},
	}
}

// toolDescriptor is a tool as advertised by tools/list.
type toolDescriptor struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`

	execute func(p *Plugin, args map[string]interface{}) (*toolResult, error)
}

// tools is the server's tool set. Every one reads live state: the protocol
// registry that serves the site's own catalog, or the sandbox key set that
// signs its tokens.
var tools = []toolDescriptor{
	{
		Name:        "list_protocols",
		Title:       "List protocols",
		Description: "List the security protocols this sandbox implements, with the RFCs each one follows. Optionally filter by a term matched against protocol id, name, description, tags, and RFCs.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": `Optional search term, for example "oauth" or "credential".`,
				},
			},
			"additionalProperties": false,
		},
		execute: (*Plugin).listProtocols,
	},
	{
		Name:        "list_protocol_flows",
		Title:       "List protocol flows",
		Description: "List the flows a protocol defines, reporting for each one whether it can be executed interactively and how many steps it has.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"protocolId": map[string]interface{}{
					"type":        "string",
					"description": `Protocol id from list_protocols, for example "oauth2" or "oid4vci".`,
				},
			},
			"required":             []string{"protocolId"},
			"additionalProperties": false,
		},
		execute: (*Plugin).listProtocolFlows,
	},
	{
		Name:        "describe_protocol_flow",
		Title:       "Describe a protocol flow",
		Description: "Return the ordered steps of one flow: who sends what to whom at each step, the parameters carried, and the security considerations that apply.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"protocolId": map[string]interface{}{
					"type":        "string",
					"description": `Protocol id from list_protocols, for example "saml".`,
				},
				"flowId": map[string]interface{}{
					"type":        "string",
					"description": "Flow id from list_protocol_flows.",
				},
			},
			"required":             []string{"protocolId", "flowId"},
			"additionalProperties": false,
		},
		execute: (*Plugin).describeProtocolFlow,
	},
	{
		Name:        "decode_jwt",
		Title:       "Decode a JWT",
		Description: "Decode a JWT into its header and payload and report whether the signature verifies against this sandbox's key set. Decoding never requires a valid signature, so malformed and expired tokens can be inspected too.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "The encoded JWT, in compact serialization.",
				},
			},
			"required":             []string{"token"},
			"additionalProperties": false,
		},
		execute: (*Plugin).decodeJWT,
	},
}

// tool looks up a tool by name.
func (p *Plugin) tool(name string) (toolDescriptor, bool) {
	for _, candidate := range tools {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return toolDescriptor{}, false
}

// listToolsResult builds the tools/list response. The freshness metadata lets
// a client and any intermediary cache the list for a known duration instead of
// re-listing on every connection.
func (p *Plugin) listToolsResult() map[string]interface{} {
	advertised := make([]toolDescriptor, 0, len(tools))
	advertised = append(advertised, tools...)

	return map[string]interface{}{
		"resultType": resultTypeComplete,
		"tools":      advertised,
		"ttlMs":      toolsListTTLMs,
		"cacheScope": "public",
	}
}

// discoverResult answers server/discover: supported versions, capabilities and
// identity in a single request, so a client need not probe each list method.
func (p *Plugin) discoverResult() map[string]interface{} {
	return map[string]interface{}{
		"resultType":        resultTypeComplete,
		"supportedVersions": []string{protocolVersion},
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"instructions": "ProtocolSoup is a sandbox that runs real authentication and identity protocols so their traffic can be inspected. Start with list_protocols to see what is implemented, then list_protocol_flows and describe_protocol_flow to read how a given exchange proceeds step by step. decode_jwt inspects any token, including one you obtained from the sandbox's own OAuth and OIDC endpoints. Every tool is read-only.",
		"ttlMs":        toolsListTTLMs,
		"cacheScope":   "public",
	}
}

// listProtocols reads the live plugin registry.
func (p *Plugin) listProtocols(args map[string]interface{}) (*toolResult, error) {
	if p.registry == nil {
		return nil, fmt.Errorf("the protocol registry is not available")
	}

	query := strings.ToLower(strings.TrimSpace(stringArg(args, "query")))

	type protocolSummary struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tags        []string `json:"tags,omitempty"`
		RFCs        []string `json:"rfcs,omitempty"`
	}

	matches := make([]protocolSummary, 0)
	for _, registered := range p.registry.List() {
		info := registered.Info()
		if query != "" {
			haystack := strings.ToLower(strings.Join(append(
				[]string{info.ID, info.Name, info.Description},
				append(info.Tags, info.RFCs...)...), " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		matches = append(matches, protocolSummary{
			ID:          info.ID,
			Name:        info.Name,
			Description: info.Description,
			Tags:        info.Tags,
			RFCs:        info.RFCs,
		})
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })

	return jsonResult(map[string]interface{}{
		"count":     len(matches),
		"protocols": matches,
	})
}

// listProtocolFlows reads the flow definitions a protocol plugin declares.
func (p *Plugin) listProtocolFlows(args map[string]interface{}) (*toolResult, error) {
	registered, err := p.protocol(stringArg(args, "protocolId"))
	if err != nil {
		return nil, err
	}

	type flowSummary struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Category    string `json:"category,omitempty"`
		Executable  bool   `json:"executable"`
		Steps       int    `json:"steps"`
	}

	flows := make([]flowSummary, 0)
	for _, flow := range registered.GetFlowDefinitions() {
		flows = append(flows, flowSummary{
			ID:          flow.ID,
			Name:        flow.Name,
			Description: flow.Description,
			Category:    flow.Category,
			Executable:  flow.Executable,
			Steps:       len(flow.Steps),
		})
	}

	return jsonResult(map[string]interface{}{
		"protocolId": registered.Info().ID,
		"count":      len(flows),
		"flows":      flows,
	})
}

// describeProtocolFlow returns one flow in full.
func (p *Plugin) describeProtocolFlow(args map[string]interface{}) (*toolResult, error) {
	registered, err := p.protocol(stringArg(args, "protocolId"))
	if err != nil {
		return nil, err
	}

	flowID := strings.TrimSpace(stringArg(args, "flowId"))
	if flowID == "" {
		return nil, fmt.Errorf(`"flowId" is required`)
	}

	definitions := registered.GetFlowDefinitions()
	for _, flow := range definitions {
		if flow.ID != flowID {
			continue
		}
		return jsonResult(map[string]interface{}{
			"protocolId": registered.Info().ID,
			"flow":       flow,
		})
	}

	known := make([]string, 0, len(definitions))
	for _, flow := range definitions {
		known = append(known, flow.ID)
	}
	return nil, fmt.Errorf("protocol %q has no flow %q; it defines %s",
		registered.Info().ID, flowID, strings.Join(known, ", "))
}

// decodeJWT decodes a token and checks it against the sandbox key set.
func (p *Plugin) decodeJWT(args map[string]interface{}) (*toolResult, error) {
	token := strings.TrimSpace(stringArg(args, "token"))
	if token == "" {
		return nil, fmt.Errorf(`"token" is required`)
	}

	decoded, err := crypto.DecodeTokenWithoutValidation(token)
	if err != nil {
		return nil, fmt.Errorf("could not decode the token: %w", err)
	}

	// Signature verification is reported alongside the claims rather than
	// gating them: a token this sandbox did not sign is still worth reading.
	signature := map[string]interface{}{
		"verified": false,
		"detail":   "no key set is available to verify against",
	}
	if p.mockIdP != nil {
		if _, err := p.mockIdP.JWTService().ValidateToken(token); err != nil {
			signature = map[string]interface{}{
				"verified": false,
				"detail":   err.Error(),
			}
		} else {
			signature = map[string]interface{}{
				"verified": true,
				"detail":   "signature and standard claims validate against this sandbox's key set",
			}
		}
	}

	return jsonResult(map[string]interface{}{
		"header":    decoded.Header,
		"payload":   decoded.Payload,
		"signature": signature,
	})
}

// protocol resolves a protocol id against the registry.
func (p *Plugin) protocol(id string) (plugin.ProtocolPlugin, error) {
	if p.registry == nil {
		return nil, fmt.Errorf("the protocol registry is not available")
	}

	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return nil, fmt.Errorf(`"protocolId" is required`)
	}

	registered, ok := p.registry.Get(trimmed)
	if !ok {
		return nil, fmt.Errorf("unknown protocol %q; call list_protocols for the ids this server serves", trimmed)
	}
	return registered, nil
}

// stringArg reads a string argument, tolerating a missing one.
func stringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, _ := args[key].(string)
	return value
}

// jsonResult renders a value as the text content of a tool result.
func jsonResult(value interface{}) (*toolResult, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("could not encode the result: %w", err)
	}
	return &toolResult{
		ResultType: resultTypeComplete,
		Content:    []toolContent{{Type: "text", Text: string(encoded)}},
	}, nil
}

// toolFailure renders a tool error as a result the model can read.
func toolFailure(err error) *toolResult {
	return &toolResult{
		ResultType: resultTypeComplete,
		Content:    []toolContent{{Type: "text", Text: err.Error()}},
		IsError:    true,
	}
}

// validateArguments checks a call's arguments against the tool's declared
// input schema. Validating inputs is required of a server, and reporting a
// failure as a tool error rather than a protocol error lets the model read
// what was wrong and retry with corrected arguments.
func validateArguments(schema map[string]interface{}, args map[string]interface{}) error {
	properties, _ := schema["properties"].(map[string]interface{})

	if additional, declared := schema["additionalProperties"].(bool); declared && !additional {
		for key := range args {
			if _, known := properties[key]; !known {
				return fmt.Errorf("unknown argument %q; this tool accepts %s",
					key, strings.Join(declaredNames(properties), ", "))
			}
		}
	}

	if required, ok := schema["required"].([]string); ok {
		for _, key := range required {
			if _, present := args[key]; !present {
				return fmt.Errorf("%q is required", key)
			}
		}
	}

	for key, value := range args {
		declared, ok := properties[key].(map[string]interface{})
		if !ok {
			continue
		}
		if expected, _ := declared["type"].(string); expected == "string" {
			if _, isString := value.(string); !isString {
				return fmt.Errorf("%q must be a string", key)
			}
		}
	}

	return nil
}

// declaredNames lists a schema's property names in a stable order.
func declaredNames(properties map[string]interface{}) []string {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
