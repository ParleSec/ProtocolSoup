package plugin

import (
	"context"

	"github.com/go-chi/chi/v5"
)

// ProtocolPlugin defines the interface that all protocol plugins must implement
type ProtocolPlugin interface {
	// Info returns metadata about the plugin
	Info() PluginInfo

	// Lifecycle management
	Initialize(ctx context.Context, config PluginConfig) error
	Shutdown(ctx context.Context) error

	// HTTP routing - plugin registers its own routes
	RegisterRoutes(router chi.Router)

	// Looking Glass integration
	GetInspectors() []Inspector
	GetFlowDefinitions() []FlowDefinition

	// Demo capabilities
	GetDemoScenarios() []DemoScenario
}

// PluginInfo contains metadata about a protocol plugin
type PluginInfo struct {
	ID          string   `json:"id"`          // Unique identifier (e.g., "oauth2", "oidc")
	Name        string   `json:"name"`        // Display name (e.g., "OAuth 2.0")
	Version     string   `json:"version"`     // Plugin version
	Description string   `json:"description"` // Brief description
	Tags        []string `json:"tags"`        // Categorization tags
	RFCs        []string `json:"rfcs"`        // Related RFC numbers
}

// PluginConfig provides configuration to plugins during initialization
type PluginConfig struct {
	BaseURL      string      // Base URL of the server
	KeySet       interface{} // Crypto key set
	MockIdP      interface{} // Mock identity provider
	LookingGlass interface{} // Looking glass engine
}

// Inspector defines a protocol-specific inspection capability
type Inspector struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // "token", "request", "response", "flow"
}

// FlowDefinition describes a protocol flow for visualization
type FlowDefinition struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Steps       []FlowStep `json:"steps"`
	Executable  bool       `json:"executable"`            // Whether this flow can be executed in Looking Glass
	Category    string     `json:"category,omitempty"`    // "workload-api", "admin", "infrastructure"
}

// FlowStep represents a single step in a protocol flow
type FlowStep struct {
	Order       int               `json:"order"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	From        string            `json:"from"`  // Actor/component sending
	To          string            `json:"to"`    // Actor/component receiving
	Type        string            `json:"type"`  // "request", "response", "internal"
	Parameters  map[string]string `json:"parameters,omitempty"`
	Security    []string          `json:"security,omitempty"` // Security considerations
}

// DemoScenario defines a runnable demonstration
type DemoScenario struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Steps       []DemoStep        `json:"steps"`
	Config      map[string]string `json:"config,omitempty"`
}

// DemoStep represents a step in a demo scenario
type DemoStep struct {
	Order       int    `json:"order"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Endpoint    string `json:"endpoint,omitempty"`
	Method      string `json:"method,omitempty"`
	Auto        bool   `json:"auto"` // Auto-execute or wait for user
}

// BasePlugin provides common functionality for plugins
type BasePlugin struct {
	info   PluginInfo
	config PluginConfig
}

// NewBasePlugin creates a new base plugin with the given info
func NewBasePlugin(info PluginInfo) *BasePlugin {
	return &BasePlugin{info: info}
}

// Info returns the plugin information
func (p *BasePlugin) Info() PluginInfo {
	return p.info
}

// SetConfig stores the plugin configuration
func (p *BasePlugin) SetConfig(config PluginConfig) {
	p.config = config
}

// Config returns the plugin configuration
func (p *BasePlugin) Config() PluginConfig {
	return p.config
}

