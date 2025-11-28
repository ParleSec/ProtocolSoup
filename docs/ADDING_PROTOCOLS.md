# Adding New Protocols

This guide walks through adding a new protocol to the Security Protocol Showcase.

## Overview

Each protocol is implemented as a self-contained plugin that integrates with the core framework. The plugin system provides:

- Automatic route registration
- Looking Glass integration
- Common crypto services
- Mock identity provider access

## Step 1: Create the Plugin Directory

```bash
mkdir -p backend/internal/protocols/newprotocol
```

## Step 2: Implement the Plugin Interface

Create `plugin.go`:

```go
package newprotocol

import (
    "context"
    
    "github.com/go-chi/chi/v5"
    "github.com/security-showcase/protocol-showcase/internal/plugin"
)

type Plugin struct {
    *plugin.BasePlugin
    // Add protocol-specific fields
}

func NewPlugin() *Plugin {
    return &Plugin{
        BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
            ID:          "newprotocol",
            Name:        "New Protocol",
            Version:     "1.0.0",
            Description: "Description of the new protocol",
            Tags:        []string{"tag1", "tag2"},
            RFCs:        []string{"RFC XXXX"},
        }),
    }
}

func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
    p.SetConfig(config)
    // Initialize protocol-specific resources
    return nil
}

func (p *Plugin) Shutdown(ctx context.Context) error {
    // Clean up resources
    return nil
}

func (p *Plugin) RegisterRoutes(router chi.Router) {
    // Register HTTP endpoints
    router.Get("/endpoint", p.handleEndpoint)
}

func (p *Plugin) GetInspectors() []plugin.Inspector {
    return []plugin.Inspector{
        {
            ID:          "newprotocol-inspector",
            Name:        "New Protocol Inspector",
            Description: "Inspect protocol artifacts",
            Type:        "token", // or "request", "response", "flow"
        },
    }
}

func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
    return []plugin.FlowDefinition{
        {
            ID:          "main_flow",
            Name:        "Main Protocol Flow",
            Description: "Description of the flow",
            Steps:       []plugin.FlowStep{
                // Define flow steps
            },
        },
    }
}

func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
    return []plugin.DemoScenario{
        {
            ID:          "demo1",
            Name:        "Demo Scenario",
            Description: "Interactive demonstration",
            Steps:       []plugin.DemoStep{
                // Define demo steps
            },
        },
    }
}
```

## Step 3: Implement HTTP Handlers

Create `handlers.go`:

```go
package newprotocol

import (
    "encoding/json"
    "net/http"
)

func (p *Plugin) handleEndpoint(w http.ResponseWriter, r *http.Request) {
    // Implement endpoint logic
    
    // Emit looking glass event
    if p.lookingGlass != nil {
        broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)
        broadcaster.Emit(
            lookingglass.EventTypeFlowStep,
            "Step Name",
            map[string]interface{}{
                "key": "value",
            },
        )
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

## Step 4: Register the Plugin

In `backend/cmd/server/main.go`:

```go
import (
    // ...
    "github.com/security-showcase/protocol-showcase/internal/protocols/newprotocol"
)

func main() {
    // ... existing code ...
    
    // Register new protocol plugin
    newPlugin := newprotocol.NewPlugin()
    if err := registry.Register(newPlugin); err != nil {
        log.Fatalf("Failed to register new protocol: %v", err)
    }
    
    // ... rest of main ...
}
```

## Step 5: Create Frontend Components

Create protocol-specific components:

```
frontend/src/components/protocols/newprotocol/
├── index.ts
├── NewProtocolDemo.tsx
└── NewProtocolInspector.tsx
```

Example component:

```tsx
// NewProtocolDemo.tsx
import { motion } from 'framer-motion'

interface NewProtocolDemoProps {
  flow: string
  onComplete: () => void
}

export function NewProtocolDemo({ flow, onComplete }: NewProtocolDemoProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-4"
    >
      {/* Protocol-specific UI */}
    </motion.div>
  )
}
```

## Step 6: Add to Protocol Demo Page

Update `frontend/src/pages/ProtocolDemo.tsx` to handle the new protocol:

```tsx
// Import new protocol component
import { NewProtocolDemo } from '../components/protocols/newprotocol'

// In the component:
{protocolId === 'newprotocol' && (
  <NewProtocolDemo flow={flowId} onComplete={handleComplete} />
)}
```

## Step 7: Define Flow Steps

Flow steps are visualized in the UI. Define them thoroughly:

```go
Steps: []plugin.FlowStep{
    {
        Order:       1,
        Name:        "Step Name",
        Description: "What happens in this step",
        From:        "Actor A",  // e.g., "Client", "Server"
        To:          "Actor B",
        Type:        "request",  // "request", "response", "internal"
        Parameters: map[string]string{
            "param1": "description",
            "param2": "description",
        },
        Security: []string{
            "Security consideration 1",
            "Security consideration 2",
        },
    },
    // More steps...
}
```

## Step 8: Add Demo Scenarios

Demo scenarios guide users through interactive demonstrations:

```go
Steps: []plugin.DemoStep{
    {
        Order:       1,
        Name:        "Setup",
        Description: "Configure initial state",
        Auto:        true,  // Executes automatically
    },
    {
        Order:       2,
        Name:        "User Action",
        Description: "User performs some action",
        Auto:        false,  // Waits for user
    },
}
```

## Step 9: Looking Glass Integration

Emit events for real-time visibility:

```go
// Get broadcaster for session
broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)

// Emit different event types
broadcaster.EmitFlowStep(1, "Step Name", "Client", "Server", data)
broadcaster.EmitTokenIssued("access_token", claims)
broadcaster.EmitRequest("POST", "/endpoint", headers, body)
broadcaster.EmitResponse(200, headers, body)

// With security annotations
broadcaster.Emit(
    lookingglass.EventTypeSecurityInfo,
    "Security Note",
    data,
    lookingglass.Annotation{
        Type:        lookingglass.AnnotationTypeBestPractice,
        Title:       "Best Practice",
        Description: "Explanation",
        Reference:   "RFC XXXX Section X",
    },
)
```

## Testing

1. **Unit Tests**: Test protocol logic in isolation
2. **Integration Tests**: Test HTTP endpoints
3. **E2E Tests**: Test full flows through the UI

## Example: SAML Plugin Skeleton

```go
package saml

import (
    "context"
    "github.com/go-chi/chi/v5"
    "github.com/security-showcase/protocol-showcase/internal/plugin"
)

type Plugin struct {
    *plugin.BasePlugin
}

func NewPlugin() *Plugin {
    return &Plugin{
        BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
            ID:          "saml",
            Name:        "SAML 2.0",
            Version:     "1.0.0",
            Description: "Security Assertion Markup Language 2.0",
            Tags:        []string{"federation", "xml", "sso"},
            RFCs:        []string{"SAML 2.0 Core", "SAML 2.0 Bindings"},
        }),
    }
}

func (p *Plugin) RegisterRoutes(router chi.Router) {
    router.Get("/metadata", p.handleMetadata)
    router.Get("/sso", p.handleSSOService)
    router.Post("/acs", p.handleAssertionConsumer)
}

// ... implement remaining methods
```

## Best Practices

1. **Follow RFC Specifications**: Implement protocols according to their specifications
2. **Add Security Annotations**: Help users understand security implications
3. **Include Error Handling**: Provide clear error messages
4. **Document Flows**: Thorough flow definitions help visualization
5. **Test Edge Cases**: Handle invalid inputs gracefully
6. **Use Looking Glass Events**: Emit events for all significant actions

