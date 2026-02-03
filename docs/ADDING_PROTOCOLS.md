# Adding Protocols (Contributor Guide)

This is a concrete, end-to-end checklist for adding a new protocol plugin. It includes exact files to touch and a worked example.

## 0. Choose IDs and naming

- Protocol ID: lowercase, URL-safe, no spaces. This becomes the base route `/<id>` and API id.
- Package dir: `backend/internal/protocols/<id>`
- Flow IDs: lowercase, snake_case or kebab-case. The UI normalizes underscores to hyphens.
- Demo scenario IDs: use the same ID as the flow you want to execute.
 - Use the exact backend flow ID in `flowMeta`. The Looking Glass executor uses the hyphen-normalized flow ID.

## 1. Backend package

Create the directory:

```bash
mkdir -p backend/internal/protocols/newprotocol
```

Create `plugin.go` and implement `plugin.ProtocolPlugin`:

```go
package newprotocol

import (
	"context"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

type Plugin struct {
	*plugin.BasePlugin
	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
}

func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "newprotocol",
			Name:        "New Protocol",
			Version:     "1.0.0",
			Description: "Short description",
			Tags:        []string{"tag1", "tag2"},
			RFCs:        []string{"RFC XXXX"},
		}),
	}
}

func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = config.BaseURL

	if idp, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIdP = idp
	}
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}
	return nil
}

func (p *Plugin) Shutdown(ctx context.Context) error { return nil }

func (p *Plugin) RegisterRoutes(router chi.Router) {
	router.Get("/endpoint", p.handleEndpoint)
}

func (p *Plugin) GetInspectors() []plugin.Inspector          { return nil }
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition { return nil }
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario     { return nil }
```

Notes:

- Routes are mounted at `/<protocol_id>`. If your plugin ID is `acme`, the route above becomes `/acme/endpoint`.
- Use real protocol execution and real cryptographic operations. Do not hardcode tokens or protocol artifacts; if you return demo metadata, include real values (timestamps, IDs) from execution.

## 2. Handlers and Looking Glass capture

Implement handlers in `handlers.go`. To emit events, you need the session id:

```go
sessionID := r.Header.Get("X-Looking-Glass-Session")
if sessionID == "" {
	sessionID = r.URL.Query().Get("lg_session")
}
if sessionID != "" && p.lookingGlass != nil {
	b := p.lookingGlass.NewEventBroadcaster(sessionID)
	b.EmitFlowStep(1, "Step Name", "Client", "Server", map[string]interface{}{
		"note": "What happened",
	})
}
```

Important:

- The capture middleware automatically emits HTTP request/response exchanges when the request includes `X-Looking-Glass-Session` or `lg_session`.
- Use `EmitFlowStep` and `EmitTokenIssued` to add semantic context.
- For browser redirects where headers are hard to set, use the `lg_session` query parameter.

## 3. Flow definitions (UI + diagram)

Flow definitions power the protocol pages and the Looking Glass diagram.

```go
plugin.FlowDefinition{
	ID:          "flow_id",
	Name:        "Flow Name",
	Description: "What the flow demonstrates",
	Executable:  true,
	Category:    "authorization",
	Steps: []plugin.FlowStep{
		{
			Order:       1,
			Name:        "Request",
			Description: "Client sends request to server",
			From:        "Client",
			To:          "Authorization Server",
			Type:        "request", // request | response | redirect | internal
			Parameters:  map[string]string{"param": "description"},
			Security:    []string{"RFC XXXX Section Y - security note"},
		},
	},
}
```

Use `Executable: false` for flows that are documentation-only. These still appear on protocol pages but are hidden from the Looking Glass executor list.

## 4. Demo scenarios

Add a demo scenario with the same ID as the flow you want to execute:

```go
plugin.DemoScenario{
	ID:          "flow_id",
	Name:        "Flow Demo",
	Description: "Interactive demonstration",
	Steps: []plugin.DemoStep{
		{Order: 1, Name: "Start", Description: "Initialize", Auto: true},
		{Order: 2, Name: "User Action", Description: "User interaction", Auto: false},
	},
}
```

## 5. Register the plugin

Add the plugin in the correct entrypoint:

- Monolith: `backend/cmd/server/main.go`
- Split services: `backend/cmd/server-federation/main.go`, `server-scim`, `server-ssf`, `server-spiffe`, etc.

If you create a new service, update docker compose and gateway routing as needed.

## 6. Frontend wiring (minimum to appear in UI)

Add the new protocol metadata (inside the object literal):

1) `frontend/src/protocols/registry.ts`:

```ts
export const protocolMeta = {
  // ...
  newprotocol: {
    icon: 'Shield',
    color: 'orange',
    gradient: 'from-orange-500 to-amber-500',
    features: ['Key feature 1', 'Key feature 2', 'Key feature 3'],
  },
}
```

2) `frontend/src/lookingglass/registry.ts`:

```ts
const PROTOCOL_COLORS = {
  // ...
  newprotocol: 'orange',
}

const PROTOCOL_ICONS = {
  // ...
  newprotocol: 'shield',
}
```

3) `frontend/src/pages/ProtocolDemo.tsx`:

```ts
const flowMeta = {
  // ...
  'flow_id': {
    icon: Shield,
    color: 'from-orange-500 to-amber-600',
    features: ['Feature A', 'Feature B'],
    recommended: true,
  },
}
```
Use the exact `flow.id` string from the backend, not the URL slug.

4) `frontend/vite.config.ts` (dev only): add a proxy entry for the protocol base path so executors can call `/${protocolId}` locally.

```ts
server: {
  proxy: {
    // ...
    '/newprotocol': { target: 'http://localhost:8080', changeOrigin: true },
  },
},
```

## 7. Optional: Looking Glass executor (for real execution)

If your flow is executable, implement a flow executor.

- `frontend/src/lookingglass/flows/newprotocol-flow.ts`
- `frontend/src/lookingglass/flows/index.ts` (export it)
- `frontend/src/lookingglass/flows/executor-factory.ts` (map the flow ID)

Looking Glass normalizes flow IDs by replacing underscores with hyphens. Use the hyphenated ID in `FLOW_EXECUTOR_MAP` and add a snake_case alias if needed.

Minimal skeleton:

```ts
export class NewProtocolExecutor extends FlowExecutorBase {
  readonly flowType = 'newprotocol-flow'
  readonly flowName = 'New Protocol Flow'
  readonly rfcReference = 'RFC XXXX'

  async execute(): Promise<void> {
    this.updateState({ status: 'executing', currentStep: 'Starting' })
    await this.makeRequest('GET', `${this.config.baseUrl}/endpoint`, {
      step: 'Call endpoint',
      rfcReference: this.rfcReference,
    })
    this.updateState({ status: 'completed', currentStep: 'Done' })
  }
}
```


## Documentation

Add `backend/internal/protocols/<id>/README.md`:

- Supported flows
- RFC/spec references
- Any config knobs or special behavior

## Acceptance criteria

- Real HTTP requests and real tokens (no placeholders)
- Looking Glass shows request/response + semantic events
- Flow definitions match the spec and contain RFC references
- UI metadata added so the protocol and flows are discoverable

