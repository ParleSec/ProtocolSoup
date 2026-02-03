# ACME Example Protocol (Contributor Walkthrough)

This is a minimal, concrete example you can follow end-to-end when adding a new protocol. It creates a single endpoint `GET /acme/ping` and a flow called `acme_ping`.

## Files you will touch

- `backend/internal/protocols/acme/plugin.go`
- `backend/internal/protocols/acme/handlers.go`
- `backend/internal/protocols/acme/README.md`
- `backend/cmd/server/main.go`
- `frontend/src/protocols/registry.ts`
- `frontend/src/lookingglass/registry.ts`
- `frontend/src/pages/ProtocolDemo.tsx`

## 1) Backend plugin

Create `backend/internal/protocols/acme/plugin.go`:

```go
package acme

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
			ID:          "acme",
			Name:        "ACME (Example)",
			Version:     "0.1.0",
			Description: "Dry run protocol used to validate contributor docs",
			Tags:        []string{"example", "dry-run"},
			RFCs:        []string{"N/A (example only)"},
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
	router.Get("/ping", p.handlePing)
}

func (p *Plugin) GetInspectors() []plugin.Inspector          { return []plugin.Inspector{} }
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition { return []plugin.FlowDefinition{
	{
		ID:          "acme_ping",
		Name:        "ACME Ping",
		Description: "Simple request/response handshake",
		Executable:  true,
		Category:    "demo",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Ping",
				Description: "Client calls /acme/ping",
				From:        "Client",
				To:          "ACME Server",
				Type:        "request",
				Security:    []string{"Example flow - not a real ACME operation"},
			},
			{
				Order:       2,
				Name:        "Pong",
				Description: "Server returns a JSON response",
				From:        "ACME Server",
				To:          "Client",
				Type:        "response",
			},
		},
	},
} }
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario     { return []plugin.DemoScenario{
	{
		ID:          "acme_ping",
		Name:        "ACME Ping Demo",
		Description: "Exercise the ping endpoint and capture Looking Glass events",
		Steps: []plugin.DemoStep{
			{Order: 1, Name: "Send Ping", Description: "Call /acme/ping", Auto: true},
			{Order: 2, Name: "Read Response", Description: "Inspect the response payload", Auto: true},
		},
	},
} }
```

## 2) Backend handler

Create `backend/internal/protocols/acme/handlers.go`:

```go
package acme

import (
	"encoding/json"
	"net/http"
	"time"
)

func (p *Plugin) handlePing(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Looking-Glass-Session")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("lg_session")
	}

	if sessionID != "" && p.lookingGlass != nil {
		b := p.lookingGlass.NewEventBroadcaster(sessionID)
		b.EmitFlowStep(1, "Ping", "Client", "ACME Server", map[string]interface{}{
			"path": r.URL.Path,
		})
	}

	response := map[string]string{
		"status":     "ok",
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"request_id": r.Header.Get("X-Request-ID"),
	}

	if sessionID != "" && p.lookingGlass != nil {
		p.lookingGlass.NewEventBroadcaster(sessionID).EmitFlowStep(2, "Pong", "ACME Server", "Client", map[string]interface{}{
			"status": "ok",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
```

## 3) Register the plugin

Add to `backend/cmd/server/main.go`:

```go
import "github.com/ParleSec/ProtocolSoup/internal/protocols/acme"

acmePlugin := acme.NewPlugin()
if err := registry.Register(acmePlugin); err != nil {
	log.Fatalf("Failed to register ACME plugin: %v", err)
}
```

## 4) Frontend wiring

Add protocol metadata:

```ts
export const protocolMeta = {
  // ...
  acme: {
    icon: 'Shield',
    color: 'orange',
    gradient: 'from-orange-500 to-amber-600',
    features: ['Example Request/Response', 'Looking Glass Capture', 'Dry Run Validation'],
  },
}
```

Add Looking Glass registry mappings:

```ts
const PROTOCOL_COLORS = {
  // ...
  acme: 'orange',
}

const PROTOCOL_ICONS = {
  // ...
  acme: 'shield',
}
```

Add flow metadata:

```ts
const flowMeta = {
  // ...
  'acme_ping': {
    icon: Shield,
    color: 'from-orange-500 to-amber-600',
    features: ['Example Request', 'Live Capture', 'Dry Run'],
    recommended: true,
  },
}
```

Add dev proxy entry:

```ts
server: {
  proxy: {
    // ...
    '/acme': { target: 'http://localhost:8080', changeOrigin: true },
  },
},
```

## 5) Looking Glass executor (required for live execution)

Create `frontend/src/lookingglass/flows/acme-ping.ts`:

```ts
import { FlowExecutorBase } from './base'

export class AcmePingExecutor extends FlowExecutorBase {
  readonly flowType = 'acme-ping'
  readonly flowName = 'ACME Ping'
  readonly rfcReference = 'Example only'

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Sending ping',
    })

    try {
      await this.makeRequest('GET', `${this.config.baseUrl}/ping`, {
        step: 'Ping request',
        rfcReference: this.rfcReference,
      })

      this.updateState({
        status: 'completed',
        currentStep: 'Ping complete',
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Ping failed',
        error: {
          code: 'execution_error',
          description: message,
        },
      })
    }
  }
}
```

Export it from `frontend/src/lookingglass/flows/index.ts`:

```ts
export { AcmePingExecutor } from './acme-ping'
```

Map the normalized flow ID in `frontend/src/lookingglass/flows/executor-factory.ts`:

```ts
import { AcmePingExecutor } from './acme-ping'

export const FLOW_EXECUTOR_MAP = {
  // ...
  'acme-ping': {
    executorClass: AcmePingExecutor,
    description: 'Example request/response handshake',
    rfcReference: 'Example only',
    requiresUserInteraction: false,
  },
}
```

Notes:

- Backend flow ID is `acme_ping`, which normalizes to `acme-ping` for the executor map.
- `baseUrl` is built from the protocol id, so this executor calls `/acme/ping`.

## 6) Protocol README

Create `backend/internal/protocols/acme/README.md` with a short summary and the flow list.
