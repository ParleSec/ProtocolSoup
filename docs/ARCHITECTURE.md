# Architecture Documentation

## Overview

The Security Protocol Showcase is built as a modular, extensible platform for demonstrating authentication and authorization protocols. The architecture emphasizes separation of concerns, testability, and the ability to add new protocols without modifying core infrastructure.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                        │
├─────────────────────────────────────────────────────────────────┤
│  Dashboard  │  Protocol Demo  │  Looking Glass  │  Callback     │
├─────────────────────────────────────────────────────────────────┤
│  Components: TokenInspector, FlowDiagram, Timeline, RequestView │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP/WebSocket
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Backend (Go)                            │
├─────────────────────────────────────────────────────────────────┤
│                        Core Server                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Config    │  │  Middleware │  │     Router (chi)        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                      Plugin Registry                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  OAuth 2.0 Plugin  │  OIDC Plugin  │  Future Plugins... │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    Shared Services                              │
│  ┌───────────┐  ┌───────────────┐  ┌─────────────────────────┐ │
│  │  Crypto   │  │ Looking Glass │  │       Mock IdP          │ │
│  │ (JWT/JWK) │  │    Engine     │  │ (Users, Clients, Codes) │ │
│  └───────────┘  └───────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### Backend

#### Plugin System

The plugin architecture allows protocols to be added independently while sharing common infrastructure:

```go
type ProtocolPlugin interface {
    // Metadata
    Info() PluginInfo
    
    // Lifecycle
    Initialize(ctx context.Context, config PluginConfig) error
    Shutdown(ctx context.Context) error
    
    // HTTP routing
    RegisterRoutes(router chi.Router)
    
    // Looking Glass integration
    GetInspectors() []Inspector
    GetFlowDefinitions() []FlowDefinition
    
    // Demo capabilities
    GetDemoScenarios() []DemoScenario
}
```

**Benefits:**
- Each protocol is self-contained
- Easy to add/remove protocols
- Shared infrastructure (crypto, IdP)
- Consistent API patterns

#### Looking Glass Engine

Real-time protocol inspection via WebSocket:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Looking Glass Engine                         │
├─────────────────────────────────────────────────────────────────┤
│  Session Manager  │  Event Broadcaster  │  Token Decoder        │
├─────────────────────────────────────────────────────────────────┤
│                    WebSocket Hub                                │
│  - Client connections per session                               │
│  - Event fan-out                                                │
│  - Session lifecycle                                            │
└─────────────────────────────────────────────────────────────────┘
```

**Event Types:**
- `flow.step` - Protocol flow progression
- `token.issued` - New token created
- `request.sent` - HTTP request captured
- `response.received` - HTTP response captured
- `security.warning` - Security annotation
- `crypto.operation` - Cryptographic operation

#### Crypto Package

JWT/JWK utilities with support for multiple algorithms:

```go
type KeySet struct {
    rsaKey   *rsa.PrivateKey  // RS256
    ecKey    *ecdsa.PrivateKey // ES256
    // Key IDs for rotation
}

type JWTService struct {
    keySet *KeySet
    issuer string
}
```

**Capabilities:**
- Key generation (RSA 2048, EC P-256)
- JWT creation/validation
- JWKS endpoint support
- Key rotation

#### Mock Identity Provider

Self-contained IdP for demonstrations:

```go
type MockIdP struct {
    users         map[string]*User
    clients       map[string]*Client
    authCodes     map[string]*AuthorizationCode
    sessions      map[string]*Session
    refreshTokens map[string]*RefreshToken
}
```

**Features:**
- Pre-configured demo users
- Multiple client types (confidential, public, M2M)
- PKCE validation
- Refresh token rotation

### Frontend

#### Component Architecture

```
src/
├── components/
│   ├── common/
│   │   └── Layout.tsx          # Main layout with navigation
│   └── lookingglass/
│       ├── TokenInspector.tsx  # JWT decoding and annotation
│       ├── FlowDiagram.tsx     # Animated protocol flows
│       ├── RequestViewer.tsx   # HTTP request/response display
│       └── Timeline.tsx        # Event timeline
├── pages/
│   ├── Dashboard.tsx           # Landing page with protocol list
│   ├── ProtocolDemo.tsx        # Interactive protocol demos
│   ├── LookingGlass.tsx        # Real-time inspection view
│   └── Callback.tsx            # OAuth callback handler
└── hooks/
    ├── useWebSocket.ts         # WebSocket connection management
    └── useProtocol.ts          # Protocol state management
```

#### State Management

Using React hooks and Zustand for lightweight state:

```typescript
// Protocol state
const useProtocolState = () => {
  const [currentFlow, setCurrentFlow] = useState(null)
  const [tokens, setTokens] = useState({})
  // ...
}

// WebSocket connection
const useWebSocket = (url) => {
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState(null)
  // Auto-reconnect logic
}
```

## Data Flow

### Authentication Flow

```
1. User clicks "Start Demo"
   └─> Frontend creates PKCE challenge
   └─> Stores verifier in sessionStorage

2. Redirect to /oauth2/authorize
   └─> Backend validates request
   └─> Shows login page with demo users

3. User submits credentials
   └─> Backend validates credentials
   └─> Creates authorization code
   └─> Stores PKCE challenge
   └─> Redirects to callback

4. Frontend /callback receives code
   └─> Exchanges code + verifier for tokens
   └─> Backend validates PKCE
   └─> Returns access_token, refresh_token, id_token

5. Frontend displays decoded tokens
   └─> TokenInspector shows claims
   └─> Security annotations displayed
```

### Looking Glass Event Flow

```
1. Start demo session
   └─> POST /api/protocols/{id}/demo/{flow}
   └─> Creates session in Looking Glass engine
   └─> Returns session ID and WebSocket URL

2. Connect WebSocket
   └─> WS /ws/lookingglass/{session}
   └─> Receives historical events
   └─> Subscribes to new events

3. Protocol execution
   └─> Each step emits events
   └─> Events broadcast to all connected clients
   └─> UI updates in real-time
```

## Security Considerations

### Production Recommendations

1. **HTTPS**: Always use TLS in production
2. **Key Management**: Use proper key storage (HSM, KMS)
3. **Token Storage**: Use secure, httpOnly cookies for refresh tokens
4. **CORS**: Restrict to known origins
5. **Rate Limiting**: Implement per-client rate limits

### Demo Security

The showcase uses appropriate security for demonstration purposes:

- Keys generated at startup (rotatable)
- Sessions expire after 24 hours
- Authorization codes expire after 10 minutes
- PKCE required for public clients
- State parameter for CSRF protection

## Extensibility

### Adding a New Protocol

1. Create plugin directory: `internal/protocols/newprotocol/`
2. Implement `ProtocolPlugin` interface
3. Register in `cmd/server/main.go`
4. Add frontend components in `src/components/protocols/newprotocol/`

See [ADDING_PROTOCOLS.md](ADDING_PROTOCOLS.md) for detailed guide.

### Adding New Demo Scenarios

Each plugin can define demo scenarios:

```go
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
    return []plugin.DemoScenario{
        {
            ID:          "new_scenario",
            Name:        "New Demo",
            Description: "Description",
            Steps:       []plugin.DemoStep{...},
        },
    }
}
```

## Performance

### Backend
- Go's efficiency handles concurrent connections well
- WebSocket hub uses goroutines for fan-out
- In-memory storage (sufficient for demo purposes)

### Frontend
- React 18 with concurrent features
- Lazy loading for protocol-specific components
- Framer Motion for smooth animations
- TailwindCSS for minimal CSS bundle

