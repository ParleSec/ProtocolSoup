# ProtocolSoup

An interactive sandbox for exploring authentication and identity protocols. Execute **real** protocol flows against a local Mock IdP, inspect HTTP traffic in real-time, decode tokens, and understand security protocols hands-on.

> Real flows against real infrastructure

**Protocols:** OAuth 2.0 • OpenID Connect • SAML 2.0 • SPIFFE/SPIRE • SCIM 2.0 • Shared Signals (SSF)

## Live Website

**[protocolsoup.com](https://protocolsoup.com)**

---

## Quick Start



## Features

| Feature | Description |
|---------|-------------|
| **Looking Glass** | Execute protocol flows and inspect every HTTP request/response in real-time via WebSocket |
| **Token Inspector** | Decode JWTs (access, ID, refresh tokens), examine claims, verify signatures, view SAML assertions |
| **Mock IdP** | Self-contained identity provider with preconfigured test users and clients |
| **Flow Visualizer** | Step-by-step animated protocol flow diagrams |
| **Plugin Architecture** | Add new protocols without modifying core infrastructure |
| **SSF Sandbox** | Interactive Shared Signals Framework testing with real-time event delivery |

---

## Supported Flows

### OAuth 2.0

| Flow | RFC | Description |
|------|-----|-------------|
| Authorization Code | RFC 6749 | Standard web app flow with PKCE support |
| Client Credentials | RFC 6749 | Machine-to-machine authentication |
| Implicit | RFC 6749 | Legacy browser-based flow (not recommended) |
| Device Code | RFC 8628 | Input-constrained device flow |
| Resource Owner Password | RFC 6749 | Direct username/password (legacy) |
| Refresh Token | RFC 6749 | Token renewal flow |
| Token Introspection | RFC 7662 | Active token metadata inspection |
| Token Revocation | RFC 7009 | Token invalidation |

### OpenID Connect

| Flow | Spec | Description |
|------|------|-------------|
| Authorization Code | OIDC Core | OAuth 2.0 + ID token for identity |
| Hybrid Flow | OIDC Core | Immediate ID token + code exchange |
| Discovery | OIDC Discovery | OpenID Provider metadata endpoint |
| UserInfo | OIDC Core | User claims endpoint |

### SAML 2.0

| Flow | Binding | Description |
|------|---------|-------------|
| SP-Initiated SSO | POST / Redirect | Service Provider starts authentication |
| IdP-Initiated SSO | POST | Identity Provider starts authentication |
| Single Logout (SLO) | POST / Redirect | Federated logout |

### SPIFFE/SPIRE

| Flow | Description |
|------|-------------|
| X.509-SVID | Acquire X.509 certificate via Workload API |
| JWT-SVID | Acquire JWT identity token |
| mTLS Configuration | Automatic certificate rotation |
| Trust Bundle | CA certificate distribution |

> SPIFFE flows execute against real SPIRE infrastructure on [protocolsoup.com](https://protocolsoup.com).

### SCIM 2.0

| Flow | RFC | Description |
|------|-----|-------------|
| User Lifecycle | RFC 7643/7644 | Create, read, update, delete users |
| Group Management | RFC 7643/7644 | Group membership provisioning |
| Filter Queries | RFC 7644 | SCIM filter syntax for searches |
| Schema Discovery | RFC 7643 | Resource type and schema introspection |

### Shared Signals Framework (SSF)

| Flow | Spec | Description |
|------|------|-------------|
| Stream Management | OpenID SSF | Create and configure event streams |
| CAEP Events | CAEP | Session revocation, token revocation, credential change |
| RISC Events | RISC | Account compromise, credential compromise indicators |
| SET Delivery | RFC 8935 | Security Event Token push delivery |

---

## Test Credentials

Demo users and client secrets are generated at startup unless provided via environment variables.

Environment overrides:
- `MOCKIDP_ALICE_PASSWORD`
- `MOCKIDP_BOB_PASSWORD`
- `MOCKIDP_ADMIN_PASSWORD`
- `MOCKIDP_DEMO_CLIENT_SECRET`
- `MOCKIDP_MACHINE_CLIENT_SECRET`

You can fetch the current demo credentials from:
- `GET /oauth2/demo/users`
- `GET /oauth2/demo/clients`
- `GET /saml/demo/users`

---

## API Reference

### OAuth 2.0

```
GET  /oauth2/authorize          Authorization endpoint
POST /oauth2/token              Token endpoint
POST /oauth2/introspect         Token introspection
POST /oauth2/revoke             Token revocation
POST /oauth2/device             Device authorization
```

### OpenID Connect

```
GET  /oidc/.well-known/openid-configuration    Discovery document
GET  /oidc/.well-known/jwks.json               JSON Web Key Set
GET  /oidc/authorize                           Authorization endpoint
POST /oidc/token                               Token endpoint
GET  /oidc/userinfo                            UserInfo endpoint
```

### SAML 2.0

```
GET  /saml/metadata             IdP Metadata (XML)
GET  /saml/sso                  SSO Service (Redirect Binding)
POST /saml/sso                  SSO Service (POST Binding)
POST /saml/acs                  Assertion Consumer Service
GET  /saml/slo                  Single Logout (Redirect)
POST /saml/slo                  Single Logout (POST)
```

### SPIFFE/SPIRE

```
GET  /spiffe/status                            Workload API status
GET  /spiffe/svid/x509                         X.509-SVID certificate
GET  /spiffe/svid/x509/chain                   PEM certificate chain
GET  /spiffe/svid/jwt?audience=<aud>           JWT-SVID token
GET  /spiffe/.well-known/spiffe-bundle         SPIFFE bundle endpoint
GET  /spiffe/trust-bundle                      Trust bundle details
GET  /spiffe/workload                          Workload identity info
POST /spiffe/validate/jwt                      Validate JWT-SVID
POST /spiffe/validate/x509                     Validate X.509-SVID
```

### SCIM 2.0

```
GET    /scim/v2/ServiceProviderConfig          Service provider configuration
GET    /scim/v2/ResourceTypes                  Available resource types
GET    /scim/v2/Schemas                        Schema definitions
GET    /scim/v2/Users                          List users (supports filtering)
POST   /scim/v2/Users                          Create user
GET    /scim/v2/Users/{id}                     Get user by ID
PUT    /scim/v2/Users/{id}                     Replace user
PATCH  /scim/v2/Users/{id}                     Partial update user
DELETE /scim/v2/Users/{id}                     Delete user
GET    /scim/v2/Groups                         List groups
POST   /scim/v2/Groups                         Create group
GET    /scim/v2/Groups/{id}                    Get group by ID
PATCH  /scim/v2/Groups/{id}                    Update group membership
DELETE /scim/v2/Groups/{id}                    Delete group
```

### Shared Signals Framework (SSF)

```
GET  /ssf/.well-known/ssf-configuration        Transmitter configuration
POST /ssf/stream                               Create event stream
GET  /ssf/stream/{id}                          Get stream configuration
PUT  /ssf/stream/{id}                          Update stream
DELETE /ssf/stream/{id}                        Delete stream
POST /ssf/stream/{id}/subjects                 Add subject to stream
DELETE /ssf/stream/{id}/subjects/{subject}     Remove subject
POST /ssf/stream/{id}/events                   Emit event to stream
GET  /ssf/stream/{id}/events                   List stream events
POST /ssf/receiver/push                        SET push delivery endpoint
GET  /ssf/receiver/events                      List received events
POST /ssf/receiver/events/{id}/ack             Acknowledge event
```

### Internal API

```
GET  /api/protocols                            List available protocols
POST /api/lookingglass/decode                  Decode tokens
WS   /ws/lookingglass/{session}                Real-time event stream
GET  /health                                   Health check
```

---

## Project Structure

```
ProtocolSoup/
├── backend/
│   ├── cmd/server/main.go         # Application entry point
│   └── internal/
│       ├── core/                   # HTTP server, config, middleware
│       ├── crypto/                 # JWT/JWK key management (RS256, ES256)
│       ├── lookingglass/           # Real-time protocol inspection engine
│       ├── mockidp/                # Mock identity provider (users, clients, sessions)
│       ├── plugin/                 # Plugin system interfaces & lifecycle
│       ├── spiffe/                 # SPIFFE Workload API client, mTLS utilities
│       └── protocols/
│           ├── oauth2/             # OAuth 2.0 implementation
│           ├── oidc/               # OpenID Connect (extends OAuth 2.0)
│           ├── saml/               # SAML 2.0 SSO & SLO
│           ├── scim/               # SCIM 2.0 user/group provisioning
│           ├── spiffe/             # SPIFFE/SPIRE handlers
│           └── ssf/                # Shared Signals Framework
├── frontend/
│   └── src/
│       ├── components/             # Shared UI components
│       │   ├── common/             # Layout, navigation
│       │   └── lookingglass/       # Token inspector, flow diagrams, timeline
│       ├── lookingglass/           # Flow executors & visualization
│       │   └── flows/              # Protocol-specific executors
│       ├── pages/                  # Route pages (Dashboard, LookingGlass, etc.)
│       ├── protocols/              # Protocol registry
│       └── hooks/                  # WebSocket, state management
├── docker/
│   ├── docker-compose.yml          # Split services (base)
│   ├── docker-compose.spiffe.yml   # SPIFFE/SPIRE overlay
│   ├── docker-compose.simple.yml   # Legacy monolith (no SPIFFE)
│   ├── docker-compose.dev.yml      # Legacy development configuration
│   ├── docker-compose.prod.yml     # Legacy production configuration
│   ├── spire/                      # SPIRE server/agent configurations
│   └── Dockerfile.*                # Container definitions
├── docs/
│   ├── ARCHITECTURE.md             # System architecture overview
│   ├── ADDING_PROTOCOLS.md         # Guide for adding new protocols
│   └── SPIFFE.md                   # SPIFFE/SPIRE integration details
├── fly.toml                        # Fly.io deployment (main app)
└── fly.spire-server.toml           # Fly.io deployment (SPIRE server)
```

---

## Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Go | 1.22 | Core language |
| chi | 5.1 | HTTP router |
| golang-jwt | 5.2 | JWT creation/validation |
| gorilla/websocket | 1.5 | Real-time communication |
| go-spiffe | 2.2 | SPIFFE Workload API client |
| modernc/sqlite | 1.29 | Embedded database for SCIM/SSF |

### Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18.3 | UI framework |
| TypeScript | 5.6 | Type safety |
| Vite | 7.3 | Build tool |
| Tailwind CSS | 3.4 | Styling |
| Framer Motion | 11.5 | Animations |
| Zustand | 4.5 | State management |

### Infrastructure

| Technology | Purpose |
|------------|---------|
| Docker | Containerization |
| Nginx | Reverse proxy |
| SPIRE | Workload identity (local) |
| Fly.io | Production hosting |

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md) - System design and data flow
- [Adding Protocols](docs/ADDING_PROTOCOLS.md) - Plugin development guide
- [SPIFFE/SPIRE Integration](docs/SPIFFE.md) - Workload identity setup

---

## Development

### Prerequisites

- Go 1.22+
- Node.js 18+
- Docker & Docker Compose

### Running Locally (without Docker)

**Backend (monolith):**
```bash
cd backend
go run ./cmd/server
```

**Backend (split services):**
```bash
cd backend
go run ./cmd/gateway
go run ./cmd/server-federation
go run ./cmd/server-scim
go run ./cmd/server-ssf
go run ./cmd/server-spiffe
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Environment Variables

#### Core Services

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Server listen address |
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Public base URL |
| `SHOWCASE_CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SHOWCASE_SPIFFE_ENABLED` | `false` | Enable SPIFFE integration |
| `SHOWCASE_SPIFFE_SOCKET_PATH` | `unix:///run/spire/sockets/agent.sock` | Workload API socket |
| `SHOWCASE_SPIFFE_TRUST_DOMAIN` | `protocolsoup.com` | SPIFFE trust domain |

#### Gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `FEDERATION_SERVICE_URL` | (empty) | Federation upstream base URL |
| `SCIM_SERVICE_URL` | (empty) | SCIM upstream base URL |
| `SPIFFE_SERVICE_URL` | (empty) | SPIFFE upstream base URL |
| `SSF_SERVICE_URL` | (empty) | SSF upstream base URL |
| `GATEWAY_REFRESH_INTERVAL` | `30s` | Protocol refresh interval |
| `GATEWAY_STARTUP_RETRY_INITIAL` | `2s` | Initial startup retry delay |
| `GATEWAY_STARTUP_RETRY_MAX` | `30s` | Maximum startup retry delay |
| `GATEWAY_REQUEST_TIMEOUT` | `5s` | Upstream request timeout |

#### SCIM / SSF

| Variable | Default | Description |
|----------|---------|-------------|
| `SCIM_DATA_DIR` | `./data` | SCIM storage directory |
| `SSF_DATA_DIR` | `./data` | SSF storage directory |
| `SCIM_API_TOKEN` | (empty) | Bearer token for SCIM API auth |
| `SCIM_LOOKING_GLASS` | `true` | Enable Looking Glass capture for SCIM |
| `SSF_RECEIVER_PORT` | `8081` | Standalone SSF receiver port |
| `SSF_RECEIVER_TOKEN` | (auto) | Receiver bearer token for push delivery |

---

### Split Services (Base)

```bash
cd ProtocolSoup/docker
docker compose up -d
```

This starts:
- **Gateway** - Aggregates `/api` and routes protocol paths
- **Federation** - OAuth 2.0, OIDC, SAML
- **SCIM** - User and group provisioning
- **SSF** - Shared Signals Framework
- **Frontend** - React UI at `http://localhost:3000`
- **Gateway API** - Available at `http://localhost:8080`

### SPIFFE/SPIRE Overlay

```bash
cd ProtocolSoup/docker
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

This adds:
- **SPIFFE Service** - Workload API demos
- **SPIRE Server/Agent** - Identity authority and SVID issuance
- **SPIRE Registration** - Workload entry bootstrap

### Standalone Usage (API-only Images)

Build any service with the shared backend Dockerfile by selecting the entrypoint:

```bash
# Gateway
docker build -f docker/Dockerfile.backend --build-arg SERVICE_CMD=./cmd/gateway -t protocol-lens-gateway .

# Federation (OAuth2/OIDC/SAML)
docker build -f docker/Dockerfile.backend --build-arg SERVICE_CMD=./cmd/server-federation -t protocol-lens-federation .

# SCIM
docker build -f docker/Dockerfile.backend --build-arg SERVICE_CMD=./cmd/server-scim -t protocol-lens-scim .

# SSF
docker build -f docker/Dockerfile.backend --build-arg SERVICE_CMD=./cmd/server-ssf -t protocol-lens-ssf .

# SPIFFE (requires SPIRE server/agent)
docker build -f docker/Dockerfile.backend-spiffe --build-arg SERVICE_CMD=./cmd/server-spiffe -t protocol-lens-spiffe .
```

Example standalone runs:

```bash
# SCIM service (data volume + optional Looking Glass)
docker run -p 8082:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SCIM_DATA_DIR=/data \
  -e SCIM_LOOKING_GLASS=true \
  -v scim-data:/data \
  protocol-lens-scim

# Gateway routing to standalone services
docker run -p 8080:8080 \
  -e FEDERATION_SERVICE_URL=http://host.docker.internal:8081 \
  -e SCIM_SERVICE_URL=http://host.docker.internal:8082 \
  -e SSF_SERVICE_URL=http://host.docker.internal:8083 \
  protocol-lens-gateway
```

Note: `docker-compose.simple.yml`, `docker-compose.dev.yml`, and `docker-compose.prod.yml`
target the legacy monolithic backend and are kept for reference.

### Using Pre-built GHCR Images

Pre-built container images are available from GitHub Container Registry. Use these for quick deployment without building from source.

**Available images:**

| Image | Description |
|-------|-------------|
| `ghcr.io/parlesec/protocolsoup-gateway` | API Gateway - routes to protocol services |
| `ghcr.io/parlesec/protocolsoup-federation` | Federation service (OAuth 2.0, OIDC, SAML) |
| `ghcr.io/parlesec/protocolsoup-scim` | SCIM 2.0 user/group provisioning |
| `ghcr.io/parlesec/protocolsoup-ssf` | Shared Signals Framework |
| `ghcr.io/parlesec/protocolsoup-spiffe` | SPIFFE workload identity (requires SPIRE) |
| `ghcr.io/parlesec/protocolsoup-frontend` | React frontend UI |
| `ghcr.io/parlesec/protocolsoup-spire-server` | SPIRE Server for workload identity |
| `ghcr.io/parlesec/protocolsoup-spire-agent` | SPIRE Agent for workload attestation |
| `ghcr.io/parlesec/protocolsoup-spire-registration` | SPIRE workload registration |

**Quick start with GHCR images:**

```bash
# Pull and run individual services
docker pull ghcr.io/parlesec/protocolsoup-federation:latest
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  ghcr.io/parlesec/protocolsoup-federation:latest
```

**Using with docker-compose:**

Edit `docker/docker-compose.yml` (and `docker/docker-compose.spiffe.yml` for SPIFFE/SPIRE):
1. Comment out the `build:` section for each service
2. Uncomment the `image: ghcr.io/parlesec/...` line

---

## Security Notes

This is an **educational tool** designed for learning and demonstration. The Mock IdP and test credentials are intentionally simple.


---



## License

See [LICENSE](LICENSE) for details.
