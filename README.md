# Protocol Soup 🍜

A sandbox for exploring authentication and identity protocols. Run real flows against a local MockIdP, inspect HTTP traffic, decode tokens, and understand security protocols hands-on.

**Currently serving:** **OAuth 2.0** • **OpenID Connect** • **SAML 2.0** • **SPIFFE/SPIRE**

## Try it Live

**[protocolsoup.com](https://protocolsoup.com)** - All protocols including real SPIFFE workload identity!

## Run Locally

```bash
cd ProtocolLens/docker
docker compose up -d

# Frontend: http://localhost:3000
# Backend:  http://localhost:8080
```

This starts the full stack including **SPIFFE/SPIRE** workload identity:
- **SPIRE Server** - Certificate authority and identity registry
- **SPIRE Agent** - Workload attestation and SVID issuance
- **Backend** - With embedded agent for real X.509/JWT SVIDs

### Without SPIFFE (lighter, matches production)

```bash
docker compose -f docker-compose.simple.yml up -d
```

## What's Here

- **Looking Glass** - Execute protocol flows and inspect every HTTP request/response in real-time
- **Token Inspector** - Decode JWTs, examine claims, check signatures, view SAML assertions
- **Mock IdP** - Self-contained identity provider with test users
- **Flow Visualizer** - Step-by-step animated protocol flow diagrams

## Test Credentials

| User | Email | Password | Role |
|------|-------|----------|------|
| Alice | alice@example.com | password123 | user |
| Bob | bob@example.com | password123 | user |
| Admin | admin@example.com | admin123 | admin |

## Registered Clients

| client_id | Type | Secret |
|-----------|------|--------|
| public-app | public | - |
| demo-app | confidential | demo-secret |
| machine-client | confidential | machine-secret |

## Endpoints

### OAuth 2.0
```
GET  /oauth2/authorize
POST /oauth2/token
POST /oauth2/introspect
POST /oauth2/revoke
```

### OpenID Connect
```
GET  /oidc/.well-known/openid-configuration
GET  /oidc/.well-known/jwks.json
GET  /oidc/authorize
POST /oidc/token
GET  /oidc/userinfo
```

### SAML 2.0
```
GET  /saml/metadata                    # IdP Metadata
GET  /saml/sso                         # SSO Service (Redirect Binding)
POST /saml/sso                         # SSO Service (POST Binding)
POST /saml/acs                         # Assertion Consumer Service
GET  /saml/slo                         # Single Logout (Redirect)
POST /saml/slo                         # Single Logout (POST)
```

### SPIFFE/SPIRE
```
GET  /spiffe/status                    # Workload API connection status
GET  /spiffe/svid/x509                 # X.509-SVID certificate
GET  /spiffe/svid/jwt                  # JWT-SVID token
GET  /spiffe/trust-bundle              # Trust bundle (CA certificates)
GET  /spiffe/workload                  # Workload identity info
```

### API
```
GET  /api/protocols
POST /api/lookingglass/decode
WS   /ws/lookingglass/{session}
```

## Project Structure

```
ProtocolLens/
├── backend/
│   ├── cmd/server/              # Entry point
│   ├── internal/
│   │   ├── core/                # HTTP server, config, middleware
│   │   ├── crypto/              # JWT/JWK utilities
│   │   ├── lookingglass/        # Protocol inspection engine
│   │   ├── mockidp/             # Mock identity provider
│   │   ├── plugin/              # Plugin interfaces & lifecycle
│   │   └── protocols/           # Protocol implementations
│   │       ├── oauth2/          # OAuth 2.0 flows
│   │       ├── oidc/            # OpenID Connect
│   │       └── saml/            # SAML 2.0 SSO & SLO
│   └── pkg/models/
├── frontend/
│   ├── src/
│   │   ├── components/          # Shared UI components
│   │   ├── lookingglass/        # Flow executors & visualizers
│   │   ├── pages/               # Route pages
│   │   └── protocols/           # Protocol registry
│   └── public/
├── docker/
│   ├── docker-compose.yml       # Main compose file
│   └── Dockerfile.*
└── docs/
    ├── ADDING_PROTOCOLS.md      # Protocol plugin guide
    └── ARCHITECTURE.md          # System architecture
```

## Supported Flows

### OAuth 2.0 / OpenID Connect
- Authorization Code (with PKCE)
- Client Credentials
- Implicit Flow
- Device Code Flow
- Resource Owner Password
- Refresh Token
- OIDC Hybrid Flow

### SAML 2.0
- SP-Initiated SSO (POST & Redirect bindings)
- IdP-Initiated SSO
- Single Logout (SLO)

### SPIFFE/SPIRE
- X.509-SVID acquisition via Workload API
- JWT-SVID acquisition and validation
- mTLS configuration with automatic certificate rotation
- Trust bundle distribution

> SPIFFE flows execute against real SPIRE infrastructure on both local Docker and production (protocolsoup.com).

## Tech Stack

**Backend:** Go 1.22+, chi router, RS256/ES256 JWT, SAML XML, go-spiffe  
**Frontend:** React 18, TypeScript, Vite, Tailwind CSS  
**Infra:** Docker, Nginx, SPIRE (local), Fly.io (production)

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [SPIFFE/SPIRE Integration](docs/SPIFFE.md)

## Built By

**Built by [Mason Parle](https://www.linkedin.com/in/mason-parle/)**

Security engineer passionate about authentication protocols and identity systems. Check out more projects on [GitHub](https://github.com/ParleSec).

## License

MIT © 2024 Mason Parle
