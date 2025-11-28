# 🔐 Security Protocol Showcase

An interactive demonstration of OAuth 2.0, OpenID Connect, and modern authentication protocols. Built as a portfolio project to showcase security engineering expertise.

## ✨ Features

- **Live Protocol Demos**: Interactive OAuth 2.0 and OIDC flows you can run in real-time
- **Looking Glass**: Real-time protocol inspection with decoded tokens and annotated security insights
- **Token Inspector**: Decode and analyze JWTs with claim explanations and security warnings
- **Flow Visualizations**: Animated sequence diagrams showing protocol flows step-by-step
- **PKCE Support**: Full Proof Key for Code Exchange implementation for public clients
- **Mock Identity Provider**: Built-in IdP with demo users for self-contained demonstrations

## 🚀 Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/protocol-showcase.git
cd protocol-showcase

# Start both backend and frontend
docker-compose -f docker/docker-compose.yml up --build

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8080
```

### Manual Setup

#### Backend (Go)

```bash
cd backend

# Install dependencies
go mod download

# Run the server
go run ./cmd/server

# Server runs on http://localhost:8080
```

#### Frontend (React)

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Frontend runs on http://localhost:3000
```

## 📁 Project Structure

```
protocol-showcase/
├── backend/
│   ├── cmd/server/          # Application entry point
│   ├── internal/
│   │   ├── core/            # HTTP server, config, middleware
│   │   ├── crypto/          # JWT/JWK cryptographic utilities
│   │   ├── lookingglass/    # Protocol inspection engine
│   │   ├── mockidp/         # Mock identity provider
│   │   ├── plugin/          # Plugin architecture
│   │   └── protocols/       # Protocol implementations
│   │       ├── oauth2/      # OAuth 2.0 plugin
│   │       └── oidc/        # OpenID Connect plugin
│   └── pkg/models/          # Shared data models
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   │   ├── common/      # Layout, navigation
│   │   │   └── lookingglass/# Token inspector, flow diagrams
│   │   ├── pages/           # Route pages
│   │   ├── hooks/           # Custom React hooks
│   │   └── utils/           # Helper utilities
│   └── public/              # Static assets
├── docker/
│   ├── docker-compose.yml   # Production compose
│   ├── Dockerfile.backend   # Backend build
│   └── Dockerfile.frontend  # Frontend build
└── docs/
    ├── ARCHITECTURE.md      # Architecture documentation
    └── ADDING_PROTOCOLS.md  # Guide for adding protocols
```

## 🔑 Demo Credentials

The mock identity provider includes these demo users:

| User | Email | Password | Role |
|------|-------|----------|------|
| Alice | alice@example.com | password123 | Standard User |
| Bob | bob@example.com | password123 | Standard User |
| Admin | admin@example.com | admin123 | Administrator |

Demo OAuth Clients:

| Client ID | Type | Secret |
|-----------|------|--------|
| demo-app | Confidential | demo-secret |
| public-app | Public (PKCE) | - |
| machine-client | M2M | machine-secret |

## 🔄 Available Protocol Flows

### OAuth 2.0
- Authorization Code Flow (with and without PKCE)
- Client Credentials Flow
- Refresh Token Flow
- Token Introspection
- Token Revocation

### OpenID Connect
- Authorization Code Flow
- ID Token validation
- UserInfo endpoint
- Discovery document
- JWKS endpoint

## 🛠 API Endpoints

### Core API
- `GET /health` - Health check
- `GET /api/protocols` - List available protocols
- `GET /api/protocols/{id}` - Protocol details
- `GET /api/protocols/{id}/flows` - Available flows
- `POST /api/protocols/{id}/demo/{flow}` - Start demo session

### Looking Glass
- `POST /api/lookingglass/decode` - Decode JWT token
- `GET /api/lookingglass/sessions` - Active sessions
- `WS /ws/lookingglass/{session}` - Real-time event stream

### OAuth 2.0 (`/oauth2`)
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `POST /introspect` - Token introspection
- `POST /revoke` - Token revocation

### OIDC (`/oidc`)
- `GET /.well-known/openid-configuration` - Discovery
- `GET /.well-known/jwks.json` - JWKS
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `GET /userinfo` - UserInfo endpoint

## 🏗 Architecture Highlights

- **Plugin Architecture**: Each protocol is a self-contained plugin
- **Looking Glass Engine**: Real-time WebSocket event streaming
- **Security Annotations**: RFC references and security best practices
- **Production Patterns**: Rate limiting, CORS, security headers

## 📚 Learn More

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Adding New Protocols](docs/ADDING_PROTOCOLS.md)

## 🎯 Use Cases

1. **Interview Demonstrations**: Pull up the app and walk through OAuth flows live
2. **Learning Tool**: Understand protocol mechanics with visual explanations
3. **Development Reference**: Example implementations of security protocols
4. **Testing Client**: Use the mock IdP to test your OAuth/OIDC clients

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with ❤️ to demonstrate security engineering expertise.

