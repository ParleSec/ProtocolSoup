# SPIFFE/SPIRE Protocol Implementation

A production-ready implementation of the [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) specification with real [SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment) infrastructure integration.

## Overview

This implementation provides:

- **Real SPIFFE Integration**: Live connection to SPIRE Agent Workload API
- **X.509-SVID Issuance**: Automatic certificate acquisition and rotation
- **JWT-SVID Issuance**: Token-based identity for API authentication
- **mTLS Support**: Mutual TLS configuration with X.509 certificates
- **Trust Bundle Management**: CA certificate distribution and validation
- **Educational Visualization**: Step-by-step flow demonstrations in Looking Glass
- **Demo Mode Fallback**: Full functionality when SPIRE infrastructure is unavailable

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SPIFFE Trust Domain                                 │
│                    spiffe://protocolsoup.com                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────┐                                                │
│  │      SPIRE Server       │  protocolsoup-spire.fly.dev                    │
│  │   (Fly.io Machine)      │                                                │
│  │                         │  • Issues X.509 and JWT SVIDs                  │
│  │   Trust Root / CA       │  • Manages registration entries                │
│  │   Port: 8081            │  • Maintains trust bundles                     │
│  │                         │  • CA TTL: 90 days                             │
│  └───────────┬─────────────┘  • SVID TTL: 24 hours                          │
│              │                                                              │
│              │ Node Attestation (join_token)                                │
│              │ Private Network: *.internal                                  │
│              ▼                                                              │
│  ┌─────────────────────────┐                                                │
│  │      SPIRE Agent        │  Embedded in protocolsoup app                  │
│  │   (Workload API)        │                                                │
│  │                         │  • Unix socket: /run/spire/sockets/agent.sock  │
│  │   Socket: agent.sock    │  • Workload attestation (unix:uid)             │
│  │   Data: /data/spire     │  • SVID caching and rotation                   │
│  └───────────┬─────────────┘  • Trust bundle distribution                   │
│              │                                                              │
│              │ Workload API (gRPC over UDS)                                 │
│              ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Backend Application                             │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │ WorkloadClient    │  │ SPIFFE Plugin     │  │ HTTP Handlers   │  │    │
│  │  │ (go-spiffe SDK)   │  │ (Protocol Impl)   │  │ (API Endpoints) │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • X509Source      │  │ • Flow Definitions│  │ • /spiffe/svid  │  │    │
│  │  │ • JWTSource       │  │ • Demo Scenarios  │  │ • /spiffe/trust │  │    │
│  │  │ • BundleSource    │  │ • Inspectors      │  │ • /spiffe/demo  │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  SPIFFE ID: spiffe://protocolsoup.com/workload/backend              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## TTL Configuration & Maintenance

The SPIFFE/SPIRE deployment uses these TTLs for stability:

| Component | TTL | Purpose |
|-----------|-----|---------|
| **CA Certificate** | 90 days | Root of trust - agents must reconnect within this window |
| **X.509-SVID** | 24 hours | Workload certificates - auto-renewed while connected |
| **JWT-SVID** | 1 hour | Short-lived tokens for API authentication |
| **Join Token** | 24 hours | Initial node attestation - single use |

### Maintenance Requirements

The system requires **at least one active connection** within the 90-day CA window:

```
┌─────────────────────────────────────────────────────────────────┐
│  Day 1        Day 45         Day 89         Day 90 (DEADLINE)   │
│    │            │              │                │               │
│    │◄── Agent connected ──────►│                │               │
│    │    (SVIDs auto-rotate)    │                │               │
│    │                           │                │               │
│    │               CA still valid, but agent    │               │
│    │               disconnected - cached trust  │               │
│    │               bundle may become stale      │               │
│    │                           │                │               │
│    │                           │◄── Must reconnect before ────► │
│    │                           │    CA rotates!                 │
└─────────────────────────────────────────────────────────────────┘
```

**If CA expires while agent is disconnected:**
1. Agent's cached trust bundle becomes stale
2. Agent cannot verify server's new CA certificate
3. Manual intervention required: clear agent data, generate new join token

## API Endpoints

### Status & Discovery

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spiffe/status` | GET | Current SPIFFE integration status |
| `/spiffe/.well-known/spiffe-bundle` | GET | Trust bundle (JWKS format per SPIFFE spec) |

### SVID Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spiffe/svid/x509` | GET | Current X.509-SVID details |
| `/spiffe/svid/x509/chain` | GET | X.509-SVID as PEM certificate chain |
| `/spiffe/svid/jwt` | GET | Fetch JWT-SVID (query: `?audience=target`) |
| `/spiffe/svid/info` | GET | Detailed SVID information |

### Validation Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spiffe/validate/jwt` | POST | Validate JWT-SVID token |
| `/spiffe/validate/x509` | POST | Validate X.509-SVID certificate |

**JWT Validation Request:**
```json
{
  "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9...",
  "audience": ["protocolsoup"]
}
```

**X.509 Validation Request:**
```json
{
  "certificate": "MIIBkTCB+wIJAKHBfpE... (base64 or PEM)"
}
```

### Workload & Trust Bundle

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spiffe/workload` | GET | Current workload information |
| `/spiffe/trust-bundle` | GET | Detailed trust bundle with CA certificates |

### Real Traffic Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/spiffe/demo/mtls` | GET | mTLS demonstration info |
| `/spiffe/demo/mtls/call` | POST | **Real mTLS call** to SPIRE Server with actual TLS handshake |
| `/spiffe/demo/jwt-auth` | GET | JWT authentication demonstration info |
| `/spiffe/demo/jwt-auth/call` | POST | **Real JWT-SVID acquisition** from SPIRE Agent |
| `/spiffe/demo/rotation` | GET | **Real rotation events** captured from live certificate rotations |

#### mTLS Call Response (Real Data)
```json
{
  "success": true,
  "client_spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "server_spiffe_id": "spiffe://protocolsoup.com/spire/server",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "handshake_time": "45.123ms",
  "peer_cert_subject": "O=SPIRE",
  "peer_cert_expiry": "2024-01-11T00:00:00Z",
  "trust_chain_length": 1,
  "steps": [
    "[14:30:00.000] Fetching X.509-SVID from SPIRE Agent Workload API",
    "[14:30:00.001] Obtained X.509-SVID: spiffe://protocolsoup.com/workload/backend",
    "[14:30:00.002] Trust bundle loaded with 1 CA certificate(s)",
    "[14:30:00.003] Initiating TLS handshake to protocolsoup-spire.internal:8081",
    "[14:30:00.048] TLS handshake completed in 45.123ms",
    "[14:30:00.048] Negotiated TLS version: TLS 1.3",
    "[14:30:00.048] Server presented certificate for: spiffe://protocolsoup.com/spire/server",
    "[14:30:00.048] Certificate verified against trust bundle",
    "[14:30:00.048] Mutual TLS authentication successful!"
  ]
}
```

#### Certificate Rotation Response (Real Events)
```json
{
  "description": "REAL X.509-SVID rotation events captured from SPIRE Agent",
  "enabled": true,
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "current_serial": "123456789...",
  "current_expiry": "2024-01-11T00:00:00Z",
  "next_rotation": "2024-01-10T12:00:00Z",
  "time_to_rotation": "11h30m0s",
  "total_rotations": 5,
  "rotation_events": [
    {
      "timestamp": "2024-01-10T00:30:00Z",
      "old_serial_number": "123456788...",
      "new_serial_number": "123456789...",
      "trigger_reason": "ttl_threshold"
    }
  ],
  "last_rotation": {
    "timestamp": "2024-01-10T00:30:00Z",
    "trigger_reason": "ttl_threshold",
    "time_since": "30m0s"
  }
}
```

## Code Structure

```
backend/internal/
├── spiffe/                    # SPIFFE SDK integration library
│   ├── workload.go            # Workload API client, X509/JWT Sources
│   ├── mtls.go                # mTLS server/client configuration
│   ├── middleware.go          # JWT-SVID authentication middleware
│   └── client.go              # SPIFFE-aware HTTP client
│
└── protocols/spiffe/          # SPIFFE protocol plugin
    ├── plugin.go              # Plugin registration, routes, lifecycle
    ├── flows.go               # Protocol flow definitions (8 flows)
    ├── handlers.go            # HTTP request handlers
    └── README.md              # This file

docker/spire/
├── server-fly/                # SPIRE Server for Fly.io deployment
│   ├── server.conf            # Server configuration (CA TTL, plugins)
│   ├── supervisord.conf       # Process manager
│   ├── health-server.go       # Health check endpoint
│   ├── bootstrap-ca.crt       # Bootstrap CA for x509pop attestation
│   └── bootstrap-agent.*      # Agent bootstrap certificates
│
├── server/                    # SPIRE Server for local development
│   ├── Dockerfile
│   └── server.conf
│
├── agent/                     # SPIRE Agent for local development
│   ├── Dockerfile
│   └── agent.conf
│
└── scripts/                   # Helper scripts
    ├── bootstrap.sh           # Initial SPIRE setup
    ├── generate-join-token.sh # Generate node attestation token
    └── register-workloads.sh  # Create registration entries
```

## Key Components

### WorkloadClient (`spiffe/workload.go`)

The core SPIFFE integration client using the official `go-spiffe/v2` SDK:

```go
// Create client with configuration
cfg := spiffe.DefaultConfig() // or customize
client, err := spiffe.NewWorkloadClient(cfg)

// Start (connects to Workload API, begins SVID rotation)
err := client.Start()

// Get current X.509-SVID
svid, err := client.GetX509SVID()
fmt.Println("SPIFFE ID:", svid.ID.String())
fmt.Println("Expires:", svid.Certificates[0].NotAfter)

// Get JWT-SVID for an audience
jwtSVID, err := client.GetJWTSVID(ctx, "target-service")
token := jwtSVID.Marshal()

// Validate a JWT-SVID (full cryptographic validation)
validated, err := client.ValidateJWTSVID(ctx, token, []string{"target-service"})

// Get trust bundle
certs, err := client.GetTrustBundle()

// TLS configuration helpers
tlsConfig := client.TLSConfig()
authorizer := tlsConfig.MTLSAuthorizer()
```

### Environment Variables

```bash
# Enable SPIFFE integration
SHOWCASE_SPIFFE_ENABLED=true

# Workload API socket path (default: /run/spire/sockets/agent.sock)
SHOWCASE_SPIFFE_SOCKET_PATH=unix:///run/spire/sockets/agent.sock

# Trust domain (default: protocolsoup.com)
SHOWCASE_SPIFFE_TRUST_DOMAIN=protocolsoup.com
```

### Plugin (`protocols/spiffe/plugin.go`)

Implements the `ProtocolPlugin` interface:

```go
plugin := spiffe.NewPlugin()

// Initialize with config (connects to Workload API in background)
plugin.Initialize(ctx, config)

// Check if SPIFFE is enabled
if plugin.IsEnabled() {
    // Real SVID operations
} else {
    // Demo mode fallback
}

// Get flow definitions for Looking Glass
flows := plugin.GetFlowDefinitions()

// Get demo scenarios
scenarios := plugin.GetDemoScenarios()

// Get inspectors (X.509, JWT, Trust Bundle, SPIFFE ID)
inspectors := plugin.GetInspectors()
```

## Protocol Flows

### Executable Flows (Real Infrastructure Operations)

All executable flows perform **real operations** against production SPIRE infrastructure:

| Flow | Real Operation |
|------|----------------|
| **X.509-SVID Issuance** | Real gRPC call to SPIRE Agent Workload API → Real certificate from SPIRE Server CA |
| **JWT-SVID Issuance** | Real gRPC call to SPIRE Agent → Real signed JWT-SVID from SPIRE Server |
| **mTLS Handshake** | Real TLS connection to SPIRE Server using X.509-SVID, capturing actual handshake details |
| **Certificate Rotation** | Real rotation events tracked and logged as they occur in the live system |

### Documentation-Only Flows (Educational)

| Flow | Category | Description |
|------|----------|-------------|
| **Workload Registration** | Admin | SPIRE Server registration entry creation |
| **Node Attestation** | Infrastructure | Agent bootstrap and server trust establishment |
| **Workload Attestation** | Infrastructure | Agent process introspection and selector matching |
| **Trust Domain Federation** | Admin | Cross-domain trust configuration |

## SVID Structures

### X.509-SVID Response

```json
{
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "certificate": "MIIBkTCB+wIJAKHBfpE... (base64)",
  "chain": ["cert1...", "cert2..."],
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2024-01-02T00:00:00Z",
  "serial_number": "123456789",
  "issuer": "O=SPIRE",
  "subject": "O=SPIRE",
  "dns_names": [],
  "uris": ["spiffe://protocolsoup.com/workload/backend"],
  "public_key": {
    "algorithm": "ECDSA",
    "curve": "P-256"
  },
  "signature": {
    "algorithm": "ECDSA-SHA256",
    "value": "MEUCIQDk..."
  }
}
```

### JWT-SVID Response

```json
{
  "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly9wcm90b2NvbHNvdXAuY29tL3dvcmtsb2FkL2JhY2tlbmQiLCJhdWQiOlsicHJvdG9jb2xzb3VwIl0sImV4cCI6MTcwNDgyNTYwMCwiaWF0IjoxNzA0ODIyMDAwfQ.signature",
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "audience": ["protocolsoup"],
  "expires_at": "2024-01-10T01:00:00Z",
  "issued_at": "2024-01-10T00:00:00Z",
  "header": {
    "alg": "ES256",
    "kid": "key-id",
    "typ": "JWT"
  },
  "claims": {
    "sub": "spiffe://protocolsoup.com/workload/backend",
    "aud": ["protocolsoup"],
    "exp": 1704825600,
    "iat": 1704822000
  }
}
```

## Demo Mode

When SPIFFE infrastructure is unavailable, the plugin operates in demo mode:

- All endpoints return valid response structures
- Certificates and tokens are marked as demo/simulated
- Educational flows still demonstrate the full protocol
- No external dependencies required

Demo mode is automatically enabled when:
- `SHOWCASE_SPIFFE_ENABLED` is `false` or unset
- SPIRE Agent socket is unavailable
- Workload API connection fails

## Infrastructure Deployment

### Fly.io Production Setup

```bash
# 1. Deploy SPIRE Server
fly deploy -c fly.spire-server.toml -a protocolsoup-spire

# 2. Generate join token for agent
fly ssh console -a protocolsoup-spire -C \
  "/opt/spire/bin/spire-server token generate \
   -socketPath /run/spire/sockets/server.sock \
   -spiffeID spiffe://protocolsoup.com/agent/fly \
   -ttl 86400"

# 3. Set join token as secret on main app
fly secrets set SPIRE_JOIN_TOKEN=<token> -a protocolsoup

# 4. Deploy main application (includes embedded SPIRE Agent)
fly deploy -a protocolsoup

# 5. Create workload registration entry
fly ssh console -a protocolsoup-spire -C \
  "/opt/spire/bin/spire-server entry create \
   -socketPath /run/spire/sockets/server.sock \
   -spiffeID spiffe://protocolsoup.com/workload/backend \
   -parentID spiffe://protocolsoup.com/agent/fly \
   -selector unix:uid:0 \
   -ttl 3600"
```

### Local Development with Docker Compose

```bash
# Start SPIRE infrastructure
docker-compose -f docker/docker-compose.spire.yml up -d

# Wait for server to be ready
sleep 5

# Generate join token
docker-compose -f docker/docker-compose.spire.yml exec spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://protocolsoup.com/agent/local

# Register workloads
docker-compose -f docker/docker-compose.spire.yml exec spire-server \
  /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://protocolsoup.com/workload/backend \
  -parentID spiffe://protocolsoup.com/agent/local \
  -selector docker:label:app:protocol-backend
```

## Testing

### Check SPIFFE Status

```bash
# Production
curl https://protocolsoup.com/spiffe/status

# Local
curl http://localhost:8080/spiffe/status
```

**Expected Response (enabled):**
```json
{
  "enabled": true,
  "trust_domain": "protocolsoup.com",
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "message": "SPIFFE integration active"
}
```

### Fetch and Validate JWT-SVID

```bash
# Get JWT-SVID
curl "https://protocolsoup.com/spiffe/svid/jwt?audience=test-service"

# Validate JWT-SVID
curl -X POST https://protocolsoup.com/spiffe/validate/jwt \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJ...", "audience": ["test-service"]}'
```

### Inspect X.509-SVID

```bash
# Get certificate details
curl https://protocolsoup.com/spiffe/svid/x509 | jq

# Get PEM certificate chain
curl https://protocolsoup.com/spiffe/svid/x509/chain

# View trust bundle
curl https://protocolsoup.com/spiffe/.well-known/spiffe-bundle | jq
```

## Specifications Compliance

This implementation follows these SPIFFE specifications:

- **[SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)**: RFC 3986 URI format `spiffe://trust-domain/path`
- **[X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)**: RFC 5280 certificates with SPIFFE ID in SAN URI
- **[JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)**: RFC 7519 JWTs with `sub` = SPIFFE ID, `aud` = audience
- **[Trust Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md)**: JWKS with X.509 roots
- **[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)**: gRPC over Unix Domain Socket

## Troubleshooting

### Common Issues

**"SPIFFE integration not available (running in demo mode)"**
- Check `SHOWCASE_SPIFFE_ENABLED=true` is set
- Verify SPIRE Agent socket exists at `/run/spire/sockets/agent.sock`
- Check agent logs: `fly logs -a protocolsoup | grep -i spire`

**"certificate signed by unknown authority"**
- Agent's cached trust bundle is stale (CA rotated while disconnected)
- Fix: Clear agent data and restart with new join token
  ```bash
  fly ssh console -a protocolsoup -C "rm -rf /data/spire/*"
  # Generate new token and restart
  ```

**"join token does not exist or has already been used"**
- Join tokens are single-use
- Generate a new token on SPIRE Server and update the secret

**"failed to create X509Source: context deadline exceeded"**
- SPIRE Agent cannot reach SPIRE Server
- Check private network connectivity: `fly ssh console -a protocolsoup -C "nc -zv protocolsoup-spire.internal 8081"`

## Dependencies

**Go Packages:**
- `github.com/spiffe/go-spiffe/v2` - Official SPIFFE Go SDK
- `google.golang.org/grpc` - gRPC for Workload API

**Docker Images:**
- `ghcr.io/spiffe/spire-server:1.9` - SPIRE Server
- `ghcr.io/spiffe/spire-agent:1.9` - SPIRE Agent

## License

Part of the ProtocolLens/Protocol Soup project.
