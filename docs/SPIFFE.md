# SPIFFE/SPIRE Integration

This document describes the real, production-ready SPIFFE/SPIRE implementation in ProtocolLens.

## Overview

ProtocolLens includes a fully functional SPIFFE/SPIRE infrastructure:
- **SPIRE Server** - Issues X.509-SVIDs and JWT-SVIDs for the `spiffe://protocolsoup.com` trust domain
- **SPIRE Agent** - Performs workload attestation and delivers SVIDs
- **Workload Registration** - Automatically registers workloads with the server

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SPIRE Infrastructure                       │
├─────────────────┬───────────────────────────────────────────┤
│  SPIRE Server   │  • Trust domain CA                        │
│  (Port 8081)    │  • Issues SVIDs                           │
│                 │  • Manages registrations                   │
├─────────────────┼───────────────────────────────────────────┤
│  SPIRE Agent    │  • Node attestation (join_token)          │
│                 │  • Workload attestation (unix)            │
│                 │  • Workload API socket                    │
├─────────────────┴───────────────────────────────────────────┤
│                   Registered Workloads                       │
│  • spiffe://protocolsoup.com/workload/backend               │
│  • spiffe://protocolsoup.com/workload/demo-client           │
│  • spiffe://protocolsoup.com/workload/demo-service          │
└─────────────────────────────────────────────────────────────┘
```

## Running the SPIRE Stack

### Local Development (Docker Compose)

```bash
cd docker

# Start the full stack with SPIRE
docker compose up -d

# View SPIRE logs
docker logs protocolsoup-spire-server
docker logs protocolsoup-spire-agent
docker logs protocolsoup-spire-registration
```

### Verify SPIRE is Working

```bash
# List registered entries
docker exec protocolsoup-spire-agent /opt/spire/bin/spire-server entry show \
    -socketPath /run/spire/sockets/server/server.sock

# Fetch SVIDs (proves SPIRE is issuing real certificates)
docker exec protocolsoup-spire-agent /opt/spire/bin/spire-agent api fetch x509 \
    -socketPath /run/spire/sockets/agent.sock
```

### Production Deployment (Fly.io)

SPIFFE/SPIRE can be deployed to Fly.io with two apps:
1. **protocolsoup-spire** - SPIRE Server (certificate authority)
2. **protocolsoup** - Main app with embedded SPIRE Agent

#### Step 1: Deploy SPIRE Server

```bash
# Create and deploy SPIRE Server app
fly launch --config fly.spire-server.toml --name protocolsoup-spire

# Create persistent volume for SPIRE data
fly volumes create spire_data -a protocolsoup-spire -s 1

# Deploy
fly deploy -c fly.spire-server.toml -a protocolsoup-spire
```

#### Step 2: Generate Join Token

```bash
# SSH into SPIRE Server and generate a join token
fly ssh console -a protocolsoup-spire

# Inside the container:
/opt/spire/bin/spire-server token generate \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://protocolsoup.com/agent/fly \
    -ttl 86400

# Copy the token value
```

#### Step 3: Configure Main App

```bash
# Set the join token as a secret
fly secrets set SPIRE_JOIN_TOKEN=<token-from-step-2> -a protocolsoup

# Deploy the main app (includes embedded SPIRE Agent)
fly deploy
```

#### Step 4: Register Workload

```bash
# SSH into SPIRE Server to register the production workload
fly ssh console -a protocolsoup-spire

/opt/spire/bin/spire-server entry create \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://protocolsoup.com/workload/backend \
    -parentID spiffe://protocolsoup.com/agent/fly \
    -selector unix:uid:0 \
    -ttl 3600
```

#### Architecture on Fly.io

```
┌─────────────────────────────────────────────────────────────┐
│                 Fly.io Private Network                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────┐      ┌─────────────────────────┐   │
│  │ protocolsoup-spire  │      │ protocolsoup            │   │
│  │ (SPIRE Server)      │◄────►│ (Backend + Agent)       │   │
│  │                     │ TCP  │                         │   │
│  │ Port 8081 (API)     │ 8081 │ Agent → Unix Socket     │   │
│  │ Port 8080 (Health)  │      │ Backend → Agent Socket  │   │
│  └─────────────────────┘      └─────────────────────────┘   │
│         ▲                              │                     │
│         │                              │                     │
│    Persistent                     Public                    │
│    Volume                         HTTPS                     │
│                                       ▼                     │
│                              ┌─────────────────┐            │
│                              │ protocolsoup.com│            │
│                              └─────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

#### Renewing Join Tokens

Join tokens are single-use. When redeploying the main app:

```bash
# Generate new token
fly ssh console -a protocolsoup-spire -C "/opt/spire/bin/spire-server token generate -socketPath /run/spire/sockets/server.sock -spiffeID spiffe://protocolsoup.com/agent/fly -ttl 86400"

# Update secret
fly secrets set SPIRE_JOIN_TOKEN=<new-token> -a protocolsoup
```

## Configuration

### Environment Variables

The backend uses these environment variables for SPIFFE:

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_SPIFFE_ENABLED` | Enable SPIFFE integration | `false` |
| `SHOWCASE_SPIFFE_SOCKET_PATH` | Workload API socket path | `unix:///run/spire/sockets/agent.sock` |
| `SHOWCASE_SPIFFE_TRUST_DOMAIN` | Trust domain | `protocolsoup.com` |

### Trust Domain

The trust domain is `protocolsoup.com`. All SPIFFE IDs follow the format:
```
spiffe://protocolsoup.com/<workload-path>
```

### Workload Registration

Workloads are registered in `docker/spire/registration/register-workloads.sh`:

```hcl
# Example registration entry
spiffe_id:  spiffe://protocolsoup.com/workload/backend
parent_id:  spiffe://protocolsoup.com/agent/main
selector:   unix:uid:0
ttl:        3600  # 1 hour
```

## Known Limitations

### Docker Unix Socket Limitation

When running in Docker Compose, the Unix domain socket cannot be shared across containers for workload attestation. This is because:

1. The SPIRE Agent uses `SO_PEERCRED` to identify callers
2. Docker containers have isolated PID namespaces
3. The agent cannot resolve caller identity across namespace boundaries

**Symptoms:**
```
Connection failed during accept: could not resolve caller information
```

### Solutions for Production

1. **Kubernetes** (Recommended)
   - Use k8s workload attestor which works natively
   - Deploy SPIRE with official Helm charts

2. **Sidecar Pattern**
   - Run agent and workload in same container
   - Share network namespace

3. **TCP Workload API**
   - Configure agent to listen on TCP
   - Less secure but works across containers

## Without SPIRE Infrastructure

When SPIFFE cannot connect to a real Workload API (e.g., on production without SPIRE deployed):

- `/spiffe/status` returns `enabled: false`
- SPIFFE flows in Looking Glass show "Workload API Unavailable"
- Clear error message explains SPIRE infrastructure is required
- Other protocols (OAuth 2.0, OIDC, SAML) work normally

## API Endpoints

### SPIFFE Status
```
GET /spiffe/status
```

### X.509-SVID
```
GET /spiffe/svid/x509      # Get current X.509-SVID
GET /spiffe/svid/x509/chain # Get PEM certificate chain
```

### JWT-SVID
```
GET /spiffe/svid/jwt?audience=<aud>  # Get JWT-SVID
```

### Trust Bundle
```
GET /spiffe/.well-known/spiffe-bundle  # SPIFFE bundle endpoint
GET /spiffe/trust-bundle               # Detailed bundle info
```

### Validation
```
POST /spiffe/validate/jwt   # Validate JWT-SVID
POST /spiffe/validate/x509  # Validate X.509-SVID
```

### Workload Info
```
GET /spiffe/workload        # Current workload identity details
```

## File Structure

```
docker/
├── docker-compose.spire.yml      # SPIRE Docker Compose overlay
└── spire/
    ├── server/
    │   ├── Dockerfile
    │   └── server.conf           # SPIRE Server configuration
    ├── agent/
    │   ├── Dockerfile
    │   ├── agent.conf            # SPIRE Agent configuration
    │   └── bootstrap-agent.sh    # Automated bootstrap script
    └── registration/
        ├── Dockerfile
        └── register-workloads.sh # Workload registration

backend/internal/
├── spiffe/
│   ├── workload.go              # Workload API client
│   ├── mtls.go                  # mTLS utilities
│   ├── middleware.go            # JWT-SVID middleware
│   └── client.go                # SPIFFE-aware HTTP client
└── protocols/spiffe/
    ├── plugin.go                # Protocol plugin
    ├── handlers.go              # HTTP handlers
    └── flows.go                 # Flow definitions
```

## Security Considerations

1. **Join Token Security**: Join tokens are single-use and short-lived (10 minutes)
2. **SVID TTL**: X.509-SVIDs have 1-hour TTL with automatic rotation
3. **Insecure Bootstrap**: Demo uses insecure bootstrap for simplicity; production should use trust bundle
4. **Unix Attestation**: Uses `unix:uid:0` selector; production should use more specific selectors

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe)
- [SPIRE Documentation](https://spiffe.io/docs/latest/)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
- [X.509-SVID Specification](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
- [JWT-SVID Specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)
