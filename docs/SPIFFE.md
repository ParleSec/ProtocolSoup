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

### Start with Docker Compose

```bash
cd docker

# Start the full stack with SPIRE
docker compose -f docker-compose.yml -f docker-compose.spire.yml up -d

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

## Demo Mode

When SPIFFE cannot connect to a real Workload API, the backend falls back to demo mode:

- Simulated X.509-SVIDs with realistic structure
- Simulated JWT-SVIDs with proper claims
- Demo trust bundle data
- All protocol flows work for educational purposes

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

### Demos
```
GET /spiffe/demo/mtls       # mTLS demonstration info
POST /spiffe/demo/mtls/call # Execute mTLS demo
GET /spiffe/demo/rotation   # Certificate rotation info
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
