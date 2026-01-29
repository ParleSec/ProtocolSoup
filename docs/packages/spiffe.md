# protocolsoup-spiffe

**SPIFFE Workload Identity Service**

Demonstrates X.509-SVID and JWT-SVID issuance, validation, and mTLS. Includes embedded SPIRE Agent.

## Quick Start

```bash
# Demo mode (simulated responses, no SPIRE required)
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  ghcr.io/parlesec/protocolsoup-spiffe
```

**Note:** Without SPIRE infrastructure, runs in demo mode with simulated responses.

## Full SPIFFE Stack

For real SVID issuance with SPIRE:

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

This starts:
- SPIRE Server (CA)
- SPIRE Agent (workload attestation)
- SPIFFE Service (this image with embedded agent)

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /spiffe/status` | SPIFFE/SPIRE availability |
| `GET /spiffe/svid/x509` | X.509-SVID certificate details |
| `GET /spiffe/svid/x509/chain` | Full certificate chain (PEM) |
| `GET /spiffe/svid/jwt?audience=svc` | JWT-SVID token |
| `GET /spiffe/.well-known/spiffe-bundle` | Trust bundle endpoint |
| `GET /spiffe/trust-bundle` | Trust bundle details |
| `GET /spiffe/workload` | Workload identity info |
| `POST /spiffe/validate/jwt` | Validate a JWT-SVID |
| `POST /spiffe/validate/x509` | Validate an X.509-SVID |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Service base URL |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Listen address |
| `SHOWCASE_SPIFFE_ENABLED` | `false` | Enable real SPIFFE |
| `SHOWCASE_SPIFFE_SOCKET_PATH` | `unix:///run/spire/sockets/agent.sock` | Workload API socket |
| `SHOWCASE_SPIFFE_TRUST_DOMAIN` | `protocolsoup.com` | SPIFFE trust domain |

## SPIFFE Concepts

### Trust Domain
All identities belong to `spiffe://protocolsoup.com/...`

### SPIFFE ID Format
```
spiffe://protocolsoup.com/workload/backend
spiffe://protocolsoup.com/workload/demo-client
```

### X.509-SVID
- Short-lived X.509 certificate
- SPIFFE ID in SAN URI extension
- Auto-rotated by SPIRE Agent

### JWT-SVID
- Short-lived JWT token
- SPIFFE ID in `sub` claim
- Audience-scoped

## Example: Get JWT-SVID

```bash
curl "http://localhost:8080/spiffe/svid/jwt?audience=my-service"
```

Response:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "audience": ["my-service"],
  "expires_at": "2026-01-28T14:00:00Z"
}
```

## Example: Validate JWT-SVID

```bash
curl -X POST http://localhost:8080/spiffe/validate/jwt \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJFUzI1NiIs...",
    "audience": ["my-service"]
  }'
```

Response:
```json
{
  "valid": true,
  "spiffe_id": "spiffe://protocolsoup.com/workload/backend",
  "details": {
    "validation_type": "cryptographic",
    "signature": "verified against SPIFFE trust bundle"
  }
}
```
