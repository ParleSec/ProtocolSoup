# protocolsoup-spiffe

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-spiffe`
- **Purpose:** Expose SPIFFE/SPIRE APIs for X.509-SVID and JWT-SVID retrieval, validation, trust-bundle inspection, and mTLS/JWT demo operations.
- **Topology role:** Optional protocol service in the split stack; can run in demo mode alone or in full mode with SPIRE infrastructure.

## Runtime Contract

### Ports

- `8080/tcp`: SPIFFE API endpoints plus health/index routes.

### Dependencies

- **Demo mode:** none.
- **Full SPIFFE mode:** requires SPIRE infrastructure and socket sharing (`docker-compose.spiffe.yml`).

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Public base URL |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SHOWCASE_ENV` | No | `development` | Runtime environment label |
| `SHOWCASE_SPIFFE_ENABLED` | No | `false` | Enable real Workload API integration |
| `SHOWCASE_SPIFFE_SOCKET_PATH` | No | `unix:///run/spire/sockets/agent.sock` | SPIRE Agent Workload API socket |
| `SHOWCASE_SPIFFE_TRUST_DOMAIN` | No | `protocolsoup.com` | Expected SPIFFE trust domain |
| `SPIRE_SERVER_ADDRESS` | No | `spire-server:8081` | Target used by mTLS demo calls |

### Storage And Volumes

- Demo mode requires no persistent storage.
- Full mode commonly mounts:
  - SPIRE server socket read-only (`/run/spire/sockets/server`)
  - agent state directory (`/opt/spire/data/agent`)

### Health And Readiness

- `GET /health` for service health.
- `GET /spiffe/status` reports whether SPIFFE integration is active or fallback/demo mode.

## API Surface

### Status, Bundle, And Workload

- `GET /spiffe/status`
- `GET /spiffe/.well-known/spiffe-bundle`
- `GET /spiffe/trust-bundle`
- `GET /spiffe/workload`

### SVID Endpoints

- `GET /spiffe/svid/x509`
- `GET /spiffe/svid/x509/chain`
- `GET /spiffe/svid/jwt?audience=<aud>`
- `GET /spiffe/svid/info`

### Validation Endpoints

- `POST /spiffe/validate/jwt`
- `POST /spiffe/validate/x509`

### Demo Endpoints

- `GET /spiffe/demo/mtls`
- `POST /spiffe/demo/mtls/call`
- `GET /spiffe/demo/jwt-auth`
- `POST /spiffe/demo/jwt-auth/call`
- `GET /spiffe/demo/rotation`

## Quick Start

### docker run

```bash
# Demo mode (no SPIRE required)
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  ghcr.io/parlesec/protocolsoup-spiffe:latest
```

### docker compose snippet

```yaml
services:
  spiffe-service:
    image: ghcr.io/parlesec/protocolsoup-spiffe:latest
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SHOWCASE_SPIFFE_ENABLED=true
      - SHOWCASE_SPIFFE_SOCKET_PATH=unix:///run/spire/sockets/agent.sock
    volumes:
      - spire-server-socket:/run/spire/sockets/server:ro
      - spiffe-agent-data:/opt/spire/data/agent
```

## Security Hardening

- Run with `SHOWCASE_SPIFFE_ENABLED=true` only when SPIRE dependencies are correctly isolated.
- Keep SPIRE sockets on internal networks and do not expose them publicly.
- Use TLS at ingress and restrict frontend origins via `SHOWCASE_CORS_ORIGINS`.
- Pin trust domain expectations via `SHOWCASE_SPIFFE_TRUST_DOMAIN`.

## Troubleshooting

- **`SPIFFE Workload API unavailable`:** set `SHOWCASE_SPIFFE_ENABLED=true` and verify socket mount/path.
- **mTLS demo call fails:** confirm `SPIRE_SERVER_ADDRESS` resolves and SPIRE Server is healthy.
- **SVID endpoints return `503`:** service is in demo mode or agent startup/attestation has not completed yet.
- **Intermittent trust errors after long downtime:** refresh SPIRE bootstrap and reconnect agent.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SPIFFE protocol implementation: [../../backend/internal/protocols/spiffe/README.md](../../backend/internal/protocols/spiffe/README.md)
- SPIRE server image: [spire-server.md](spire-server.md)
- SPIRE agent image: [spire-agent.md](spire-agent.md)
