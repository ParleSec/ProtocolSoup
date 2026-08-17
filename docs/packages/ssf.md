# protocolsoup-ssf

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-ssf`
- **Purpose:** Provide SSF transmitter and receiver behavior for CAEP/RISC event workflows with real SET generation and processing. Looking Glass is the run surface; this image stays independent of federation.
- **Topology role:** Can run standalone or behind `protocolsoup-gateway` as `/ssf`; includes a secondary receiver listener for push-delivery demos.
- **Discovery:** `GET /.well-known/ssf-configuration` on the issuer (`spec_version` `"1_0"`). Local/demo `issuer` may be `http://` (SSF §7.1 wants `https`).

## Runtime Contract

### Ports

- `8080/tcp`: primary SSF API (discovery, stream management, actions, state, proxy receiver routes).
- `8081/tcp`: standalone receiver service (`/ssf/*`) used by push-delivery scenarios.

### Dependencies

- No external services required for SET delivery.
- Optional gateway integration for single-origin routing.
- Optional `FEDERATION_SERVICE_URL` for post-CAEP MockIdP session/token revocation.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Main API listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Public issuer/base URL used in SSF metadata and event context |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SHOWCASE_ENV` | No | `development` | Runtime environment label |
| `SSF_DATA_DIR` | No | `./data` | SQLite storage directory |
| `SSF_RECEIVER_PORT` | No | `8081` | Standalone receiver listener port |
| `SSF_RECEIVER_TOKEN` | No | `(auto-generated)` | Bearer token expected by receiver push delivery |
| `FEDERATION_SERVICE_URL` | No | loopback from `SHOWCASE_LISTEN_ADDR` | Federation base URL for post-CAEP `revoke-subject` |
| `SSF_TO_FEDERATION_TOKEN` | No | `(empty)` | Bearer token shared with federation for that demo API |

### Storage And Volumes

- SSF state is persisted in SQLite under `SSF_DATA_DIR`.
- Recommended container mount: `-v ssf-data:/app/data` with `SSF_DATA_DIR=/app/data`.

### Health And Readiness

- `GET /health` on the main service.
- Receiver health/status is exposed at:
  - `GET /ssf/receiver/status` (proxy via main API)
  - `GET http://<host>:8081/ssf/status` (direct receiver listener)

## API Surface

### Discovery And Metadata

- `GET /ssf/info`
- `GET /.well-known/ssf-configuration`
- `GET /ssf/jwks`

### Stream, Subject, And Delivery APIs

- `POST|GET|PATCH|DELETE /ssf/stream` (nested `delivery`; GET without `stream_id` returns a list)
- `GET|POST /ssf/status`
- `POST /ssf/verify` (`stream_id` required; 204 empty)
- `GET|POST /ssf/subjects`
- `DELETE /ssf/subjects/{id}`
- `GET|POST /ssf/poll`
- `POST /ssf/ack`

### Lab And Inspection APIs

- `POST /ssf/actions/{action}`
- `GET /ssf/events`
- `GET /ssf/received`
- `GET /ssf/responses`
- `GET /ssf/event-types`
- `POST /ssf/decode`
- `GET /ssf/security-state`
- `GET /ssf/security-state/{email}`
- `POST /ssf/security-state/{email}/reset`

### Receiver Proxy APIs (Main Port -> Receiver Port)

- `POST /ssf/receiver/push`
- `GET /ssf/receiver/status`
- `GET /ssf/receiver/events`
- `GET /ssf/receiver/actions`

## Quick Start

### docker run

```bash
docker run -p 8080:8080 -p 8081:8081 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SSF_DATA_DIR=/app/data \
  -v ssf-data:/app/data \
  ghcr.io/parlesec/protocolsoup-ssf:latest
```

### docker compose snippet

```yaml
services:
  ssf-service:
    image: ghcr.io/parlesec/protocolsoup-ssf:latest
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SSF_DATA_DIR=/app/data
      - SSF_RECEIVER_PORT=8081
      - FEDERATION_SERVICE_URL=http://federation-service:8080
      - SSF_TO_FEDERATION_TOKEN=ssf-federation-caep-lab
    ports:
      - "8080:8080"
      - "8081:8081"
    volumes:
      - ssf-data:/app/data
```

## Security Hardening

- Set `SSF_RECEIVER_TOKEN` explicitly outside local demos.
- Set `SSF_TO_FEDERATION_TOKEN` on both `ssf-service` and `federation-service`.
- Keep `8081` receiver port internal unless external push testing requires exposure.
- Restrict `SHOWCASE_CORS_ORIGINS` to trusted frontend origins.
- Front the service with TLS termination for production traffic.

## Troubleshooting

- **No push events are processed:** verify receiver token alignment and `SSF_RECEIVER_PORT`.
- **Looking Glass appears empty:** mint a session with `POST /api/protocols/ssf/demo/ssf-stream-lab` and send `X-Looking-Glass-Session` on `/ssf/*` requests. The engine drops events for unknown sessions. Fire event mutates RP state; Verify stream does not.
- **State resets after restart:** mount persistent storage and set `SSF_DATA_DIR`.
- **Gateway path issues:** confirm `SSF_SERVICE_URL` points to this service in gateway config.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- Protocol implementation details: [../../backend/internal/protocols/ssf/README.md](../../backend/internal/protocols/ssf/README.md)
- Gateway integration: [gateway.md](gateway.md)
