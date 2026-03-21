# protocolsoup-gateway

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-gateway`
- **Purpose:** Aggregate protocol metadata and route protocol/API traffic to upstream ProtocolSoup services.
- **Topology role:** Entry point for split-service deployments. Usually fronted by the web UI and/or an edge proxy.

## Runtime Contract

### Ports

- `8080/tcp`: gateway API, protocol routing, and Looking Glass websocket proxy.

### Dependencies

- At least one protocol upstream should be configured:
  - federation (`/oauth2`, `/oidc`, `/saml`, plus VC modules in current federation runtime)
  - scim (`/scim`)
  - ssf (`/ssf`)
  - spiffe (`/spiffe`)

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FEDERATION_SERVICE_URL` | No | `(none)` | Federation upstream base URL |
| `SCIM_SERVICE_URL` | No | `(none)` | SCIM upstream base URL |
| `SSF_SERVICE_URL` | No | `(none)` | SSF upstream base URL |
| `SPIFFE_SERVICE_URL` | No | `(none)` | SPIFFE upstream base URL |
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Public base URL |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `GATEWAY_REFRESH_INTERVAL` | No | `30s` | Upstream protocol refresh interval |
| `GATEWAY_STARTUP_RETRY_INITIAL` | No | `2s` | Initial startup retry delay |
| `GATEWAY_STARTUP_RETRY_MAX` | No | `30s` | Maximum startup retry delay |
| `GATEWAY_REQUEST_TIMEOUT` | No | `5s` | Upstream request timeout |

### Storage And Volumes

- None required.
- Gateway state (protocol map and session routing hints) is in-memory only.

### Health And Readiness

- `GET /health`
  - Always returns HTTP `200`.
  - `ready` indicates whether protocol inventory has been populated.
- `GET /health/upstreams`
  - Returns HTTP `200` when at least one upstream is healthy.
  - Returns HTTP `503` with `status: no_upstreams` (none configured) or `status: degraded` (configured but unavailable).
- Container healthcheck probes `/health` by default.

## API Surface

### Core Gateway APIs

- `GET /api` and `GET /api/protocols`
- `GET /api/protocols/{id}`
- `GET /api/protocols/{id}/flows`
- `POST /api/protocols/{id}/demo/{flow}`

### Looking Glass Proxy APIs

- `POST /api/lookingglass/decode`
- `GET /api/lookingglass/sessions`
- `GET /api/lookingglass/sessions/{id}`
- `GET /ws/lookingglass/{session}`

## Quick Start

### docker run

```bash
docker run -p 8080:8080 \
  -e FEDERATION_SERVICE_URL=http://federation-service:8080 \
  -e SCIM_SERVICE_URL=http://scim-service:8080 \
  -e SSF_SERVICE_URL=http://ssf-service:8080 \
  ghcr.io/parlesec/protocolsoup-gateway:latest
```

### docker compose snippet

```yaml
services:
  gateway:
    image: ghcr.io/parlesec/protocolsoup-gateway:latest
    ports:
      - "8080:8080"
    environment:
      - FEDERATION_SERVICE_URL=http://federation-service:8080
      - SCIM_SERVICE_URL=http://scim-service:8080
      - SSF_SERVICE_URL=http://ssf-service:8080
```

## Security Hardening

- Set `SHOWCASE_CORS_ORIGINS` explicitly for production origins only.
- Keep upstream service URLs on a private/internal network.
- Put TLS termination in front of the gateway (reverse proxy or managed edge).
- Avoid exposing unused protocol upstreams.

## Troubleshooting

- **`/api/protocols` returns `503`**: upstreams are unreachable or not configured.
- **`/health/upstreams` reports `no_upstreams`**: no upstream environment URLs were supplied.
- **`/api/protocols/{id}` returns `404`**: protocol not discovered from any upstream.
- **Looking Glass websocket returns `404`**: session ID does not exist on discovered upstreams.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- Federation image: [federation.md](federation.md)
- SCIM image: [scim.md](scim.md)
- SSF image: [ssf.md](ssf.md)
