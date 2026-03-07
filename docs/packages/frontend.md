# protocolsoup-frontend

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-frontend`
- **Purpose:** Serve the React UI for protocol browsing, flow execution, Looking Glass inspection, and SSF sandbox interaction.
- **Topology role:** Web entrypoint that proxies protocol/API traffic to the gateway service.

## Runtime Contract

### Ports

- `3000/tcp`: Nginx-served frontend application.

### Dependencies

- Requires a reachable gateway backend at `gateway:8080` on the same Docker network.
- The container Nginx proxy forwards protocol and API routes to that upstream.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `(none)` | N/A | N/A | This image is pre-built and does not expose runtime env switches for upstream selection |

### Storage And Volumes

- No persistent storage required.

### Health And Readiness

- Container healthcheck probes `http://localhost:3000`.
- Readiness depends on both static asset availability and upstream gateway reachability for API-backed screens.

## API Surface

- This image is UI-only; it does not implement backend protocol handlers.
- Built-in Nginx proxy routes:
  - `/api`
  - `/ws`
  - `/oauth2`
  - `/oidc`
  - `/saml`
  - `/scim`
  - `/ssf`
  - `/spiffe`

## Quick Start

### docker run

```bash
# Start a user-defined network so frontend can resolve "gateway"
docker network create protocolsoup-net

docker run -d --name gateway --network protocolsoup-net \
  -p 8080:8080 ghcr.io/parlesec/protocolsoup-gateway:latest

docker run -d --name frontend --network protocolsoup-net \
  -p 3000:3000 ghcr.io/parlesec/protocolsoup-frontend:latest
```

### docker compose snippet

```yaml
services:
  frontend:
    image: ghcr.io/parlesec/protocolsoup-frontend:latest
    ports:
      - "3000:3000"
    depends_on:
      gateway:
        condition: service_healthy

  gateway:
    image: ghcr.io/parlesec/protocolsoup-gateway:latest
    ports:
      - "8080:8080"
```

## Security Hardening

- Terminate TLS in front of the frontend service for production.
- Keep gateway on a private network segment; only expose the frontend ingress publicly.
- Ensure upstream gateway CORS policy is restricted to expected origins.

## Troubleshooting

- **UI loads but protocol calls fail:** gateway is missing, unhealthy, or not resolvable as `gateway`.
- **WebSocket-based Looking Glass is disconnected:** verify `/ws` proxy path reaches the gateway.
- **Direct deep links return 404 at reverse proxy:** ensure SPA fallback to `index.html` is preserved.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- Gateway service docs: [gateway.md](gateway.md)
- Platform quickstart: [../content/start-here/quickstart.md](../content/start-here/quickstart.md)
