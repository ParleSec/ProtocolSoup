# protocolsoup-frontend

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-frontend`
- **Purpose:** Serve the Next.js App Router UI (SSR/SSG discovery pages plus client-side interactive protocol tools).
- **Topology role:** Web UI service that rewrites HTTP protocol/API calls to the gateway/backend service.

## Runtime Contract

### Ports

- `3000/tcp`: Next.js standalone server.

### Dependencies

- Requires a reachable backend/gateway upstream (for example `gateway:8080` on the same Docker network).
- HTTP protocol/API traffic is forwarded by Next rewrites.
- WebSocket routes are **not** rewritten by Next and must be routed by the edge proxy (Nginx/Fly ingress) to backend.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BACKEND_ORIGIN` | Yes (outside local defaults) | `http://localhost:8080` | Upstream backend base URL for HTTP rewrites (`/api`, `/oauth2`, `/oidc`, `/oid4vci`, `/oid4vp`, `/saml`, `/spiffe`, `/scim`, `/ssf`) |
| `NEXT_PUBLIC_SITE_URL` | Yes (production) | `https://protocolsoup.com` | Canonical public origin used in metadata and sitemap generation |
| `DOCS_SITE_URL` | No | `https://docs.protocolsoup.com` | Docs host used in sitemap-index output |

### Storage And Volumes

- No persistent storage required.

### Health And Readiness

- Container healthcheck probes `http://localhost:3000`.
- Readiness depends on Next runtime startup and backend reachability for API-backed routes.

## API Surface

- This image is UI-only; protocol handlers remain backend services.
- Serves Next routes and SEO endpoints, including:
  - `/`
  - `/protocols`
  - `/protocol/:protocolId`
  - `/protocol/:protocolId/flow/:flowId`
  - `/robots.txt`
  - `/sitemap.xml`
  - `/sitemap-index.xml`
- Rewritten HTTP upstream paths:
  - `/api`
  - `/oauth2`
  - `/oidc`
  - `/oid4vci`
  - `/oid4vp`
  - `/saml`
  - `/spiffe`
  - `/scim`
  - `/ssf`

## Quick Start

### docker run

```bash
# Start a user-defined network so frontend can resolve "gateway"
docker network create protocolsoup-net

docker run -d --name gateway --network protocolsoup-net \
  -p 8080:8080 ghcr.io/parlesec/protocolsoup-gateway:latest

docker run -d --name frontend --network protocolsoup-net \
  -e BACKEND_ORIGIN=http://gateway:8080 \
  -e NEXT_PUBLIC_SITE_URL=http://localhost:3000 \
  -p 3000:3000 ghcr.io/parlesec/protocolsoup-frontend:latest
```

### docker compose snippet

```yaml
services:
  frontend:
    image: ghcr.io/parlesec/protocolsoup-frontend:latest
    ports:
      - "3000:3000"
    environment:
      - BACKEND_ORIGIN=http://gateway:8080
      - NEXT_PUBLIC_SITE_URL=http://localhost:3000
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
- Keep backend on a private network segment; only expose frontend ingress publicly.
- Ensure edge proxy routes WebSocket upgrades (`/ws/*`) directly to backend.
- Ensure backend CORS policy is restricted to expected origins.

## Troubleshooting

- **UI loads but protocol/API calls fail:** backend is missing, unhealthy, or `BACKEND_ORIGIN` is incorrect.
- **Looking Glass WebSocket is disconnected:** verify edge proxy `/ws/*` upgrade routing to backend (not Next).
- **Discovery routes return unexpected 404/500:** verify Next service is healthy and proxy points web routes to frontend service.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- Gateway service docs: [gateway.md](gateway.md)
- Platform quickstart: [../content/start-here/quickstart.md](../content/start-here/quickstart.md)
