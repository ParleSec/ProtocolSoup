# protocolsoup-scim

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-scim`
- **Purpose:** SCIM 2.0 server for user and group lifecycle provisioning.
- **Topology role:** Can run standalone or behind the gateway as the `/scim` upstream service.

RFC alignment target: RFC 7642, RFC 7643, and RFC 7644.

## Runtime Contract

### Ports

- `8080/tcp`: SCIM API and service health endpoints.

### Dependencies

- No external database required (SQLite-backed storage).
- Optional integration dependencies are external IdPs (Okta, Azure AD, SailPoint, etc.).

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Base URL used in SCIM metadata |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SCIM_API_TOKEN` | No (Yes for production) | `(none)` | Bearer token for SCIM auth; if unset, auth is disabled |
| `SCIM_DATA_DIR` | No | `./data` (container default path resolves to `/app/data`) | SQLite storage directory |
| `SCIM_LOOKING_GLASS` | No | `true` | Enable Looking Glass capture for SCIM events |

### Storage And Volumes

- Persist SCIM data by mounting a volume to the storage directory.
- Recommended container mount: `-v scim-data:/app/data` with `SCIM_DATA_DIR=/app/data`.

### Health And Readiness

- `GET /health` returns service health.
- Container healthcheck probes `/health` by default.

## API Surface

### Discovery Endpoints

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/ResourceTypes/{id}`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/Schemas/{id}`

### User Endpoints

- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/{id}`
- `PUT /scim/v2/Users/{id}`
- `PATCH /scim/v2/Users/{id}`
- `DELETE /scim/v2/Users/{id}`

### Group Endpoints

- `GET /scim/v2/Groups`
- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/{id}`
- `PUT /scim/v2/Groups/{id}`
- `PATCH /scim/v2/Groups/{id}`
- `DELETE /scim/v2/Groups/{id}`

### Bulk And Search Endpoints

- `POST /scim/v2/Bulk`
- `POST /scim/v2/.search`

## Quick Start

### docker run

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SCIM_API_TOKEN=your-secure-token \
  -e SCIM_DATA_DIR=/app/data \
  -v scim-data:/app/data \
  ghcr.io/parlesec/protocolsoup-scim:latest
```

### docker compose snippet

```yaml
services:
  scim-service:
    image: ghcr.io/parlesec/protocolsoup-scim:latest
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SCIM_API_TOKEN=${SCIM_API_TOKEN}
      - SCIM_DATA_DIR=/app/data
    volumes:
      - scim-data:/app/data
```

## Security Hardening

- Set `SCIM_API_TOKEN` in production; do not run with open auth outside local/demo use.
- Use HTTPS at the edge between IdP and SCIM endpoint.
- Restrict `SHOWCASE_CORS_ORIGINS` to trusted origins.
- Persist data to a managed volume and protect that volume as sensitive identity state.
- Rotate `SCIM_API_TOKEN` on a regular cadence.

## Troubleshooting

- **`401` with `invalidValue` errors**: missing/invalid `Authorization: Bearer <SCIM_API_TOKEN>`.
- **SCIM auth unexpectedly open**: verify `SCIM_API_TOKEN` is set in runtime environment.
- **Data disappears after restart**: configure persistent volume and `SCIM_DATA_DIR`.
- **IdP connector test fails**: confirm base URL uses `/scim/v2` and bearer token matches runtime token.

## IdP Integration Hints

- **Okta:** Base URL `http://<host>:8080/scim/v2`, auth header `Bearer <SCIM_API_TOKEN>`.
- **SailPoint:** Base URL `http://<host>:8080/scim/v2`, bearer token auth.
- **Azure AD:** Tenant URL `http://<host>:8080/scim/v2`, secret token `SCIM_API_TOKEN`.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SCIM implementation details: [../../backend/internal/protocols/scim/README.md](../../backend/internal/protocols/scim/README.md)
- Gateway service docs: [gateway.md](gateway.md)
