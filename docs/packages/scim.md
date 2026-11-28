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
| `SCIM_AS_JWKS_URI` | When no authorization server runs in the process | `(none)` | JWK Set URL of the authorization server that issues the access tokens. The standalone image does not start without it. The monolith validates in process and leaves it unset. |
| `SCIM_AS_ISSUER` | No | `{SHOWCASE_BASE_URL}/oauth2` | Issuer identifier the access token's `iss` must equal (RFC 9068 Section 4) |
| `SCIM_RESOURCE` | No | `{SHOWCASE_BASE_URL}/scim/v2` | Resource indicator the access token's `aud` must contain. Set the same value on the federation service when it differs from the default. |
| `SCIM_AS_INTROSPECT_URI` | No | `(none)` | RFC 7662 introspection endpoint. When set, the split service asks it whether each token is still active, so a revoked token is refused before it expires. |
| `SCIM_AS_INTROSPECT_CLIENT_SECRET` | With `SCIM_AS_INTROSPECT_URI` | `(none)` | Secret for authenticating to introspection as the resource server registration `scim-service-provider`. Must equal `SCIM_SERVICE_PROVIDER_CLIENT_SECRET` on the federation service. |
| `SCIM_DATA_DIR` | No | `./data` (container default path resolves to `/app/data`) | SQLite storage directory |
| `SCIM_RETENTION` | No | `24h` | How long visitor-created users and groups are kept, based on `updated_at`. `0` disables deletion. Each sweep re-seeds demo data. |
| `SCIM_LOOKING_GLASS` | No | `true` | Enable Looking Glass capture for SCIM events |

### Storage And Volumes

- Persist SCIM data by mounting a volume to the storage directory.
- Recommended container mount: `-v scim-data:/app/data` with `SCIM_DATA_DIR=/app/data`.

### Health And Readiness

- `GET /health` returns service health and per-plugin lifecycle state.
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
- `POST /scim/v2/.search`, `POST /scim/v2/Users/.search`, `POST /scim/v2/Groups/.search`
- `GET /scim/v2` — query Users and Groups together

### Outbound Client Endpoints

- `POST /scim/client/provision` creates a single user on an external target.
- `POST /scim/client/sync` discovers an external target and reconciles every local user.
- Both endpoints require an access token that grants `scim.write`, and accept the exact target SCIM base URL plus the bearer token for that target.
- Server-managed attributes (`id`, `meta`, `groups`, `password`) are always stripped before forwarding; the source id is preserved as `externalId`.
- Successful source-to-target ID mappings from `sync` are persisted in SQLite and reused as `PUT` targets on later runs.
- `200` means every user succeeded; `sync` returns `207` when it includes per-user failures.
- The operation is intentionally one-way and never deletes remote users without an explicit deprovisioning policy.
- In production, target URLs must use HTTPS and must not resolve to a loopback, private, or link-local address (SSRF hardening).

## Quick Start

### docker run

```bash
docker run -p 8081:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8081 \
  -e SCIM_AS_ISSUER=http://localhost:8080/oauth2 \
  -e SCIM_AS_JWKS_URI=http://host.docker.internal:8080/api/.well-known/jwks.json \
  -e SCIM_DATA_DIR=/app/data \
  -v scim-data:/app/data \
  ghcr.io/parlesec/protocolsoup-scim:latest
```

This runs the service provider beside a federation service on port 8080, which issues the access tokens. Start that service with `SCIM_RESOURCE=http://localhost:8081/scim/v2` so the tokens it issues for `scim.read` and `scim.write` name this service provider in `aud`. The Compose stack wires both for you.

### docker compose snippet

```yaml
services:
  scim-service:
    image: ghcr.io/parlesec/protocolsoup-scim:latest
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SCIM_AS_JWKS_URI=http://federation-service:8080/api/.well-known/jwks.json
      - SCIM_AS_INTROSPECT_URI=http://federation-service:8080/oauth2/introspect
      - SCIM_AS_INTROSPECT_CLIENT_SECRET=${SCIM_SERVICE_PROVIDER_CLIENT_SECRET}
      - SCIM_DATA_DIR=/app/data
    volumes:
      - scim-data:/app/data
```

## Security Hardening

- Every endpoint except `GET /scim/v2/ServiceProviderConfig` requires an OAuth 2.0 access token in every environment; there is no unauthenticated mode and no static token. RFC 7644 Section 7.4 requires bearer tokens to have a limited lifetime.
- The service does not start unless it can validate tokens: in the monolith the authorization server is in the process, and the standalone image needs `SCIM_AS_JWKS_URI`.
- Set `SCIM_AS_INTROSPECT_URI` on the standalone image so a revoked token is refused before it expires.
- `/scim/client/*` needs the `scim.write` scope; use HTTPS target URLs in production.
- `/scim/client/*` target URLs are rejected in production if they resolve to a loopback, private, or link-local address, preventing use of the endpoints for SSRF against internal infrastructure.
- Use HTTPS at the edge between IdP and SCIM endpoint.
- Restrict `SHOWCASE_CORS_ORIGINS` to trusted origins.
- Persist data to a managed volume and protect that volume as sensitive identity state.
- Pin `SCIM_CLIENT_SECRET` on the federation service as a secret and rotate it on a regular cadence.

| Hosted instance | Not for real identity data |
| --- | --- |
| Visitors may create users and groups. Records older than `SCIM_RETENTION` (default 24h) are deleted and demo data is restored. Do not send real employee or customer records to the hosted instance. |

## Troubleshooting

- **`401` with `WWW-Authenticate: Bearer realm="scim"`**: the request carried no bearer access token. Request one from `/oauth2/token` as `scim-client`.
- **`401` with `error="invalid_token"`**: read `error_description`. The token is expired or revoked, was issued by another issuer (`SCIM_AS_ISSUER`), or its `aud` is not the SCIM base URI (`SCIM_RESOURCE`).
- **`403` with `error="insufficient_scope"`**: the challenge's `scope` names the scope the request needs (`scim.read` or `scim.write`).
- **Service exits with `SCIM_AS_JWKS_URI is required`**: the standalone image has no authorization server; point it at the federation service's JWK Set.
- **Data disappears after restart**: configure persistent volume and `SCIM_DATA_DIR`.
- **IdP connector test fails**: confirm the base URL uses `/scim/v2` and that the connector sends an access token issued by the configured authorization server.

## IdP Integration Hints

- Base URL: `http(s)://<host>/scim/v2`.
- The connector must authenticate with OAuth 2.0: it obtains an access token from the authorization server (`SCIM_AS_ISSUER`) with the `scim.read` and `scim.write` scopes and sends it as `Authorization: Bearer`.
- A connector mode that sends one fixed header value or "secret token" forever does not work: this service provider accepts no static secret (RFC 7644 Section 7.4).

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SCIM implementation details: [../../backend/internal/protocols/scim/README.md](../../backend/internal/protocols/scim/README.md)
- Gateway service docs: [gateway.md](gateway.md)
