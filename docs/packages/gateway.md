# protocolsoup-gateway

**API Gateway for ProtocolSoup microservices**

Routes requests to protocol-specific backend services and aggregates their APIs.

## Quick Start

```bash
docker run -p 8080:8080 \
  -e FEDERATION_SERVICE_URL=http://federation:8080 \
  -e SCIM_SERVICE_URL=http://scim:8080 \
  -e SSF_SERVICE_URL=http://ssf:8080 \
  ghcr.io/parlesec/protocolsoup-gateway
```

**Requires:** At least one upstream service running

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Gateway health |
| `GET /health/upstreams` | Upstream service status |
| `GET /api/protocols` | Aggregated protocol list |
| `WS /ws/lookingglass/{session}` | Real-time protocol inspection |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FEDERATION_SERVICE_URL` | (empty) | OAuth/OIDC/SAML service URL |
| `SCIM_SERVICE_URL` | (empty) | SCIM service URL |
| `SSF_SERVICE_URL` | (empty) | SSF service URL |
| `SPIFFE_SERVICE_URL` | (empty) | SPIFFE service URL |
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Public URL for generated links |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Listen address |
| `GATEWAY_REFRESH_INTERVAL` | `30s` | Protocol refresh interval |
| `GATEWAY_STARTUP_RETRY_INITIAL` | `2s` | Initial startup retry delay |
| `GATEWAY_STARTUP_RETRY_MAX` | `30s` | Maximum startup retry delay |
| `GATEWAY_REQUEST_TIMEOUT` | `5s` | Upstream request timeout |

## Architecture

```
┌─────────────┐     ┌─────────────────────┐
│   Client    │---->│       Gateway       │
└─────────────┘     │    (this image)     │
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Federation    │  │      SCIM       │  │       SSF       │
│  /oauth2, /oidc │  │    /scim/v2     │  │      /ssf       │
│     /saml       │  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Docker Compose Example

```yaml
services:
  gateway:
    image: ghcr.io/parlesec/protocolsoup-gateway
    ports:
      - "8080:8080"
    environment:
      - FEDERATION_SERVICE_URL=http://federation:8080
      - SCIM_SERVICE_URL=http://scim:8080
    depends_on:
      - federation
      - scim
```
