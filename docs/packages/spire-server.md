# protocolsoup-spire-server

**SPIRE Server - Certificate Authority for Workload Identity**

Issues X.509-SVIDs and JWT-SVIDs for the `spiffe://protocolsoup.com` trust domain.

## Quick Start

```bash
docker run -d \
  -v spire-data:/opt/spire/data/server \
  -v spire-socket:/run/spire/sockets \
  --name spire-server \
  ghcr.io/parlesec/protocolsoup-spire-server
```

## Ports

| Port | Description |
|------|-------------|
| `8081` | SPIRE Server API (agent connections, registration) |
| `8443` | Federation bundle endpoint (HTTPS) |

## Volumes

| Path | Description |
|------|-------------|
| `/opt/spire/data/server` | Server data (keys, database) |
| `/run/spire/sockets` | Unix socket for local CLI |

## Health Check

```bash
docker exec spire-server \
  /opt/spire/bin/spire-server healthcheck \
  -socketPath /run/spire/sockets/server.sock
```

## Generate Join Token

For agents to connect, generate a join token:

```bash
docker exec spire-server \
  /opt/spire/bin/spire-server token generate \
  -socketPath /run/spire/sockets/server.sock \
  -spiffeID spiffe://protocolsoup.com/agent/main
```

## Register Workload Entry

```bash
docker exec spire-server \
  /opt/spire/bin/spire-server entry create \
  -socketPath /run/spire/sockets/server.sock \
  -parentID spiffe://protocolsoup.com/agent/main \
  -spiffeID spiffe://protocolsoup.com/workload/myapp \
  -selector docker:label:app:myapp
```

## Docker Compose

```yaml
services:
  spire-server:
    image: ghcr.io/parlesec/protocolsoup-spire-server
    volumes:
      - spire-server-data:/opt/spire/data/server
      - spire-server-socket:/run/spire/sockets
    healthcheck:
      test: ["/opt/spire/bin/spire-server", "healthcheck", "-socketPath", "/run/spire/sockets/server.sock"]
      interval: 30s
      timeout: 10s
      start_period: 15s

volumes:
  spire-server-data:
  spire-server-socket:
```

## Configuration

The server is pre-configured for the `protocolsoup.com` trust domain with:
- In-memory datastore (for demos)
- Join token node attestation
- 1-hour SVID TTL
- RSA-2048 CA key

## Use With

- `protocolsoup-spire-agent` - Standalone agent
- `protocolsoup-spiffe` - Service with embedded agent
- `protocolsoup-spire-registration` - Bootstrap workload entries
