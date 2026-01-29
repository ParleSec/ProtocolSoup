# protocolsoup-spire-registration

**SPIRE Workload Registration - Bootstrap Container**

One-shot container that registers default workload entries on SPIRE Server. Runs once and exits.

## Quick Start

```bash
docker run --rm \
  -v spire-server-socket:/run/spire/sockets:ro \
  ghcr.io/parlesec/protocolsoup-spire-registration
```

**Requires:** `protocolsoup-spire-server` healthy

## Registered Entries

This container creates the following workload entries:

| SPIFFE ID | Selector | Description |
|-----------|----------|-------------|
| `spiffe://protocolsoup.com/workload/backend` | `docker:label:app:protocol-backend` | Main backend service |
| `spiffe://protocolsoup.com/workload/demo-client` | `docker:label:app:demo-client` | Demo client workload |
| `spiffe://protocolsoup.com/workload/demo-service` | `docker:label:app:demo-service` | Demo service workload |

## Docker Compose

```yaml
services:
  spire-registration:
    image: ghcr.io/parlesec/protocolsoup-spire-registration
    depends_on:
      spire-server:
        condition: service_healthy
      spire-agent:
        condition: service_healthy
    volumes:
      - spire-server-socket:/run/spire/sockets:ro
    restart: "no"  # Run once and exit
```

## Volumes

| Path | Description |
|------|-------------|
| `/run/spire/sockets` | SPIRE Server socket (read-only) |

## Behavior

1. Waits for SPIRE Server to be healthy
2. Creates workload entries via `spire-server entry create`
3. Exits with code 0 on success

## Custom Entries

To register custom workloads, run commands against the SPIRE Server directly:

```bash
docker exec spire-server \
  /opt/spire/bin/spire-server entry create \
  -socketPath /run/spire/sockets/server.sock \
  -parentID spiffe://protocolsoup.com/agent/main \
  -spiffeID spiffe://protocolsoup.com/workload/custom \
  -selector docker:label:app:custom-app
```

## Platform Notes

### Windows Docker

When running on Windows with Docker Desktop, **use Docker Compose instead of standalone `docker run`** for SPIRE containers. Windows Docker has limitations with Unix socket volumes that can prevent proper socket sharing.

**Recommended approach:**
```bash
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

The standalone `docker run` commands work correctly on Linux and macOS.

## Use With

Use this container as part of the full SPIFFE stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

The registration container runs after SPIRE Server/Agent are healthy and then exits.
