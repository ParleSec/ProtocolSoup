# protocolsoup-spire-agent

**SPIRE Agent - Workload Attestation**

Connects to SPIRE Server, performs workload attestation, and exposes Workload API socket for applications to fetch SVIDs.

## Quick Start

```bash
docker run -d \
  -v spire-server-socket:/run/spire/sockets/server:ro \
  -v spire-agent-socket:/run/spire/sockets \
  -v spire-agent-data:/opt/spire/data/agent \
  --name spire-agent \
  ghcr.io/parlesec/protocolsoup-spire-agent
```

**Requires:** `protocolsoup-spire-server` running and healthy

## Volumes

| Path | Description |
|------|-------------|
| `/run/spire/sockets/server` | SPIRE Server socket (read-only) |
| `/run/spire/sockets` | Agent socket (expose to workloads) |
| `/opt/spire/data/agent` | Agent data (bundle cache) |

## Health Check

```bash
docker exec spire-agent \
  /opt/spire/bin/spire-agent healthcheck \
  -socketPath /run/spire/sockets/agent.sock
```

## Docker Compose

```yaml
services:
  spire-agent:
    image: ghcr.io/parlesec/protocolsoup-spire-agent
    depends_on:
      spire-server:
        condition: service_healthy
    volumes:
      - spire-server-socket:/run/spire/sockets/server:ro
      - spire-agent-socket:/run/spire/sockets
      - spire-agent-data:/opt/spire/data/agent
    healthcheck:
      test: ["/opt/spire/bin/spire-agent", "healthcheck", "-socketPath", "/run/spire/sockets/agent.sock"]
      interval: 30s
      timeout: 10s
      start_period: 45s
```

## Important Note

**For Docker deployments**, consider using `protocolsoup-spiffe` instead. It has an embedded SPIRE Agent, which avoids Unix socket attestation issues across container boundaries.

The standalone agent is useful for:
- Kubernetes deployments (DaemonSet pattern)
- VM-based deployments
- Multi-workload scenarios

## Workload API

Applications connect to `/run/spire/sockets/agent.sock` to:
- Fetch X.509-SVIDs
- Fetch JWT-SVIDs
- Watch for SVID rotation
- Get trust bundles

Example with `go-spiffe`:
```go
source, err := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(
        workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
    ),
)
```
