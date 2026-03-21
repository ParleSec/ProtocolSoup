# protocolsoup-spire-agent

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-spire-agent`
- **Purpose:** Run SPIRE Agent for node/workload attestation and provide Workload API sockets to workloads.
- **Topology role:** Identity-plane runtime that bridges workload processes to SPIRE Server trust data.

## Runtime Contract

### Ports

- No public TCP port is required for normal operation.
- Agent Workload API is provided via Unix socket (`/run/spire/sockets/agent.sock`).

### Dependencies

- Requires `protocolsoup-spire-server` socket access for bootstrap and trust synchronization.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `(none)` | N/A | N/A | Runtime behavior is defined by embedded bootstrap script and mounted SPIRE config |

### Storage And Volumes

- `/run/spire/sockets/server` (read-only): SPIRE Server socket mount.
- `/run/spire/sockets`: agent socket output mount (`agent.sock` for workloads).
- `/opt/spire/data/agent`: agent state (bundle cache and attestation artifacts).

### Health And Readiness

- Container healthcheck runs:
  - `/opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock`
- Bootstrap script waits for server socket and generates join token before launching agent runtime.

## API Surface

- Exposes SPIFFE Workload API over Unix socket:
  - X.509-SVID retrieval
  - JWT-SVID retrieval
  - trust-bundle access
  - rotation watch streams

## Quick Start

### docker run

```bash
docker run -d --name spire-agent \
  -v spire-server-socket:/run/spire/sockets/server:ro \
  -v spire-agent-socket:/run/spire/sockets \
  -v spire-agent-data:/opt/spire/data/agent \
  ghcr.io/parlesec/protocolsoup-spire-agent:latest
```

### docker compose snippet

```yaml
services:
  spire-agent:
    image: ghcr.io/parlesec/protocolsoup-spire-agent:latest
    depends_on:
      spire-server:
        condition: service_healthy
    volumes:
      - spire-server-socket:/run/spire/sockets/server:ro
      - spire-agent-socket:/run/spire/sockets
      - spire-agent-data:/opt/spire/data/agent
```

## Security Hardening

- Restrict socket volume access to trusted workloads only.
- Keep agent and server on isolated, private networks.
- Rotate join tokens and remove unused registration entries.
- Audit which workloads can mount `agent.sock`.

## Troubleshooting

- **Agent never becomes healthy:** verify server socket mount path and server health.
- **Workload cannot get SVID:** confirm workload has access to `/run/spire/sockets/agent.sock`.
- **Bootstrap loop/re-attestation churn:** inspect persistent agent data volume and token generation path.
- **Windows Docker socket issues:** prefer compose-managed SPIRE stack.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SPIRE server image: [spire-server.md](spire-server.md)
- SPIFFE service image: [spiffe.md](spiffe.md)
