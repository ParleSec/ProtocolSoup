# protocolsoup-spire-registration

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-spire-registration`
- **Purpose:** Run one-shot SPIRE workload registration bootstrap against the SPIRE server socket.
- **Topology role:** Initialization helper in SPIFFE stack startup; exits after creating baseline entries.

## Runtime Contract

### Ports

- None.

### Dependencies

- Requires SPIRE Server socket mounted at `/run/spire/sockets/server.sock`.
- Typically run after `protocolsoup-spire-server` (and often `protocolsoup-spire-agent`) are healthy.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `(none)` | N/A | N/A | Behavior is defined by embedded registration script |

### Storage And Volumes

- `/run/spire/sockets` (read-only): provides SPIRE Server socket access for registration CLI calls.
- No persistent local state is stored by this container.

### Health And Readiness

- No long-running health endpoint.
- Success criteria: container exits with code `0` after registering entries.

## API Surface

- No HTTP API.
- Executes `spire-server entry create` commands against server socket.

## Quick Start

### docker run

```bash
docker run --rm \
  -v spire-server-socket:/run/spire/sockets:ro \
  ghcr.io/parlesec/protocolsoup-spire-registration:latest
```

### docker compose snippet

```yaml
services:
  spire-registration:
    image: ghcr.io/parlesec/protocolsoup-spire-registration:latest
    depends_on:
      spire-server:
        condition: service_healthy
    volumes:
      - spire-server-socket:/run/spire/sockets:ro
    restart: "no"
```

## Registered Workload Entries

- `spiffe://protocolsoup.com/workload/backend`
- `spiffe://protocolsoup.com/workload/demo-client`
- `spiffe://protocolsoup.com/workload/demo-service`

All default entries in the bootstrap script use selector `unix:uid:0` under parent `spiffe://protocolsoup.com/agent/main`.

## Security Hardening

- Keep registration container ephemeral and run only during controlled bootstrap windows.
- Restrict socket access to trusted bootstrap jobs.
- Audit and prune stale registration entries after topology changes.

## Troubleshooting

- **`Server socket not available`:** ensure SPIRE server volume mount and readiness.
- **Entries not created but container exits:** inspect container logs for "Entry may already exist" and list current entries manually.
- **Workload attestation mismatch:** verify selectors in registration entries match actual runtime workload selectors.
- **Windows Docker socket issues:** prefer compose-managed SPIRE startup.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SPIRE server image: [spire-server.md](spire-server.md)
- SPIRE agent image: [spire-agent.md](spire-agent.md)
- SPIFFE service image: [spiffe.md](spiffe.md)
