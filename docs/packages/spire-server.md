# protocolsoup-spire-server

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-spire-server`
- **Purpose:** Run SPIRE Server as trust-domain authority and SVID issuer for `spiffe://protocolsoup.com`.
- **Topology role:** SPIFFE control-plane root used by SPIRE agents and SPIFFE-enabled workloads.

## Runtime Contract

### Ports

- `8081/tcp`: SPIRE Server API (agent connections and registration operations).
- `8443/tcp`: federation bundle endpoint.

### Dependencies

- No external service dependency; this image includes SPIRE server runtime and config.
- Companion images usually include:
  - `protocolsoup-spire-agent`
  - `protocolsoup-spire-registration`
  - `protocolsoup-spiffe`

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `(none)` | N/A | N/A | Runtime behavior is primarily driven by mounted config and SPIRE CLI operations |

### Storage And Volumes

- `/opt/spire/data/server`: persistent server state (SQLite datastore + key material).
- `/run/spire/sockets`: local admin socket path (`server.sock`) for CLI and other containers.

### Health And Readiness

- Container healthcheck runs:
  - `/opt/spire/bin/spire-server healthcheck -socketPath /run/spire/sockets/server.sock`
- Config also enables HTTP health endpoints (`/live`, `/ready`) on internal port `8080`.

## API Surface

- SPIRE gRPC/API listener on `8081` for agent attestation and server operations.
- SPIFFE federation bundle endpoint on `8443`.
- Local admin operations via `spire-server` CLI and Unix socket (`server.sock`).

## Quick Start

### docker run

```bash
docker run -d --name spire-server \
  -v spire-server-data:/opt/spire/data/server \
  -v spire-server-socket:/run/spire/sockets \
  -p 8081:8081 \
  -p 8443:8443 \
  ghcr.io/parlesec/protocolsoup-spire-server:latest
```

### docker compose snippet

```yaml
services:
  spire-server:
    image: ghcr.io/parlesec/protocolsoup-spire-server:latest
    volumes:
      - spire-server-data:/opt/spire/data/server
      - spire-server-socket:/run/spire/sockets
    healthcheck:
      test: ["/opt/spire/bin/spire-server", "healthcheck", "-socketPath", "/run/spire/sockets/server.sock"]
      interval: 30s
      timeout: 10s
      start_period: 15s
```

## Security Hardening

- Keep socket and datastore volumes private to trusted workloads only.
- Restrict network exposure of ports `8081` and `8443`.
- Rotate join tokens and registration entries as part of environment lifecycle.
- Back up and protect server state (`datastore.sqlite3`, signing keys) as sensitive PKI material.

## Troubleshooting

- **Server healthcheck fails:** verify socket path mount and write permissions.
- **Agent attestation failures:** validate join token workflow and trust-domain consistency.
- **Federation endpoint unavailable:** check port `8443` exposure and network policy.
- **Windows Docker socket issues:** prefer compose-based SPIRE stack orchestration.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- SPIRE agent image: [spire-agent.md](spire-agent.md)
- SPIRE registration image: [spire-registration.md](spire-registration.md)
- SPIFFE service image: [spiffe.md](spiffe.md)
