# `protocolsoup-<service>`

Use this template for all GHCR service pages under `docs/packages`.

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-<service>`
- **Purpose:** One-sentence service description.
- **Topology role:** Explain where it sits in a typical deployment (standalone, behind gateway, companion services).

## Runtime Contract

### Ports

- List all listening ports and what each port serves.

### Dependencies

- List required upstreams, shared networks, or external services.

### Environment Variables

Use this structure:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EXAMPLE_ENV` | Yes/No | `value` or `(none)` | What it controls |

### Storage And Volumes

- Document persistence paths and recommended volume mounts.

### Health And Readiness

- Health endpoint(s) and expected status behavior.
- Docker healthcheck command assumptions.

## API Surface

- List major endpoint groups and the most important operations.
- Link to deeper protocol/API reference docs where relevant.

## Quick Start

### `docker run`

```bash
# Minimal runnable example
docker run -p 8080:8080 ghcr.io/parlesec/protocolsoup-<service>:latest
```

### `docker compose` Snippet

```yaml
services:
  <service>:
    image: ghcr.io/parlesec/protocolsoup-<service>:latest
    # ...
```

## Security Hardening

- Production auth requirements.
- Network exposure guidance.
- Secret management expectations.
- TLS and CORS considerations.

## Troubleshooting

- Common failure signatures.
- Likely causes.
- Fast checks and fixes.

## Versioning And Tags

- `latest`: default moving tag.
- `sha-*`: immutable commit-derived tag.
- `vX.Y.Z` and `vX.Y`: release tags when published from tagged releases.
- See `ghcr-publish.yml` for the exact publishing matrix and tag generation behavior.

## Related Docs

- Link to:
  - package index (`docs/packages/README.md`)
  - relevant protocol docs (`backend/internal/protocols/*/README.md`)
  - architecture and deployment docs where helpful.
