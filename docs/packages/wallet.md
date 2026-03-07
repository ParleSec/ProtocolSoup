# protocolsoup-wallet

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-wallet`
- **Purpose:** Act as an external wallet harness for OID4VP demos, including optional OID4VCI bootstrap and callback submission.
- **Topology role:** Companion service for `protocolsoup-vc` or federation VC endpoints; called by UI/external tooling, then relays to verifier callbacks.

## Runtime Contract

### Ports

- `8080/tcp` (commonly mapped to host `8081`): wallet harness API.

### Dependencies

- Requires a reachable VC target (`WALLET_TARGET_BASE_URL`) exposing OID4VCI and OID4VP endpoints.
- Target host and callback URI are strictly validated against configured base URL.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WALLET_LISTEN_ADDR` | No | `:8080` | Listen address |
| `WALLET_TARGET_BASE_URL` | Yes | `https://protocolsoup.com` | Trusted verifier/issuer base URL |
| `WALLET_DEFAULT_SUBJECT` | No | `did:example:wallet:alice` | Default wallet subject root |
| `WALLET_SESSION_TTL` | No | `20m` | In-memory wallet material TTL |
| `WALLET_STRICT_SESSION_ISOLATION` | No | `true` | Require request/session scoping key for wallet isolation |
| `WALLET_ALLOWED_CORS_ORIGINS` | No | `https://protocolsoup.com,https://www.protocolsoup.com,https://protocolsoup.fly.dev` | CORS allow-list |
| `WALLET_HTTP_TIMEOUT` | No | `15s` | Upstream request timeout |

### Storage And Volumes

- No disk persistence; wallet key material and credential cache are in-memory per scope key.
- Session-scoped wallet entries expire based on `WALLET_SESSION_TTL`.

### Health And Readiness

- `GET /health` returns service status.
- Readiness depends on VC target reachability when `/submit` is used.

## API Surface

- `GET /health`
- `POST /submit`
  - Supports `mode=one_click` (default)
  - Supports `mode=stepwise` with steps: `bootstrap`, `issue_credential`, `build_presentation`, `submit_response`

## Quick Start

### docker run

```bash
docker run -p 8081:8080 \
  -e WALLET_TARGET_BASE_URL=http://host.docker.internal:8080 \
  -e WALLET_ALLOWED_CORS_ORIGINS=http://localhost:3000 \
  ghcr.io/parlesec/protocolsoup-wallet:latest
```

### docker compose snippet

```yaml
services:
  wallet:
    image: ghcr.io/parlesec/protocolsoup-wallet:latest
    ports:
      - "8081:8080"
    environment:
      - WALLET_TARGET_BASE_URL=http://vc-service:8080
      - WALLET_ALLOWED_CORS_ORIGINS=http://localhost:3000
```

## Security Hardening

- Keep `WALLET_STRICT_SESSION_ISOLATION=true` outside debug scenarios.
- Set a narrow `WALLET_ALLOWED_CORS_ORIGINS` list.
- Place wallet and VC services on private networks; expose only required ingress.
- Rotate and monitor upstream credentials and trust boundaries at the VC target.

## Troubleshooting

- **`session isolation key is required`:** supply `looking_glass_session_id` or `request_id` in `/submit`.
- **`response_uri ... does not match trusted verifier callback`:** request object callback does not match `WALLET_TARGET_BASE_URL`.
- **`credential_jwt sub does not match wallet_subject`:** provided credential is bound to a different holder.
- **Upstream timeout/failure:** check `WALLET_HTTP_TIMEOUT` and VC target health.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- VC service docs: [vc.md](vc.md)
- Federation service docs: [federation.md](federation.md)
