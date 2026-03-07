# protocolsoup-vc

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-vc`
- **Purpose:** Run standalone OID4VCI issuer and OID4VP verifier APIs without the broader federation protocol set.
- **Topology role:** VC-focused backend service, optionally paired with `protocolsoup-wallet` for wallet simulation and callback submission.

## Runtime Contract

### Ports

- `8080/tcp`: VC API endpoints, health, and API index.

### Dependencies

- No external database required for basic operation.
- Optional companion services:
  - `protocolsoup-wallet` for automated OID4VP wallet submission.
  - `protocolsoup-gateway` if you want a single frontend routing entrypoint.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Public base URL used in issuer metadata and verifier request objects |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SHOWCASE_ENV` | No | `development` | Runtime environment label |
| `SHOWCASE_MOCK_IDP` | No | `true` | Enable built-in mock identity data |
| `SHOWCASE_DATA_DIR` | No | `(none)` | Durable persistence root for wallet lineage and verifier session state |
| `VC_LOOKING_GLASS` | No | `true` | Enable Looking Glass event capture |

### Storage And Volumes

- In-memory by default.
- Set `SHOWCASE_DATA_DIR` and mount a volume (for example `/app/data`) to persist wallet-credential lineage and verifier-result continuity across restarts.

### Health And Readiness

- `GET /health` returns runtime health.
- `GET /api` returns protocol and endpoint index metadata.
- Container healthchecks typically probe `/health`.

## API Surface

### Health And Index

- `GET /health`
- `GET /api`

### OID4VCI (Issuer)

- `GET /.well-known/openid-credential-issuer/oid4vci`
- `GET /oid4vci/.well-known/openid-credential-issuer`
- `GET /oid4vci/credential-offer/{offerID}`
- `POST /oid4vci/offers/pre-authorized`
- `POST /oid4vci/offers/pre-authorized/by-value`
- `POST /oid4vci/offers/pre-authorized/deferred`
- `POST /oid4vci/token`
- `POST /oid4vci/nonce`
- `POST /oid4vci/credential`
- `POST /oid4vci/deferred_credential`

### OID4VP (Verifier)

- `POST /oid4vp/request/create`
- `GET|POST /oid4vp/request/{requestID}`
- `POST /oid4vp/response`
- `GET /oid4vp/result/{requestID}`

## Quick Start

### docker run

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SHOWCASE_DATA_DIR=/app/data \
  -v vc-data:/app/data \
  ghcr.io/parlesec/protocolsoup-vc:latest
```

### docker compose snippet

```yaml
services:
  vc-service:
    image: ghcr.io/parlesec/protocolsoup-vc:latest
    ports:
      - "8080:8080"
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SHOWCASE_DATA_DIR=/app/data
    volumes:
      - vc-data:/app/data
```

## Security Hardening

- Set `SHOWCASE_BASE_URL` to your external HTTPS origin.
- Restrict `SHOWCASE_CORS_ORIGINS` to trusted origins only.
- Keep wallet and verifier services on private networks when possible.
- Persist `SHOWCASE_DATA_DIR` on protected storage if you need auditable lineage continuity.

## Troubleshooting

- **Wallet `/submit` fails with callback mismatch:** verify wallet `WALLET_TARGET_BASE_URL` exactly matches this VC base URL.
- **OID4VP result disappears after restart:** configure persistent `SHOWCASE_DATA_DIR`.
- **Nonce/proof validation failures:** ensure wallet proof uses the latest `c_nonce`.
- **CORS failures in browser tooling:** check `SHOWCASE_CORS_ORIGINS`.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- API contract: [../../openapi/v1/vc.yaml](../../openapi/v1/vc.yaml)
- Wallet harness: [wallet.md](wallet.md)
- OID4VCI module notes: [oid4vci.md](oid4vci.md)
- OID4VP module notes: [oid4vp.md](oid4vp.md)
