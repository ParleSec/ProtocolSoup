# protocolsoup-federation

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-federation`
- **Purpose:** Run OAuth 2.0, OpenID Connect, SAML 2.0, OID4VCI, and OID4VP endpoints in one service runtime.
- **Topology role:** Core protocol service; can run standalone or behind `protocolsoup-gateway`.

## Runtime Contract

### Ports

- `8080/tcp`: protocol endpoints, API index, and health checks.

### Dependencies

- No external database is required for a development/demo run.
- Production requires a reachable TLS-protected Redis service for atomic
  `private_key_jwt` assertion replay reservations.
- Optional companion services:
  - `protocolsoup-gateway` for unified routing.
  - `protocolsoup-wallet` for OID4VP wallet callback automation.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHOWCASE_LISTEN_ADDR` | No | `:8080` | Listen address |
| `SHOWCASE_BASE_URL` | No | `http://localhost:8080` | Public issuer/base URL used in tokens and endpoint URLs; use HTTPS to enable RFC 8414 metadata |
| `SHOWCASE_CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins |
| `SHOWCASE_ENV` | No | `development` | Runtime environment label |
| `SHOWCASE_MOCK_IDP` | No | `true` | Enable built-in mock identity provider |
| `SHOWCASE_DATA_DIR` | No | `(none)` | Enables durable VC wallet-credential and verifier-session persistence |
| `OAUTH2_REPLAY_REDIS_URL` | Demo and production | In-memory in development/tests | Shared Redis URL for atomic client-assertion replay protection. Production requires `rediss://`; demo and production fail startup if the store is missing or unreachable. Also backs the RFC 9449 DPoP proof `jti` replay stores for both oauth2 and OID4VCI (distinct key prefix and instance from the `private_key_jwt` store). |
| `SHOWCASE_DPOP_NONCE_REQUIRED` | No | `false` | Enables the RFC 9449 §8 server-provided nonce challenge at oauth2's `/oauth2/token` and OID4VCI's own `/oid4vci/token`. |
| `SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED` | No | `false` | Enables the same challenge, independently, at OID4VCI's resource-server endpoints (`/oid4vci/credential`, `/oid4vci/nonce`, `/oid4vci/deferred_credential`). |
| `MOCKIDP_ALICE_PASSWORD` | No | `(auto-generated)` | Demo user password override |
| `MOCKIDP_BOB_PASSWORD` | No | `(auto-generated)` | Demo user password override |
| `MOCKIDP_ADMIN_PASSWORD` | No | `(auto-generated)` | Demo user password override |
| `MOCKIDP_DEMO_CLIENT_SECRET` | No | `(auto-generated)` | OAuth/OIDC demo-app client secret override |
| `MOCKIDP_MACHINE_CLIENT_SECRET` | No | `(auto-generated)` | OAuth machine-client secret override |

### Storage And Volumes

- Stateless by default.
- If `SHOWCASE_DATA_DIR` is set, mount a persistent volume (for example `/app/data`) to keep VC-related state across restarts.

### Health And Readiness

- `GET /health` returns runtime health.
- `GET /api` returns protocol and endpoint index metadata.
- Container healthchecks typically probe `/health`.

## API Surface

### Health And Index

- `GET /health`
- `GET /api`

### OAuth 2.0

- `GET|POST /oauth2/authorize`
- `POST /oauth2/token`
- `GET /.well-known/oauth-authorization-server/oauth2`
- `POST /oauth2/introspect`
- `POST /oauth2/revoke`
- `GET /oauth2/demo/users`
- `GET /oauth2/demo/clients`
- `POST /oauth2/demo/clients/machine-client-pkjwt/jwks`
- `POST /oauth2/demo/caep/revoke-subject` (SSF receiver CAEP hook; bearer `SSF_TO_FEDERATION_TOKEN`)

The OAuth token endpoint supports `private_key_jwt` for the
`client_credentials` grant with RS256, ES256, and EdDSA assertions. The
browser registration endpoint requires the session's one-time-returned owner
capability, accepts one public JWK Set while the session is active, creates the
real isolated client ID, expires it after 10 minutes, and returns the exact
token endpoint audience. There is no seeded `private_key_jwt` client. RSA keys
must use an odd modulus of at least 2048 bits and a valid odd exponent.
Production replay reservations are globally atomic in Redis through the
assertion's `exp` plus skew; store outages fail closed. Authorization server
metadata is emitted only when `SHOWCASE_BASE_URL` is a pathless HTTPS origin,
as RFC 8414 and the root-mounted route topology require.

The token endpoint also accepts an optional `DPoP` proof header (RFC 9449).
When present and valid, the issued access token is bound to the proof's key
via a `cnf.jkt` claim and the response's `token_type` is `DPoP` instead of
`Bearer`; for the `authorization_code` grant, a DPoP-bound token issued to a
public client also binds the issued refresh token to the same key. Absent
that header, every Bearer flow is unchanged. Metadata advertises the
accepted proof algorithms under `dpop_signing_alg_values_supported`.

### OpenID Connect

- `GET /oidc/.well-known/openid-configuration`
- `GET /oidc/.well-known/jwks.json`
- `GET /oidc/authorize`
- `POST /oidc/token`
- `GET|POST /oidc/userinfo`

### SAML 2.0

- `GET /saml/metadata`
- `GET|POST /saml/sso`
- `GET|POST /saml/acs`
- `GET|POST /saml/slo`
- `GET /saml/demo/users`

### Verifiable Credentials (Mounted Modules)

- `GET /.well-known/openid-credential-issuer/oid4vci`
- `POST /oid4vci/*`
- `POST /oid4vp/request/create`
- `GET|POST /oid4vp/request/{requestID}`
- `GET /oid4vp/verifier-attestation/.well-known/openid-configuration`
- `GET /oid4vp/verifier-attestation/.well-known/oauth-authorization-server`
- `GET /oid4vp/verifier-attestation/jwks`
- `POST /oid4vp/response`
- `GET /oid4vp/result/{requestID}`

## Quick Start

### docker run

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SHOWCASE_DATA_DIR=/app/data \
  -v federation-data:/app/data \
  ghcr.io/parlesec/protocolsoup-federation:latest
```

### docker compose snippet

```yaml
services:
  federation-service:
    image: ghcr.io/parlesec/protocolsoup-federation:latest
    ports:
      - "8080:8080"
    environment:
      - SHOWCASE_BASE_URL=http://localhost:8080
      - SHOWCASE_DATA_DIR=/app/data
    volumes:
      - federation-data:/app/data
```

## Security Hardening

- Set `SHOWCASE_BASE_URL` to your external HTTPS origin.
- Keep `SHOWCASE_BASE_URL` pathless and omit a trailing slash.
- Set `OAUTH2_REPLAY_REDIS_URL` to a platform-managed `rediss://` secret in production.
- Restrict `SHOWCASE_CORS_ORIGINS` to trusted production origins.
- Override autogenerated mock credentials in shared environments.
- Keep services on private networks when fronted by a gateway or reverse proxy.
- Persist VC state (`SHOWCASE_DATA_DIR`) on protected storage if replay/audit continuity matters.

## Troubleshooting

- **OIDC discovery issuer mismatch:** ensure `SHOWCASE_BASE_URL` matches the URL clients call.
- **Login succeeds but client exchange fails:** verify demo client secret via `/oauth2/demo/clients`.
- **OID4VP result not found after restart:** configure persistent `SHOWCASE_DATA_DIR`.
- **Browser CORS errors:** check `SHOWCASE_CORS_ORIGINS` includes the frontend origin.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- API contract: [../../openapi/v1/federation.yaml](../../openapi/v1/federation.yaml)
- OID4VCI module notes: [oid4vci.md](oid4vci.md)
- OID4VP module notes: [oid4vp.md](oid4vp.md)
- Standalone VC service: [vc.md](vc.md)
