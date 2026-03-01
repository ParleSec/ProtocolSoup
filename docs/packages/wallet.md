# protocolsoup-wallet

**OID4VP wallet harness for callback submission and wallet bootstrap**

Wallet-side helper service for OpenID4VP flows. It accepts a request object, prepares a wallet response, and submits it to the verifier callback.

## Quick Start

```bash
docker run -p 8081:8080 \
  -e WALLET_TARGET_BASE_URL=http://host.docker.internal:8080 \
  ghcr.io/parlesec/protocolsoup-wallet
```

> `WALLET_TARGET_BASE_URL` should point to your VC verifier/issuer service (for example `protocolsoup-vc`).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | `GET` | Health check |
| `/submit` | `POST` | Submit wallet response for OID4VP request |

## `/submit` Request Payload

```json
{
  "request_id": "request-id",
  "request": "signed-request-object-jwt",
  "wallet_subject": "did:example:wallet:alice",
  "credential_jwt": "optional-issuer-credential-jwt"
}
```

## Runtime Behavior

- If `credential_jwt` is provided, wallet binds and uses it.
- If missing, wallet can bootstrap by obtaining a real OID4VCI credential from the target VC service.
- If cached credential is stale/near expiry, wallet refreshes it before OID4VP submission.
- Supports `direct_post` and `direct_post.jwt`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WALLET_LISTEN_ADDR` | `:8080` | Listen address |
| `WALLET_TARGET_BASE_URL` | `https://protocolsoup.com` | Verifier/issuer base URL |
| `WALLET_DEFAULT_SUBJECT` | `did:example:wallet:alice` | Fallback wallet subject |
| `WALLET_ALLOWED_CORS_ORIGINS` | `https://protocolsoup.com,...` | CORS allow-list |
| `WALLET_HTTP_TIMEOUT` | `15s` | Upstream request timeout |
