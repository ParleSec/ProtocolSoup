# protocolsoup-vc

**Standalone Verifiable Credentials API service (OID4VCI + OID4VP)**

Deploy this image when you want only VC issuance and presentation APIs without the rest of federation protocols.

## Quick Start

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  ghcr.io/parlesec/protocolsoup-vc
```

## Included Protocol APIs

### OID4VCI (Issuer)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-credential-issuer/oid4vci` | `GET` | Canonical issuer metadata |
| `/oid4vci/offers/pre-authorized` | `POST` | Create pre-authorized offer |
| `/oid4vci/offers/pre-authorized/by-value` | `POST` | Create by-value offer |
| `/oid4vci/offers/pre-authorized/deferred` | `POST` | Create deferred issuance offer |
| `/oid4vci/token` | `POST` | Exchange pre-authorized code for access token + c_nonce |
| `/oid4vci/nonce` | `POST` | Rotate c_nonce |
| `/oid4vci/credential` | `POST` | Submit proof and request credential |
| `/oid4vci/deferred_credential` | `POST` | Poll deferred issuance transaction |

### OID4VP (Verifier)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/oid4vp/request/create` | `POST` | Create request object |
| `/oid4vp/request/{requestID}` | `GET`/`POST` | Retrieve request object |
| `/oid4vp/response` | `POST` | Wallet response callback (`direct_post` / `direct_post.jwt`) |
| `/oid4vp/result/{requestID}` | `GET` | Fetch verifier policy result |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Public base URL for issuer/verifier URLs |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Listen address |
| `SHOWCASE_MOCK_IDP` | `true` | Enable built-in mock identity data |
| `VC_LOOKING_GLASS` | `true` | Enable Looking Glass event capture |

## Complete VC Experience

For wallet callback automation and OID4VP wallet submission, pair this service with:

- `ghcr.io/parlesec/protocolsoup-wallet`

Run both services in the same environment and set wallet harness target base URL to your VC API host.
