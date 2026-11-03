# `protocolsoup-counterparty`

> Not a ProtocolSoup deployment component. Self-hosters do not need it, and no product UI links to it.

## Service Summary

- **Image:** none published. CI builds `docker/Dockerfile.conformance-counterparty` and deploys it to the Fly app `protocolsoup-counterparty`; it is not part of the GHCR publishing matrix.
- **Purpose:** the deliberately broken peer that `cmd/conformance-capture` points the hosted wallet at, so a requirement page can show the wallet refusing an invalid protocol message.
- **Topology role:** standalone. Only the capture job calls it, for a few minutes after each deploy of `master`. The hosted wallet reaches it as an external issuer or verifier over public HTTPS.

Every response carries `X-Conformance-Counterparty`, a notice that it serves deliberately invalid protocol messages, plus `X-Robots-Tag: noindex, nofollow`. `robots.txt` disallows everything.

## Runtime Contract

### Ports

- `8080`: HTTP (`COUNTERPARTY_LISTEN_ADDR`). Fly terminates TLS.

### Dependencies

- None. It holds signing keys it generates at startup and scenario state in memory for the length of one exchange, so it runs as one Machine (`flyctl deploy --ha=false`).

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COUNTERPARTY_LISTEN_ADDR` | No | `:8080` | Listen address |
| `COUNTERPARTY_BASE_URL` | Yes in production | `http://localhost:8080` | Public origin the scenario messages name as their own identifier. Must be a bare origin. |
| `BUILD_COMMIT` | Yes in production | (none) | Commit reported on `/health`; CI stages it, and the capture refuses to run unless it matches the main app's |

### Storage And Volumes

- None.

### Health And Readiness

- `GET /health` returns `{"status":"ok","commit":"<BUILD_COMMIT>"}`.

## API Surface

- `GET /`: plain-text notice of what this service is.
- `GET /health`, `GET /robots.txt`.
- `/scenarios/...` and the scenario well-known documents: one group per requirement failing case, below.

Every scenario named `<id>` is identified by `https://<host>/scenarios/<id>`. Request objects are signed ES256 with the counterparty's own key under the `decentralized_identifier:did:web:<host>:scenarios:<id>` Client Identifier Prefix, whose DID Document is `GET /scenarios/<id>/did.json`. Issuer metadata sits where OpenID4VCI 1.0 Section 12.2.2 and RFC 8414 Section 3 insert the well-known path.

| Requirement | Routes | What is invalid |
|-------------|--------|-----------------|
| VP-001 | `GET /scenarios/vp-001/request` | `client_id` uses `entity_id:`, a prefix OpenID4VP 1.0 does not define, with the removed `client_id_scheme` parameter |
| VP-002 | `GET /scenarios/vp-002/request` | `client_id` uses an unrecognized prefix |
| VP-003 | `GET /scenarios/vp-003/request`, `POST /scenarios/vp-003/response` | Nothing: a valid request carrying unrecognized parameters; `/response` accepts a `state` it served, without verifying the presentation |
| VP-004 | `GET /scenarios/vp-004/request` | The signed request wrapped in JSON and served as `application/json` |
| VP-011 | `GET /scenarios/vp-011/request` | A `transaction_data` entry of a type no wallet supports |
| VP-012 | `POST /scenarios/vp-012/request` | The returned request object's `wallet_nonce` differs from the one POSTed |
| CW-H017 | `GET /scenarios/cw-h017/request` | An ES256 request object whose signature does not verify |
| CI-010 | `GET /scenarios/ci-010/credential-offer`, issuer and AS metadata, `POST /scenarios/ci-010/token`, `POST /scenarios/ci-010/credential` | The Credential Response carries an empty `credentials` array |
| CW-006 | `GET /scenarios/cw-006/credential-offer` | The pre-authorized grant carries an empty `tx_code` object |
| CW-010 | `GET /scenarios/cw-010/credential-offer`, issuer metadata | The offer's `authorization_server` is not in the metadata's `authorization_servers` |
| CW-024 | issuer metadata | `credential_issuer` has a trailing slash the identifier lacks |
| CW-072 | offer, issuer and AS metadata, token, `POST /scenarios/cw-072/credential` | The Credential Response is encrypted with `ECDH-ES+A256KW`, not the negotiated `ECDH-ES` |
| CW-H003 | issuer and AS metadata | The authorization server requires PAR but offers only the `plain` PKCE method |
| CW-H014 | offer, issuer and AS metadata | `key_attestations_required` demands `iso_18045_high` levels a software wallet cannot back |

Pre-authorized codes are single use and last 15 minutes; access tokens last 5 minutes. No scenario issues a Credential, so the counterparty holds no credential-signing key.

## Local Use

```bash
cd backend && COUNTERPARTY_LISTEN_ADDR=:8282 COUNTERPARTY_BASE_URL=http://localhost:8282 BUILD_COMMIT=localcapture go run ./cmd/conformance-counterparty
```

The hosted wallet refuses non-public hosts, so local capture of the wallet rows needs the wallet harness started locally as well.

## Versioning And Tags

- Deployed from every push to `master` by the `deploy-counterparty` job in `.github/workflows/ci-cd.yml`, before `capture-artefacts`.
