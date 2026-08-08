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
| `WALLET_DEFAULT_SUBJECT` | No | `did:example:wallet:alice` | Default holder DID root; this is wallet key identity, not an issuer user-record ID |
| `WALLET_SESSION_TTL` | No | `20m` | In-memory wallet material TTL |
| `WALLET_STRICT_SESSION_ISOLATION` | No | `true` | Require request/session scoping key for wallet isolation |
| `WALLET_ALLOWED_CORS_ORIGINS` | No | `https://protocolsoup.com,https://www.protocolsoup.com,https://protocolsoup.fly.dev` | CORS allow-list |
| `WALLET_HTTP_TIMEOUT` | No | `15s` | Upstream request timeout |
| `WALLET_DEVICE_KEY_PATH` | No | `(empty)` | Persistent `mso_mdoc` holder device key (EC P-256) file path; empty uses an ephemeral key |
| `WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM` | No | System roots only | Additional PEM CA roots trusted for `x509_san_dns` / `x509_hash` request objects; `x5c` certificates are never self-trusted |
| `WALLET_MDOC_IACA_ROOT_PEM` | Required for mdoc storage | `(empty)` | PEM IACA roots trusted when verifying `IssuerAuth` before an issued `mso_mdoc` is stored |

### Storage And Volumes

- Session wallet key material and credential cache are in-memory per scope key, expiring based on `WALLET_SESSION_TTL`.
- Automatic OID4VCI bootstrap omits `wallet_user_id`, allowing the issuer to select its designated default identity record. Anonymous pre-authorized proof JWTs omit `iss`; the wallet key is carried in the JOSE `jwk` header and signs the proof.
- `WALLET_MDOC_IACA_ROOT_PEM` must contain the public IACA root for the configured issuer. Production CI reads the main app's persisted `/data/mdoc/iaca_root.pem`, validates it as a self-anchored certificate, and installs it as a Fly secret on `protocolsoup-wallet` before deploying the wallet.
- When `WALLET_DEVICE_KEY_PATH` is set, the `mso_mdoc` (ISO/IEC 18013-5) holder device key is persisted to that file so the device binding of issued mdoc credentials survives restarts; mount a durable volume for it. `fly.wallet.toml` uses `/data/device-key.pem` on the `protocolsoup_wallet_data` volume. Otherwise the device key is ephemeral.
- The wallet stores an issued `mso_mdoc` only after its document-signer chain,
  Annex B profile, signature, tagged MSO, digests, validity interval, document
  type, namespaces, and device key verify against `WALLET_MDOC_IACA_ROOT_PEM`.
  CRL/OCSP revocation remains an external trust-policy responsibility.
- External issuer offer, metadata, token, nonce, credential, JWKS, and
  notification endpoints pass through the wallet URL policy. Userinfo,
  non-HTTPS public origins, and private, loopback, link-local, multicast, or
  internal literal-address targets are rejected; the configured ProtocolSoup
  issuer origin remains trusted for local deployments.

### Health And Readiness

- `GET /health` returns service status and the deployed commit when
  `BUILD_COMMIT` is configured.
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
- **`wallet does not have a credential that satisfies the presentation request`:** ensure the selected OID4VCI credential profile issues a format requested by the OID4VP DCQL preset, or provide a matching `credential_jwt`.
- **Upstream timeout/failure:** check `WALLET_HTTP_TIMEOUT` and VC target health.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- VC service docs: [vc.md](vc.md)
- Federation service docs: [federation.md](federation.md)
