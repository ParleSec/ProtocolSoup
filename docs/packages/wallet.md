# protocolsoup-wallet

## Service Summary

- **Image:** `ghcr.io/parlesec/protocolsoup-wallet`
- **Purpose:** OID4VP presentation harness and OID4VCI wallet reference client. Imports or bootstraps credentials from real issuers, then presents to verifiers (including Looking Glass demos and callback submission).
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
| `WALLET_MDOC_IACA_ROOT_PEM` | Required for mdoc storage | `(empty)` | PEM IACA root(s) trusted when verifying `IssuerAuth` before an issued `mso_mdoc` is stored. Multiple certificates are additive. Include ProtocolSoup's issuer IACA (and any other independently obtained IACA roots this wallet should accept). |
| `WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON` | No | `(empty)` | Attester private JWK (+ `x5c`) used to mint `OAuth-Client-Attestation` JWTs. Together with the key-attestation attester JWK, enables the HAIP issuance path |
| `WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON` | No | `(empty)` | Attester private JWK (+ `x5c`) used to mint Appendix D `key_attestation` JWTs for HAIP credential proofs |
| `WALLET_OID4VCI_ATTESTED_CLIENT_ID` | No | `protocolsoup-wallet` | Attested `client_id` / client attestation JWT `sub` / client attestation PoP JWT `iss` when HAIP attestation material is configured |
| `WALLET_CLIENT_ATTESTATION_ISSUER` | No | `https://wallet.protocolsoup.com/attester` | `iss` claim on client attestation JWTs |
| `WALLET_KEY_ATTESTATION_KEY_STORAGE` | No | `(empty)` | Comma-separated `key_storage` attack-potential levels asserted in key attestation (for example `iso_18045_moderate`). Omitted unless set honestly for the deployment |
| `WALLET_KEY_ATTESTATION_USER_AUTHENTICATION` | No | `(empty)` | Comma-separated `user_authentication` attack-potential levels asserted in key attestation. Omitted unless set honestly for the deployment |

### Storage And Volumes

- Session wallet key material and credential cache are in-memory per scope key, expiring based on `WALLET_SESSION_TTL`. Durable encrypted credential-at-rest storage (OID4VCI 1.0 §15.3 SHOULD; requirement CW-100) is deferred until the platform vault initiative — a temporary Fly-backed vault would be throwaway once storage moves to HashiCorp. Credentials, JWT holder keys, refresh tokens, and DPoP/client-instance state do not survive process restart. The mdoc device key at `WALLET_DEVICE_KEY_PATH` is the exception so DeviceAuth survives restarts. Do not advertise hardware or ISO 18045 assurance properties that software keys cannot prove; key-attestation `key_storage` / `user_authentication` claims stay env-gated and omitted by default.
- Automatic OID4VCI bootstrap omits `wallet_user_id`, allowing the issuer to select its designated default identity record. It selects a wallet signing key from the configuration's advertised JWT proof algorithms (ES256 when advertised, otherwise RS256/EdDSA) and signs every batch proof with that same algorithm. Anonymous pre-authorized proof JWTs omit `iss`, carry that public key in the JOSE `jwk` header, and sign the proof with it. A failed credential notification after a successful issuance does not unwind the stored credential.
- `WALLET_MDOC_IACA_ROOT_PEM` must contain the public IACA root for the configured issuer. Hosts typically copy the issuer's persisted public `iaca_root.pem` into that wallet environment variable or secret before deploying the wallet.
- Hosted ProtocolSoup CI also copies the showcase verifier request-signer CA (`{SHOWCASE_DATA_DIR}/oid4vp/x509_request_signer_chain.pem`, last certificate) into `WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM` so Looking Glass `x509_hash` / `x509_san_dns` one-click presentations can validate the live `x5c` chain. Roots carried in `x5c` are never self-trusted.
- When `WALLET_DEVICE_KEY_PATH` is set, the `mso_mdoc` (ISO/IEC 18013-5) holder device key is persisted to that file so the device binding of issued mdoc credentials survives restarts; mount a durable volume for it. `fly.wallet.toml` uses `/data/device-key.pem` on the `protocolsoup_wallet_data` volume. Otherwise the device key is ephemeral.
- The wallet stores an issued `mso_mdoc` only after its document-signer chain,
  Annex B profile, signature, tagged MSO, digests, validity interval, document
  type, and namespaces verify against `WALLET_MDOC_IACA_ROOT_PEM`. Activating a
  credential for DeviceResponse also requires `deviceKeyInfo.deviceKey` to match
  the wallet device key (batch secondaries bound to ephemeral proof keys are
  stored for protocol visibility but not activated).
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

## OID4VCI Client (Reference Implementation)

The wallet runs a unified, metadata-driven OID4VCI client shared by automatic bootstrap (`POST /api/issue`, `/submit` bootstrap) and external import (`POST /api/import`):

- **Grants:** `pre-authorized_code` (with optional `tx_code`) and `authorization_code`.
- **Authorization code:** discovers RFC 8414 AS metadata; uses PAR + PKCE S256 when the AS requires or advertises PAR (and HAIP attestation material is configured for the HAIP path); completes at `GET /api/oid4vci/callback`. After PAR, the browser authorization redirect carries only `client_id` and `request_uri` (FAPI2 SP Final §5.3.3.2). PAR and token use the same client attestation authentication. The wallet UI keeps the offer in the current tab and opens the AS authorize step in a popup (same-tab fallback if popups are blocked, with `sessionStorage` restoring offer context on return). Resource-endpoint DPoP nonce challenges are accepted as HTTP 401 or 400. The same HAIP client can authorize for a protected resource (paste discovery URL + resource URL + scope into Import → `POST /api/import` with `discovery_url`, `resource_endpoint`, `scope`): after token exchange the callback GETs the resource with DPoP and `x-fapi-interaction-id` instead of redeeming a credential — this is ordinary OAuth resource access. When a pasted discovery URL is `openid-configuration` or `oauth-authorization-server`, the wallet checks that metadata `issuer` matches the Issuer URL derived from that discovery URL (OIDC Discovery §4.3 / RFC 8414 §3.3) and **stops** on mismatch — it must not continue to PAR or try another well-known path. FAPI2 OIDC discovery uses `{issuer}/.well-known/openid-configuration`; `{issuer}/.well-known/oauth-authorization-server` (OIDC append placement) is rewritten to `openid-configuration`. RFC 8414 insertion (`/.well-known/oauth-authorization-server/{path}`) is unchanged for HAIP. When a paste contains both well-known URLs, `openid-configuration` wins.
- **Wallet-initiated issuance:** paste a Credential Issuer identifier (or `/.well-known/openid-credential-issuer` metadata URL) into Import. `POST /api/import` with `credential_issuer` fetches Credential Issuer Metadata and returns `configuration_selection_required` plus `credential_configurations` from `credential_configurations_supported`. After the holder picks a configuration, a second import with `credential_configuration_id` starts `authorization_code` (empty grant — no issuer_state). Authorization Server discovery URLs are rejected as credential issuers.
- **UI protocol mode:** the SPA classifies input and deep links as credential issuer, offer, issued credential, protected resource, presentation request, or AS discovery, then reshapes tabs and CTAs (`Issue` + Discover/Import vs `Request` + Resolve/Review/Present). Before PAR it shows issuer identifier, selected format/`vct`, and requirements taken from real metadata (PAR, DPoP, client attestation, encryption, holder binding). After Discover, the configuration picker stays on Issue so a later **Request again** can start a new PAR without rediscovering (`request_uri` is single-use). Used Issue steps collapse; **Request again** and **Continue to Issuer** remain on the collapsed headers. Reset mode returns to idle.
- **HAIP path (env-gated):** when both attestation attester JWKs are configured, the client can present client attestation + PoP, DPoP-bound tokens, and Appendix D key attestation on proofs for HAIP configurations / AS metadata that require them. When AS metadata advertises `challenge_endpoint` (OAuth 2.0 Attestation-Based Client Authentication §6.1), the wallet POSTs for an `attestation_challenge` and includes it as the Client Attestation PoP JWT `challenge` claim. On a DPoP `use_dpop_nonce` challenge (PAR or token), the wallet retries with a fresh DPoP proof **and** a new client attestation PoP `jti` (Client Attestation JWT may be reused), refreshing the attestation challenge from `OAuth-Client-Attestation-Challenge` or the challenge endpoint when advertised.
- **Credential request:** when Credential Issuer Metadata advertises `batch_credential_issuance`, the wallet sends multiple pairwise-distinct JWT proofs in `proofs.jwt` (capped by `batch_size`, currently 2). Distinct keys apply to SD-JWT/JWT and mdoc (first mdoc proof keeps the persistent device key; additional proofs use ephemeral keys). Returned `credentials` are matched by each credential's holder key (`cnf` / mdoc `deviceKeyInfo.deviceKey`) rather than response array order. Batch-secondary `mso_mdoc` credentials bound to ephemeral proof keys are stored after IACA verification but are not activated for DeviceResponse; the device-key-bound copy remains the active credential.
- **Credential request/response encryption:** the wallet encrypts Credential and Deferred Credential Requests as compact JWE (`application/jwt`, ECDH-ES + A128GCM/A256GCM) when metadata sets `credential_request_encryption.encryption_required` to true, or when the request includes `credential_response_encryption` (OID4VCI 1.0 §8.2 / §9). Advertising request-encryption JWKs with `encryption_required` false is a MAY; this wallet leaves those requests as JSON so deferred polling stays `application/json` unless encryption is required.
- **Deferred polling:** follows `transaction_id` via the advertised `deferred_credential_endpoint`. Credential and deferred endpoints may return HTTP 202 (with optional `interval`); both endpoints retry DPoP `use_dpop_nonce` challenges (HTTP 401/400) the same way as other HAIP resource calls.
- **Notifications:** reports `credential_accepted` to the advertised `notification_endpoint` with the access-token-bound `notification_id`. Notification is a DPoP-bound resource call (RFC 9449): the wallet retries HTTP 401/400 `use_dpop_nonce` and sends `x-fapi-interaction-id`. Success is HTTP 2xx (typically 204). A failed notification after a successful issuance does not unwind the stored credential.
- **`credential_identifiers`:** when the token response returns them, credential requests use `credential_identifier` and omit `credential_configuration_id`.
- **Issuer metadata trust:** fail-closed — fetched Credential Issuer Metadata must present a `credential_issuer` that matches the offer's issuer identifier.
- **Holder binding:** JWT `sub` is optional on SD-JWT VC. The wallet stores an issued JWT/SD-JWT when RFC 7800 `cnf` is present (HAIP requires `cnf.jwk` when cryptographic holder binding is used) or when `sub` / `credentialSubject.id` is present. It does not reject a HAIP `dc+sd-jwt` solely for a missing `sub`.
- **Issuer key resolution:** JWT and SD-JWT issuer signatures are verified against `jwks_uri` advertised in Credential Issuer Metadata and RFC 8414 Authorization Server metadata. The ProtocolSoup OID4VCI Authorization Server advertises `jwks_uri` as `{issuer}/.well-known/jwks.json`. The wallet stops at the first non-empty JWK set and does not probe SD-JWT VC Issuer Metadata (`/.well-known/jwt-vc-issuer`) — that resource is not a JWK Set. Speculative ProtocolSoup JWKS paths (`/.well-known/jwks.json`, `/api/.well-known/jwks.json`, `/oidc/.well-known/jwks.json`) run only when no advertised `jwks_uri` yielded keys.
- **Metadata discovery:** Credential Issuer Metadata uses OID4VCI §12.2.2 well-known insertion and preserves a trailing slash on the issuer path; OAuth Authorization Server metadata follows RFC 8414 §3.1 (`oauth-authorization-server` only — no `openid-configuration` fallback) and strips it. Concurrent GETs to the same discovery URL are single-flighted so overlapping imports cannot race issuer discovery.
- **Key attestation honesty:** the software wallet does not assert `iso_18045_moderate` (or other attack-potential levels) unless `WALLET_KEY_ATTESTATION_KEY_STORAGE` / `WALLET_KEY_ATTESTATION_USER_AUTHENTICATION` are set to values the deployment can actually support.

Looking Glass OID4VCI pre-authorized executors create the issuer offer, then
delegate redemption to this wallet via `POST /api/import` (with
`looking_glass_session_id`) so token, proof, credential, and deferred polling
run in the harness — not in the browser. The issuer-initiated Looking Glass
flow creates and optionally delivers an `authorization_code` offer, then
observes issuer-side milestones via `status_uri`; it does not redeem codes
in-browser. Pointing Looking Glass **Advanced** `credential_offer_endpoint` at this wallet
(and configuring HAIP attestation env when required) is how an end-to-end
wallet-driven authorization-code / HAIP issuance path is exercised.

## API Surface

- `GET /health`
- `GET /authorize`
  - Public OID4VP authorization endpoint (`client_id`, `request_uri`, `request_uri_method`)
  - Redirects into the wallet SPA consent flow (does not auto-present)
  - SPA resolve auto-issues the request-inferred credential profile when the
    current wallet store has no DCQL match (for example after switching from
    an mdoc plan to an SD-JWT plan)
  - Result UI treats `response_uri` 2xx replies (`redirect_uri` or empty
    body) as accepted; Looking Glass `result.policy.allowed` remains the denial
    signal for ProtocolSoup verifiers. The SPA follows a verifier `redirect_uri`
    only when it is `https` without userinfo or a loopback, private, or internal host.
- `POST /submit`
  - Supports `mode=one_click` (default)
  - Supports `mode=stepwise` with steps: `bootstrap`, `issue_credential`, `build_presentation`, `submit_response`
  - For `direct_post.jwt`, encrypts the Authorization Response to the verifier's ephemeral ECDH-ES key from `client_metadata.jwks` (OID4VP 1.0 Section 8.3); the HTTP form contains only `response`
- `POST /api/resolve`, `POST /api/present`, `POST /api/preview`, `GET /api/session`
- `POST /api/issue` — OID4VCI bootstrap against the configured issuer
- `POST /api/import` — import from an external credential offer (pre-authorized or authorization_code), start wallet-initiated issuance from `credential_issuer` (optional `credential_configuration_id`), or HAIP authorize + DPoP GET of a protected resource (`discovery_url`, `resource_endpoint`, `scope`, optional `wallet_base_url`)
- `GET /api/oid4vci/callback` — authorization-code redirect callback

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
- Do not set `WALLET_KEY_ATTESTATION_*` to hardware or ISO 18045 levels unless the deployment truly meets them.

## Troubleshooting

- **`session isolation key is required`:** supply `looking_glass_session_id` or `request_id` in `/submit`.
- **`wallet_submission_failed`:** `/submit` returns `422 Unprocessable Content` with the issuer or credential-selection error; choose a credential format compatible with the request, or provide a matching `credential_jwt`.
- **`response_uri ... does not match trusted verifier callback`:** request object callback does not match `WALLET_TARGET_BASE_URL`.
- **`credential_jwt sub does not match wallet_subject`:** provided credential is bound to a different holder.
- **`wallet does not have a credential that satisfies the presentation request`:** ensure the selected OID4VCI credential format issues a credential requested by the OID4VP DCQL query, or provide a matching `credential_jwt`.
- **`credential configuration ... requires haip attestation material`:** this is the HAIP *issuance* gate on `POST /api/import` (HTTP 400). The hosted wallet is configured with `WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON` and `WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON` (with `x5c`). A self-hosted wallet without those JWKs must set them or choose a non-HAIP configuration. OID4VP `/submit` can still present after issuing a HAIP credential when attestation is present; without attestation material it issues the general equivalent of the same format (`MobileDrivingLicenceMsoMdocHAIP` → `MobileDrivingLicenceMsoMdoc`).
- **Upstream timeout/failure:** check `WALLET_HTTP_TIMEOUT` and VC target health.

## Versioning And Tags

- `latest` is published from default-branch builds.
- `sha-*` tags are emitted per build for immutable traceability.
- release tags publish semver variants (`vX.Y.Z`, `vX.Y`, `vX`).

## Related Docs

- Package index: [README.md](README.md)
- VC service docs: [vc.md](vc.md)
- Federation service docs: [federation.md](federation.md)
