# OID4VCI (within protocolsoup-federation)

OpenID for Verifiable Credential Issuance (OID4VCI 1.0) endpoints exposed by the federation service.

## Implementation Docs

- Backend protocol README: [`backend/internal/protocols/oid4vci/README.md`](../../backend/internal/protocols/oid4vci/README.md)

## Scope

- Pre-authorized code issuance
- Authorization code issuance (RFC 8414 AS metadata discovery of the
  mockidp-backed `/oidc/authorize` + `/oid4vci/token`)
- RFC 9126 PAR with client attestation, PKCE S256, redirect, scope or
  `authorization_details`, exact client binding, and optional early DPoP
  binding via a `DPoP` proof and/or `dpop_jkt` (RFC 9449 Section 10.1;
  mismatched thumbprints are rejected). The PAR endpoint rejects a
  `request_uri` form parameter with HTTP 400 `invalid_request` (RFC 9126
  §2.1). HAIP wallets may introduce DPoP at
  token redemption. Authorization codes remain bound to the attested
  `client_id`: redemption by a different attested client returns HTTP 400
  `invalid_grant` (FAPI2 SP / OIDCC §3.1.3.4), including when that second
  client has not previously called PAR. Authorization codes expire after at
  most 60 seconds (FAPI2 SP Final §5.3.2.1-11). When the
  wallet returns an `issuer_state` from an issuer-initiated offer and selects
  credentials by scope only, the authorization is bound to the intersection of
  that scope's configurations and the offer's `credential_configuration_ids`
  (shared scopes such as `vc:mdl` otherwise map to more than one config)
- Optional `tx_code` enforcement
- `c_nonce`-bound proof validation
- OAuth 2.0 Attestation-Based Client Authentication at the token endpoint
  (opt-in via `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM`)
- OID4VCI 1.0 Appendix D key attestation on the proof JWT, per credential
  configuration (opt-in via `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM`)
- Attestation-based client authentication metadata, including the supported
  client-attestation and attestation-PoP signing algorithms
- JWE-encrypted credential/deferred-credential responses
  (`credential_response_encryption`)
- Sender-constrained access tokens (RFC 9449 DPoP), opt-in per request via a
  `DPoP` proof header at the token endpoint, enforced on the credential,
  nonce, deferred_credential, and notification endpoints when a token is bound, with an
  independent, off-by-default `DPoP-Nonce` challenge per role
  (`SHOWCASE_DPOP_NONCE_REQUIRED` at the token endpoint,
  `SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED` at resource endpoints). Replaying an
  authorization code returns `invalid_grant` and revokes the previously issued
  access token so those resource endpoints reject it with `invalid_token`
  (RFC 6749 Section 4.1.2 SHOULD). The `authorization_code` grant issues a
  `refresh_token` (advertised in AS metadata); refresh requests require client
  authentication, honor DPoP binding for non-attested public clients, and when
  issued under Client Attestation bind to the Client Instance Key rather than
  the DPoP key (OAuth2-ATCA §10.3; FAPI2 refresh may present a new DPoP key).
  Refresh tokens themselves are not rotated (FAPI2 SP Final §5.3.2.1-9).
  When a refresh grant was issued with a DPoP-bound access token, refresh
  requests must present a DPoP proof. Client Attestation PoP `jti` values are
  committed only after DPoP validation so a `use_dpop_nonce` challenge can be
  retried with the same attestation PoP.
  `SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED` at the resource endpoints); this
  issuer's RFC 8414 metadata advertises `dpop_signing_alg_values_supported`
- Deferred issuance with `transaction_id`
- Batch credential issuance via the Credential Endpoint
  (`batch_credential_issuance.batch_size`, up to 20 JWT proofs in one request;
  each proof binds a distinct copy of the same Credential Dataset)
- Authorization-details state bound through authorization code, access token,
  `credential_identifiers`, and credential request
- Access-token-bound, idempotent credential status notifications
- Signed Credential Issuer Metadata and certificate-backed ES256 HAIP SD-JWT
  VC issuance with OAuth Status List references
- Replay/freshness denial handling

The attestation, encryption, and DPoP items are HAIP-related API building
blocks in the running demo. Named certified ProtocolSoup versions and OID4VCI
profiles are listed on the [trust page](https://protocolsoup.com/trust#conformance).
The hosted wallet reference
client (`protocolsoup-wallet`) drives client attestation, key attestation,
DPoP, and credential-response encryption together when its HAIP attestation
env material is configured. Looking Glass pre-authorized executors create the
issuer offer, then surface each real wallet→issuer hop (metadata, token, nonce,
proof JWT, credential, deferred polling) from the wallet's `_protocol_exchanges`
transcript. Issuer-initiated Looking
Glass observes wallet-driven `authorization_code` milestones via `status_uri`
and does not redeem codes in-browser. Only JWT access tokens can be DPoP-bound;
opaque/reference token binding is out of scope. The `authorization_code`
grant issues a refresh token (DPoP-bound when the access token is and Client
Attestation was not used; Client Instance Key-bound under attestation per
OAuth2-ATCA §10.3). Refresh tokens are not rotated on use (FAPI2 SP Final
§5.3.2.1-9). Pre-authorized code grants do not issue refresh tokens.

## Default credential configuration

The default and lead `credential_configurations_supported` entry is the ISO/IEC 18013-5 mobile driving licence (`mso_mdoc`, configuration ID `MobileDrivingLicenceMsoMdoc`). A request that omits an explicit configuration receives the mDL. SD-JWT VC (`UniversityDegreeCredential`) and the W3C formats (`UniversityDegreeCredentialJWT`, `UniversityDegreeCredentialJWTLD`, `UniversityDegreeCredentialLDP`) remain fully selectable by naming their configuration explicitly. This is a behavioural change for consumers that previously relied on the implicit SD-JWT VC default — see the [OID4VCI default credential format note](../starlight/src/content/docs/protocols/oid4vci.mdx).

## Base URL and Well-Known Metadata

- Local: `http://localhost:8080/oid4vci`
- Mounted by plugin ID (`oid4vci`) in the core server.
- Canonical metadata endpoint is served at `/.well-known/openid-credential-issuer/oid4vci` (issuer-derived path).
- Canonical Authorization Server metadata (RFC 8414) is served at
  `/.well-known/oauth-authorization-server/oid4vci` (issuer-derived path,
  mounted at root by `server.go`, mirroring the credential issuer metadata
  mount).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-credential-issuer/oid4vci` | `GET` | Canonical credential issuer metadata (issuer-derived path) |
| `/.well-known/oauth-authorization-server/oid4vci` | `GET` | Canonical Authorization Server metadata (RFC 8414, issuer-derived path) |
| `/oid4vci/.well-known/jwks.json` | `GET` | Authorization Server JWK Set advertised as RFC 8414 `jwks_uri` |
| `/oid4vci/jwks` | `GET` | Alternate JWKS path for the same KeySet |
| `/credential-offer/{offerID}` | `GET` | Resolve by-reference credential offer |
| `/par` | `POST` | Push a client-attested HAIP authorization request, optionally pre-bound to DPoP |
| `/token` | `POST` | Exchange grant (`pre-authorized_code` or `authorization_code`) for an access token; accepts `OAuth-Client-Attestation`/`-PoP` headers |
| `/nonce` | `POST` | Obtain a fresh public `c_nonce` |
| `/credential` | `POST` | Submit proof and request credential |
| `/deferred_credential` | `POST` | Poll deferred transaction |
| `/notification` | `POST` | Report the storage outcome for an issued credential |
| `/status-lists/{listID}` | `GET` | Retrieve the signed OAuth Status List Token used by HAIP SD-JWT VC credentials |
| `/credential-types/university-degree` | `GET` | Retrieve ProtocolSoup's HAIP SD-JWT VC Type Metadata |
| `/offers/pre-authorized` | `POST` | Create pre-authorized offer |
| `/offers/pre-authorized/by-value` | `POST` | Create by-value pre-authorized offer |
| `/offers/pre-authorized/deferred` | `POST` | Create deferred pre-authorized offer |
| `/offers/authorization-code` | `POST` | Create an issuer-initiated `authorization_code` offer with a fresh `issuer_state`; optional `credential_offer_endpoint` triggers a real §4.1.2 HTTPS delivery GET |
| `/offers/authorization-code/status/{statusID}` | `GET` | Check server-observed issuer-initiated milestones without exposing `issuer_state` as the status reference |

## Real Execution Guarantees

- Access tokens are issued by issuer keys; proof JWTs are signed by wallet keys and verified against the proof JOSE header `jwk`.
- Credential Issuer Metadata advertises only HAIP-recognized formats
  (`dc+sd-jwt`, `mso_mdoc`), with claims nested under `credential_metadata`
  per OID4VCI 1.0 Final. W3C formats remain issuable by explicit configuration
  id for Looking Glass. HAIP client-attestation, DPoP, and key-attestation
  requirements apply whenever a HAIP credential configuration is authorized.
- Authorization Endpoint issuance uses client-attested RFC 9126 PAR; direct
  OID4VCI authorization requests are rejected because
  `require_pushed_authorization_requests` is advertised.
- When the Wallet uses `scope` for authorization (OID4VCI §5.1.2), the token
  response omits `authorization_details` unless the Wallet also used RFC 9396
  `authorization_details`. Returning invented configuration IDs for a shared
  scope (for example both general and HAIP mDL under `vc:mdl`) would invent
  configuration IDs the wallet did not request.
- Authorization Server Metadata advertises
  `authorization_response_iss_parameter_supported: true` (RFC 9207); the shared
  `/oidc/authorize` endpoint returns `iss` equal to the OID4VCI AS issuer on
  OID4VCI authorization responses (FAPI 2.0 SP §5.3.2.2).
- PAR `request_uri` values remain usable across authorize page loads and are
  consumed only when authorization completes (FAPI 2.0 SP §5.3.2.2 Note 3).
  PAR-backed requests never silent-SSO via an existing session cookie; with a
  session present the OP shows a Continue confirmation instead.
- Proof JWT header `typ` is validated as `openid4vci-proof+jwt` before credential issuance.
- `credential` responses return real artifacts in the negotiated format (`dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`, or `mso_mdoc`) from live handler execution using wallet-bound subject data.
- Credential time claims (`iat`/`nbf`/`exp` and mdoc MSO `validityInfo.signed`/`validFrom`/`validUntil`) are rounded to the start of the UTC day per RFC 9901 Section 10.1 so same-dataset credentials issued seconds apart are not linkable by precise issuance time. JWT/SD-JWT lifetime is measured from that rounded instant.
- `mso_mdoc` metadata uses numeric COSE algorithm identifier `-7` for
  credential signing; JWT holder proofs continue to use JOSE `ES256`.
- The issuer advertises `batch_credential_issuance.batch_size` (20) and accepts
  up to that many JWT proofs in one Credential Request, issuing one credential
  copy per proof bound to that proof's key (same Credential Dataset). Non-JWT
  proof types are not advertised. Credential Requests may be a compact ECDH-ES
  JWE using the key advertised in `credential_request_encryption`. The deferred
  credential endpoint accepts the same JSON or encrypted JWT media types.
- Authorization codes, credential nonces, and deferred transaction identifiers
  are consumed atomically; conflicting notification lifecycle events are
  rejected without mutating accepted history.
- `dc+sd-jwt` issuance uses `typ: dc+sd-jwt`, canonical compact serialization,
  top-level `_sd_alg`, and positional recursive disclosure processing. Incoming
  issuer credentials that already contain a Key Binding JWT are not stored.
- `openid_credential` authorization details are validated before approval,
  bound to the grant, and enforced through token-response
  `credential_identifiers`; identifiers cannot be reused across access tokens.
  An unbound or unknown `credential_identifier` at the Credential Endpoint
  returns HTTP 400 `unknown_credential_identifier` (OID4VCI §8.3.1.2).
- Credential responses return an access-token-bound `notification_id`.
  Accepted, failed, and deleted events mutate issuer state, emit Looking Glass
  evidence, and treat exact retries idempotently.
- `mso_mdoc` is issued as base64url CBOR `IssuerSigned`; verification enforces
  tagged MSO bytes, MSO and DeviceResponse invariants, unique elements, value
  digests, and the Annex B document-signer profile against an independent IACA
  root. Mandatory mDL elements include an identity-derived stylized JPEG
  portrait that is explicitly not presented as a real person's photograph.
  CRL/OCSP revocation requires external trust state.
- Issued credentials are persisted into a shared wallet credential store for downstream OID4VP presentation lineage.
- `c_nonce` freshness is enforced at runtime (`invalid_nonce` on stale replay/mismatch).
- Client attestation, when presented, is authenticated by real `x5c` chain validation against `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM` and real signature verification of both the attestation and PoP JWTs — never accepted on trust anchor absence.
- Key attestation, when a credential configuration requires it (`MobileDrivingLicenceMsoMdocHAIP`), is validated the same way against `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM`, and the holder's proof key must be among the attestation's `attested_keys`.
- Encrypted credential responses are real JWE (ECDH-ES + A128GCM/A256GCM) encryption via `go-jose`, not a stub — the response body is genuinely undecryptable without the wallet's ephemeral private key.
- Looking Glass events are emitted from real request handling, including security rejections.
- Authorization-code and HAIP-related issuance controls are covered by backend
  HTTP tests and by the wallet reference client's unified OID4VCI import path
  when HAIP attestation env is configured. Looking Glass pre-authorized flows
  create the offer then surface the wallet's recorded OID4VCI hops
  (`_protocol_exchanges`: metadata, token, nonce, proof, credential, deferred).
  Issuer-initiated
  Looking Glass (`oid4vci-issuer-initiated`) observes rather than impersonates
  the wallet via `status_uri`. The issuer persists
  the offer context, rejects unknown or expired `issuer_state` values and
  Credential-Configuration-mismatched bindings at PAR (the same offer may be
  redeemed by consecutive clients until the offer TTL), and propagates the
  validated context through authorization-code redemption and credential
  issuance. Credential Offer Endpoint delivery accepts 2xx/3xx without
  following redirects and omits non-spec fields from the wire
  `credential_offer` object.
- Issued credentials of any registered format, including `mso_mdoc`, are inspectable via the gateway's `POST /lookingglass/decode/credential` (see [Credential Inspection](../starlight/src/content/docs/protocols/oid4vci.mdx#credential-inspection-looking-glass)). It decodes through the same shared `CredentialFormat` registry and evidence shape issuance and OID4VP verification already use, and reports issuer trust plus (`mso_mdoc` only) MSO digest consistency in an assurance envelope kept structurally separate from the decoded evidence — never a blanket validity flag.

## Failure Semantics

- Missing proof: `invalid_proof`
- Missing or wrong `tx_code` when required: `invalid_grant`
- Stale or mismatched nonce-bound proof: `invalid_nonce`
- Deferred issuance not ready: `issuance_pending`
- Client attestation presented but invalid, missing trust anchor, or replayed PoP `jti`: `invalid_client` (401, `WWW-Authenticate: Bearer`)
- Key attestation required but missing, invalid, or insufficient `key_storage`/`user_authentication`: `invalid_proof`
- Unsupported `credential_response_encryption.jwk.alg` / `.enc`: `invalid_encryption_parameters`

## Demo Flow IDs

- `oid4vci-pre-authorized`
- `oid4vci-pre-authorized-tx-code`
- `oid4vci-deferred-issuance`
- `oid4vci-issuer-initiated` — creates an `authorization_code` Credential
  Offer with a fresh `issuer_state` via `POST /offers/authorization-code`
  and, when an external `credential_offer_endpoint` is supplied under Looking
  Glass **Advanced**, has the issuer deliver the offer with a real
  HTTPS GET (`credential_offer` query parameter). With no external endpoint
  it produces an `openid-credential-offer://` invocation URI and QR code.
  Looking Glass then reuses the OID4VP wallet-handoff chrome
  (`awaiting_user` + "Check Result"): each click checks the separate opaque
  `status_uri` once and shows `waiting_for_wallet`,
  `authorization_request_received`, `token_issued`, or `credential_issued`
  from the issuer's real request handling. The wallet remains responsible
  for sending its own PAR, token, and credential requests (including HAIP
  attestation and DPoP when that wallet is configured for them).
