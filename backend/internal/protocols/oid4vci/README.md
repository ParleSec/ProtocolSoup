# OpenID4VCI Protocol Implementation

A standards-aligned implementation of OpenID for Verifiable Credential Issuance (OID4VCI) with real credential issuance across multiple formats, proof validation, `c_nonce` freshness enforcement, and deferred issuance support.

## Overview

This implementation provides:

- **Pre-Authorized Code Issuance**: Wallet-first credential issuance without interactive OAuth authorization
- **Offer Transport Modes**: Both by-reference (`credential_offer_uri`) and by-value (`credential_offer`)
- **`tx_code` Enforcement**: Optional transaction code challenge in pre-authorized token exchange
- **Proof Validation**: JWT proof verification with required `typ=openid4vci-proof+jwt`
- **Nonce Freshness**: Runtime `c_nonce` issuance, rotation, and replay detection
- **Deferred Issuance**: `transaction_id` lifecycle with polling via `/deferred_credential`
- **Multi-Format Issuance**: `mso_mdoc` (ISO/IEC 18013-5 mDL), `dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, and `ldp_vc` (W3C Data Integrity with `ecdsa-rdfc-2019` / `eddsa-rdfc-2022` cryptosuites)
- **Default Configuration**: the default and lead `credential_configurations_supported` entry is the mDL `mso_mdoc` (`MobileDrivingLicenceMsoMdoc`); a request that omits an explicit configuration receives the mDL, while SD-JWT VC (`UniversityDegreeCredential`) and the W3C formats remain selectable by naming their configuration
- **Authorization Code Issuance**: RFC 8414 Authorization Server metadata discovery of the mockidp-backed `/oidc/authorize` + `/oid4vci/token` endpoints
- **Sender-Constrained Access Tokens (RFC 9449 DPoP)**: opt-in per request via a `DPoP` proof header at the token endpoint, binding the issued access token to the proof's key (`cnf.jkt`, `token_type: DPoP`) — this issuer has no refresh grant, so DPoP binding applies only to the access token; enforced on the credential, nonce, deferred_credential, and notification endpoints when a token is bound, with an independent, per-role, off-by-default `DPoP-Nonce` challenge (RFC 9449 §8)
- **HAIP Building Blocks**: OAuth 2.0 Attestation-Based Client Authentication at the token endpoint, OID4VCI 1.0 Appendix D key attestation on the proof JWT (per credential configuration), JWE-encrypted credential/deferred-credential responses, and DPoP sender-constraining — all opt-in via trust-anchor environment variables or request headers; a complete end-to-end HAIP wallet demo combining every building block at once is not implemented
- **Looking Glass Integration**: End-to-end event emission for each issuance phase

## Service Deployment

The OID4VCI implementation is mounted as plugin ID `oid4vci` in the backend protocol server.

- **Behind gateway** (recommended): `/oid4vci/*` exposed through the gateway
- **Standalone backend**: access OID4VCI endpoints directly on the backend service
- **VC image deployment**: included in `protocolsoup-vc` image for VC-focused environments

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Plugin lifecycle, route registration, flow definitions, issuer metadata helpers |
| `handlers.go` | Offer creation, token exchange, nonce handling, credential issuance, deferred polling |
| `authorization_server_metadata.go` | RFC 8414 Authorization Server metadata endpoint |
| `attestation_trust.go` | Shared PEM trust-anchor loading and `x5c` chain validation for client/key attestation |
| `client_attestation.go` | OAuth 2.0 Attestation-Based Client Authentication (`OAuth-Client-Attestation`/`-PoP`) validation |
| `key_attestation.go` | OID4VCI 1.0 Appendix D Key Attestation JWT validation |
| `credential_response_encryption.go` | JWE-encrypted Credential/Deferred Credential Response support |
| `registry.go` | Static credential configuration registry (formats, claims, key-attestation requirements) |
| `contracts.go` | Protocol contract guardrails (`tx_code`, proof requirements, offer envelope rules, key attestation) |
| `plugin_test.go` | OID4VCI behavior and regression tests |
| `haip_conformance_test.go` | AS metadata discovery, client attestation, key attestation, and encrypted-response regression tests |

## API Endpoints

### Metadata and Offer Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/oid4vci/.well-known/openid-credential-issuer` | Credential issuer metadata |
| GET | `/oid4vci/.well-known/openid-credential-issuer/*` | Issuer-derived metadata path support |
| GET | `/oid4vci/.well-known/oauth-authorization-server` | RFC 8414 Authorization Server metadata (plugin-local alias) |
| GET | `/oid4vci/.well-known/oauth-authorization-server/*` | Issuer-derived AS metadata path support |
| GET | `/oid4vci/credential-offer/{offerID}` | Resolve by-reference credential offer |
| POST | `/oid4vci/offers/pre-authorized` | Create pre-authorized offer (by reference) |
| POST | `/oid4vci/offers/pre-authorized/by-value` | Create offer with inline `credential_offer` |
| POST | `/oid4vci/offers/pre-authorized/deferred` | Create deferred-capable pre-authorized offer |

### Issuance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/oid4vci/token` | Grant exchange (`pre-authorized_code` and `authorization_code`); accepts `OAuth-Client-Attestation`/`-PoP` headers |
| POST | `/oid4vci/nonce` | Issue a fresh `c_nonce` for active access token |
| POST | `/oid4vci/credential` | Validate proof and issue credential (or deferred transaction) |
| POST | `/oid4vci/deferred_credential` | Poll and complete deferred issuance |

## Supported Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `oid4vci-pre-authorized` | Pre-Authorized Code | Offer resolution, token exchange, proof-bound credential issuance |
| `oid4vci-pre-authorized-tx-code` | Pre-Authorized + `tx_code` | Same flow with mandatory transaction code |
| `oid4vci-deferred-issuance` | Deferred Issuance | Initial request returns `transaction_id`, then wallet polls |

## Protocol Contracts and Security Controls

### Offer and Grant Validation

- Exactly one of `credential_offer` or `credential_offer_uri` must be used
- `tx_code` is required when offer grants include a `tx_code` object
- Unknown/expired pre-authorized codes are rejected with `invalid_grant`

### Proof and Nonce Validation

- Proofs are required for credential requests
- Proofs use the OID4VCI 1.0 object keyed by proof type
- Proof JWT header `typ` must be `openid4vci-proof+jwt`
- Proof audience must target issuer, and proof nonce must match active `c_nonce`
- `c_nonce` is one-time and freshness-bound, with rotation between issuance steps

### Authorization Details and Notifications

- `openid_credential` authorization details are validated and bound through
  authorization code, access token, token-response `credential_identifiers`,
  and credential request
- Credential and deferred-credential responses return a `notification_id`
  bound to the issuing access token
- `/notification` validates the allowed event values, enforces access-token
  and DPoP binding, records real issuer state, emits Looking Glass evidence,
  and treats exact retries idempotently

### Credential Issuance Guarantees

- Issued VC output is generated by live signing logic, not static payloads
- Credential response format matches the negotiated `credential_configuration_id`: `mso_mdoc` (ISO/IEC 18013-5 mDL as base64url CBOR `IssuerSigned`, the default), `dc+sd-jwt` (SD-JWT VC with selective disclosures), `jwt_vc_json` / `jwt_vc_json-ld` (JWT-encoded W3C VCs), or `ldp_vc` (W3C Data Integrity proofs with URDNA2015 canonicalization)
- Credential Requests accept one JWT proof; unsupported batch issuance,
  non-JWT proofs, and encrypted Credential Requests are not advertised
- Authorization-code, nonce, and deferred-transaction redemption is atomic;
  conflicting credential-notification lifecycle events are rejected
- Issued credential lineage is stored in the shared VC wallet store for OID4VP verification paths

### HAIP Controls (opt-in, trust-anchor-gated)

These are API-level building blocks covered by backend regression tests, not a
complete HAIP conformance claim. The current Looking Glass/wallet executors
do not drive the client-attestation, key-attestation, DPoP proof, and
encrypted-credential-request material together in one end-to-end HAIP demo,
and no external conformance suite run has been recorded.

- **Client attestation**: `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` headers at `/oid4vci/token` are validated end-to-end when `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM` is configured — attestation `x5c` chain, `sub`/`exp`/`cnf.jwk`, PoP signature (against `cnf.jwk`), `aud`/`jti`/`iat`, and single-use `jti` replay protection. Presenting either header at all makes attestation the authentication verdict; a failure is never downgraded to `client_secret`/public-client auth. Unset trust anchor means the issuer accepts none.
- **Key attestation**: credential configurations with `RequireKeyAttestation` (e.g. `MobileDrivingLicenceMsoMdocHAIP`) require a `key_attestation` JOSE header on the proof JWT, validated against `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM` — `x5c` chain, `iat`/`exp`/`attested_keys`, optional `nonce` match against the active `c_nonce`, and that the proof's JOSE-header `jwk` is among `attested_keys` and meets any required `key_storage`/`user_authentication` level.
- **Encrypted responses**: a `credential_response_encryption` object on the Credential or Deferred Credential Request is validated against advertised `alg_values_supported`/`enc_values_supported` (`ECDH-ES`; `A128GCM`/`A256GCM`) and, when valid, the response is returned as a compact JWE instead of JSON.
- **DPoP sender-constraining (RFC 9449)**: a `DPoP` proof header on the token request binds the issued access token to the proof's key via `cnf.jkt`, with `token_type: DPoP` — this issuer never issues a refresh token, for any grant, so there is no refresh-token binding to describe here (contrast the oauth2 plugin's `authorization_code` grant, where DPoP does bind a refresh token for public clients per RFC 9449 §5). A bound token is then rejected at `/oid4vci/nonce`, `/oid4vci/credential`, `/oid4vci/deferred_credential`, and `/oid4vci/notification` unless presented as `Authorization: DPoP <token>` with a matching, unreplayed proof — presenting it as a bare bearer token fails outright. An independent, off-by-default `DPoP-Nonce` challenge is available separately at the token endpoint (`SHOWCASE_DPOP_NONCE_REQUIRED`) and at the resource endpoints (`SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED`), enforcing RFC 9449 §8.2's independent AS/RS nonce spaces even though both roles run in this same process. This issuer's own RFC 8414 metadata advertises `dpop_signing_alg_values_supported` for the accepted proof algorithms (RS256, ES256, EdDSA). Opaque/reference access tokens cannot be bound; only JWT access tokens can.

## Error Semantics

| Error | Typical Trigger |
|-------|-----------------|
| `invalid_request` | Missing/malformed required parameters |
| `unsupported_grant_type` | Unsupported `grant_type` at token endpoint |
| `invalid_grant` | Unknown/expired pre-authorized code or invalid `tx_code` |
| `invalid_token` | Missing/expired access token |
| `invalid_proof` | Missing or invalid proof JWT |
| `invalid_nonce` | Stale, reused, or mismatched nonce |
| `invalid_credential_request` | Requested credential configuration not authorized |
| `invalid_transaction_id` | Unknown deferred transaction |
| `issuance_pending` | Deferred credential not ready yet |
| `invalid_client` | Client attestation presented but invalid/expired/untrusted, missing trust anchor, replayed PoP `jti`, or `client_id` mismatch with the attested `sub` |
| `invalid_encryption_parameters` | Unsupported `credential_response_encryption.jwk.alg` or `.enc` |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_BASE_URL` | Public base URL used in issuer metadata | `http://localhost:8080` |
| `SHOWCASE_DATA_DIR` | Durable state root for wallet credential persistence | (unset) |
| `SHOWCASE_MDOC_PKI_PATH` | Persistent store directory for the `mso_mdoc` issuer PKI | `{DataDir}/mdoc` (else ephemeral) |
| `MDOC_ISSUER_COUNTRY` | Two-letter country code for the `mso_mdoc` issuer PKI certificate subjects | `US` |
| `MDOC_ISSUER_ORG` | Organization name for the `mso_mdoc` issuer PKI certificate subjects | `ProtocolSoup` |
| `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM` | PEM CA trust anchor for OAuth 2.0 Attestation-Based Client Authentication `x5c` chains | (unset — attestation-based auth refused) |
| `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM` | PEM CA trust anchor for OID4VCI 1.0 Appendix D Key Attestation `x5c` chains | (unset — key-attestation-required configurations refuse all credential requests) |
| `OAUTH2_REPLAY_REDIS_URL` | Shared Redis URL backing this issuer's RFC 9449 DPoP proof `jti` replay store (distinct key prefix/instance from the oauth2 plugin's `private_key_jwt` assertion replay store) | In-memory in development/tests |
| `SHOWCASE_DPOP_NONCE_REQUIRED` | Enables the RFC 9449 §8 nonce challenge at this issuer's own `/oid4vci/token` | `false` |
| `SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED` | Enables the same challenge, independently, at `/oid4vci/credential`, `/oid4vci/nonce`, `/oid4vci/deferred_credential`, and `/oid4vci/notification` | `false` |

When `SHOWCASE_DATA_DIR` is configured, credentials are persisted under:

- `vc/wallet_credentials.json`

## Development Notes

- The plugin is designed to interoperate directly with the OID4VP plugin through shared wallet credential state
- Looking Glass events for offer creation, token exchange, proof checks, and issuance are emitted from real handler execution
- `tx_code` values are cryptographically random 6-digit numeric codes generated per offer, delivered out-of-band through the offer response

## Specifications

- OpenID for Verifiable Credential Issuance 1.0
- OAuth 2.0 Authorization Framework (grant/token semantics)
- RFC 8414 OAuth 2.0 Authorization Server Metadata
- OAuth 2.0 Attestation-Based Client Authentication (draft-ietf-oauth-attestation-based-client-auth)
- OID4VCI 1.0 Appendix D Key Attestation
- High Assurance Interoperability Profile (HAIP) 1.0
- SD-JWT VC profile (`dc+sd-jwt` selective disclosure)
- W3C Verifiable Credentials Data Model 1.1 / 2.0 (`jwt_vc_json`, `jwt_vc_json-ld`)
- W3C VC Data Integrity 1.0 (`ldp_vc` with `ecdsa-rdfc-2019` and `eddsa-rdfc-2022` cryptosuites)
