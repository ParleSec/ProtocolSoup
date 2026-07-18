# OpenID4VP Protocol Implementation

A standards-aligned implementation of OpenID for Verifiable Presentations (OID4VP) with signed request objects, `direct_post` / `direct_post.jwt`, backend W3C Digital Credentials API (`dc_api.jwt`) processing, HAIP mode enforcement, verifier policy evaluation, and DCQL-based credential contract validation.

## Overview

This implementation provides:

- **Request Object Creation**: Signed authorization request JWTs with `typ=oauth-authz-req+jwt`
- **DCQL-First Contracts**: Enforces `dcql_query` xor scope alias request semantics
- **Default Presentation Request**: the canonical request targets the mDL (`mso_mdoc`, doctype `org.iso.18013.5.1.mDL`) when no explicit `dcql_query`/`scope` is supplied; SD-JWT VC and the W3C formats remain selectable via an explicit query
- **Response Modes**: Supports `direct_post`, `direct_post.jwt`, and backend processing for W3C Digital Credentials API (`dc_api`, `dc_api.jwt`); no browser DC API executor is included
- **HAIP Mode**: Opt-in `profile: "haip"` enforcing HAIP 1.0 (DCQL, encrypted response, `x509_hash`, both `A128GCM`+`A256GCM`); out-of-profile choices are rejected
- **Response JWT Validation**: Validates `typ=oauth-authz-resp+jwt` for the legacy JOSE `direct_post.jwt` path; ECDH-ES mdoc/HAIP responses carry the Authorization Response directly in the JWE payload
- **VP Token Validation**: Signature, `typ=vp+jwt`, nonce, audience, expiry, and holder-binding checks
- **ISO mdoc Online Profile**: `mso_mdoc` presentations with DCQL-keyed base64url CBOR `DeviceResponse`, verifier-reconstructed `OpenID4VPHandover` (redirect, Appendix B.2.6.1) or `OpenID4VPDCAPIHandover` (DC API, Appendix B.2.6.2), and ECDH-ES + A128GCM/A256GCM encrypted responses
- **W3C Digital Credentials API Backend**: Origin-bound (`origin:`) response audience, `request_id` correlation (no `state`/`response_uri`), and distinct DC API handover processing for SD-JWT VC and `mso_mdoc`, covered by backend tests only
- **Credential Evidence**: Produces deterministic verifier diagnostics and reason codes
- **DID:web Trust Resolution**: Runtime trust checks for decentralized identifier client IDs
- **Verifier Attestation**: Signed attestation JWTs with published JWKS for `verifier_attestation` scheme
- **X.509 (`x509_san_dns` / `x509_hash`)**: PKIX chain validation with ephemeral auto-provisioning; `x509_hash` is the HAIP-mandated prefix
- **Durable Session State**: Optional persistence of request sessions and verification outcomes
- **Looking Glass Integration**: Live events for request generation, wallet submission, and policy decisions

## Service Deployment

The OID4VP implementation is mounted as plugin ID `oid4vp` in the backend protocol server.

- **Behind gateway** (recommended): `/oid4vp/*` exposed through the gateway
- **Standalone backend**: access verifier endpoints directly on the backend service
- **VC image deployment**: included in `protocolsoup-vc` image for VC-focused environments

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Plugin lifecycle, route registration, request session persistence, flow definitions |
| `handlers.go` | Request creation/retrieval, wallet response processing, verifier policy evaluation |
| `haip.go` | HAIP profile enforcement, W3C Digital Credentials API response modes, origin handling/audience, DCQL-keyed SD-JWT unwrap |
| `mdoc_online.go` | ISO `mso_mdoc` OID4VP online profile: DCQL-keyed `vp_token`, handover reconstruction (redirect + DC API), ECDH-ES + A128GCM/A256GCM JWE encrypt/decrypt |
| `mdoc_presentation.go` | mdoc `DeviceResponse` detection and verification against the reconstructed `SessionTranscript` and IACA trust anchor |
| `trust.go` | DID:web trust resolver and DID document validation |
| `verifier_identity.go` | Verifier identity signers for `verifier_attestation`, `x509_san_dns`, and `x509_hash` schemes, including ephemeral certificate auto-provisioning |
| `contracts.go` | OID4VP contract checks (`dcql_query` xor scope, response mode constraints, type headers) |
| `plugin_test.go` | OID4VP behavior, security, and regression tests |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/oid4vp/request/create` | Create signed OID4VP request object |
| GET | `/oid4vp/request/{requestID}` | Retrieve request object by URI |
| POST | `/oid4vp/request/{requestID}` | Retrieve request object via POST transport |
| POST | `/oid4vp/response` | Wallet submission endpoint (`direct_post` / `direct_post.jwt` correlated by `state`; `dc_api.jwt` correlated by `request_id`) |
| GET | `/oid4vp/result/{requestID}` | Fetch verification status/result (`pending` or `completed`) |

## Supported Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `oid4vp-direct-post` | DCQL + `direct_post` | Wallet posts `vp_token` and `state` directly to verifier response endpoint |
| `oid4vp-direct-post-jwt` | DCQL + `direct_post.jwt` | Wallet submits encrypted/signed response JWT containing `vp_token` and `state` |

## Request and Response Contracts

### Request Object Rules

- `client_id` must use a supported scheme for this profile
- Exactly one of `dcql_query` or scope alias must be provided
- For `direct_post` modes:
  - `response_uri` is required
  - `redirect_uri` must not be present
- For `dc_api` modes (W3C Digital Credentials API):
  - `origin` (Verifier Web Origin) is used; `response_uri` and `state` are not
  - `expected_origins` is included for signed requests
- In HAIP mode (`profile: "haip"`): DCQL is required, the response mode must be encrypted (`direct_post.jwt`/`dc_api.jwt`), and the signed-request scheme must be `x509_hash`; out-of-profile choices are rejected with `invalid_request`
- Request JWT header `typ` must be `oauth-authz-req+jwt`

### Wallet Response Rules

- `state` (redirect) or `request_id` (DC API) must map to an active request session
- `vp_token` is required for `direct_post`
- `response` (JWE) is required for `direct_post.jwt` and `dc_api.jwt`
- `direct_post.jwt` payload must include `vp_token` and matching `state`
- `dc_api.jwt` payload carries `vp_token` (no `state`); the audience is the `origin:`-prefixed Verifier Origin
- Response JWT header `typ` must be `oauth-authz-resp+jwt` (SD-JWT redirect path)

## Verifier Policy Evaluation

The verifier computes policy outcome from real token and credential validation signals:

- Nonce validation (`nonce` claim equals session nonce)
- Audience validation (wallet presentation audience includes verifier client ID)
- Expiry validation (`exp` claim freshness)
- Holder-binding validation (subject and key thumbprint alignment)
- Presented credential validation against wallet issuance lineage and requested claims

Failures are emitted with deterministic machine-readable reason codes (for example `nonce_mismatch`, `audience_mismatch`, `vp_token_signature_invalid`, `holder_binding_mismatch`) and surfaced in Looking Glass.

## Trust Model

### Supported `client_id` Schemes

- `redirect_uri`
- `decentralized_identifier` (`did:web`)
- `verifier_attestation`
- `x509_san_dns`
- `x509_hash` (HAIP-mandated; `client_id` = `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`)

#### `decentralized_identifier` (did:web)

- DID document URL is derived from DID syntax
- DID document is fetched and validated at runtime
- Document `id` must match presented DID
- Verification material must be present (`authentication`, `assertionMethod`, or `verificationMethod`)
- Host allowlist controls where DID resolution is permitted

#### `verifier_attestation`

- Verifier signs request objects with an attestation key pair
- Attestation issuer metadata and JWKS are published at `.well-known/openid-configuration` under the attestation issuer URL
- Wallet validates the attestation JWT against the published JWKS
- Ephemeral in-memory key used by default; set `OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM` for production continuity

#### `x509_san_dns` (OpenID4VP Section 5.9)

- Request object carries an `x5c` JOSE header with the certificate chain
- Wallet validates PKIX chain, verifies leaf SAN matches `client_id` DNS name, confirms `response_uri` host matches, and verifies JWT signature against leaf public key
- The `client_id_scheme` claim is included in the signed request object
- When `OID4VP_X509_SANDNS_CERT_CHAIN_PEM` and `OID4VP_X509_SANDNS_PRIVATE_KEY_PEM` are unset, an ephemeral ECDSA P-256 self-signed CA + leaf chain is auto-generated at startup with the leaf SAN bound to the deployment hostname
- Set the PEM env vars in production for certificate continuity across restarts

## State Persistence

When durable data storage is enabled, OID4VP request sessions are persisted to:

- `vc/oid4vp_request_sessions.json`

This persistence allows verifier result retrieval continuity across process restarts.

## Error Semantics

| Error | Typical Trigger |
|-------|-----------------|
| `invalid_request` | Missing/malformed request parameters or invalid state mapping |
| `invalid_client` | Unsupported/invalid `client_id` scheme or trust resolution failure |
| `invalid_request_uri` | Unknown or expired request object |
| `invalid_request_object` | Request object type/header contract failure |
| `server_error` | Internal failure (signing/persistence/decryption pipeline) |

Verifier policy denials are returned as successful transport responses with policy object details, rather than protocol-level request errors.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_BASE_URL` | Base URL used for generated `request_uri` and verifier endpoints | `http://localhost:8080` |
| `SHOWCASE_DATA_DIR` | Durable state root for request and wallet credential persistence | (unset) |
| `OID4VP_VERIFIER_ATTESTATION_ISSUER` | Issuer URL for `verifier_attestation` metadata and JWKS | `<SHOWCASE_BASE_URL>/oid4vp/verifier-attestation` |
| `OID4VP_VERIFIER_ATTESTATION_CLIENT_ID` | Verifier `client_id` for `verifier_attestation` scheme | `verifier_attestation:<host>` |
| `OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM` | PEM-encoded signing key for verifier attestation JWTs | Ephemeral in-memory key |
| `OID4VP_X509_SANDNS_CLIENT_ID` | Verifier `client_id` for `x509_san_dns` scheme | `x509_san_dns:<host>` |
| `OID4VP_X509_SANDNS_CERT_CHAIN_PEM` | PEM-encoded certificate chain for `x5c` JOSE header | Ephemeral self-signed chain |
| `OID4VP_X509_SANDNS_PRIVATE_KEY_PEM` | PEM-encoded private key matching the leaf certificate | Ephemeral key |

## Development Notes

- OID4VP relies on shared VC wallet credential lineage to validate presented credential signatures and bindings
- Looking Glass includes request contract data, trust mode, and policy diagnostics from live processing
- The wallet harness at `wallet.protocolsoup.com` is intended as a companion for real wallet interaction automation and stepwise execution
- Looking Glass exposes the redirect flows only; `profile: "haip"` and `dc_api.jwt` currently require direct API use, and the wallet harness does not invoke the browser Digital Credentials API

## Specifications

- OpenID for Verifiable Presentations 1.0
- JOSE (JWT/JWS/JWE) profiles used for request and response transport
- DCQL request contract semantics used by verifier request generation
- RFC 5280 / PKIX (X.509 certificate chain validation for `x509_san_dns`)
- DID Core / did:web (for `decentralized_identifier` trust resolution)
