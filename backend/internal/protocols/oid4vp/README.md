# OpenID4VP Protocol Implementation

A standards-aligned implementation of OpenID for Verifiable Presentations (OID4VP) with signed request objects, `direct_post` and `direct_post.jwt` response modes, verifier policy evaluation, and DCQL-based credential contract validation.

## Overview

This implementation provides:

- **Request Object Creation**: Signed authorization request JWTs with `typ=oauth-authz-req+jwt`
- **DCQL-First Contracts**: Enforces `dcql_query` xor scope alias request semantics
- **Response Modes**: Supports both `direct_post` and `direct_post.jwt`
- **Response JWT Validation**: Validates `typ=oauth-authz-resp+jwt` for `direct_post.jwt`
- **VP Token Validation**: Signature, `typ=vp+jwt`, nonce, audience, expiry, and holder-binding checks
- **Credential Evidence**: Produces deterministic verifier diagnostics and reason codes
- **DID:web Trust Resolution**: Runtime trust checks for decentralized identifier client IDs
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
| `trust.go` | DID:web trust resolver and DID document validation |
| `contracts.go` | OID4VP contract checks (`dcql_query` xor scope, response mode constraints, type headers) |
| `plugin_test.go` | OID4VP behavior, security, and regression tests |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/oid4vp/request/create` | Create signed OID4VP request object |
| GET | `/oid4vp/request/{requestID}` | Retrieve request object by URI |
| POST | `/oid4vp/request/{requestID}` | Retrieve request object via POST transport |
| POST | `/oid4vp/response` | Wallet submission endpoint (`direct_post` or `direct_post.jwt`) |
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
- Request JWT header `typ` must be `oauth-authz-req+jwt`

### Wallet Response Rules

- `state` must map to an active request session
- `vp_token` is required for `direct_post`
- `response` (JWT) is required for `direct_post.jwt`
- `direct_post.jwt` payload must include `vp_token` and matching `state`
- Response JWT header `typ` must be `oauth-authz-resp+jwt`

## Verifier Policy Evaluation

The verifier computes policy outcome from real token and credential validation signals:

- Nonce validation (`nonce` claim equals session nonce)
- Audience validation (wallet presentation audience includes verifier client ID)
- Expiry validation (`exp` claim freshness)
- Holder-binding validation (subject and key thumbprint alignment)
- Presented credential validation against wallet issuance lineage and requested claims

Failures are emitted with deterministic machine-readable reason codes (for example `nonce_mismatch`, `audience_mismatch`, `vp_token_signature_invalid`, `holder_binding_mismatch`) and surfaced in Looking Glass.

## Trust Model

### Supported `client_id` Schemes (MVP profile)

- `redirect_uri`
- `decentralized_identifier` (`did:web`)

For `decentralized_identifier:did:web` client IDs:

- DID document URL is derived from DID syntax
- DID document is fetched and validated at runtime
- Document `id` must match presented DID
- Verification material must be present (`authentication`, `assertionMethod`, or `verificationMethod`)
- Host allowlist controls where DID resolution is permitted

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

## Development Notes

- OID4VP relies on shared VC wallet credential lineage to validate presented credential signatures and bindings
- Looking Glass includes request contract data, trust mode, and policy diagnostics from live processing
- The wallet harness at `wallet.protocolsoup.com` is intended as a companion for real wallet interaction automation and stepwise execution

## Specifications

- OpenID for Verifiable Presentations 1.0
- JOSE (JWT/JWS/JWE) profiles used for request and response transport
- DCQL request contract semantics used by verifier request generation
