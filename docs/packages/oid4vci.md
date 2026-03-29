# OID4VCI (within protocolsoup-federation)

OpenID for Verifiable Credential Issuance (OID4VCI 1.0) endpoints exposed by the federation service.

## Implementation Docs

- Backend protocol README: [`backend/internal/protocols/oid4vci/README.md`](../../backend/internal/protocols/oid4vci/README.md)

## Scope

- Pre-authorized code issuance
- Optional `tx_code` enforcement
- `c_nonce`-bound proof validation
- Deferred issuance with `transaction_id`
- Replay/freshness denial handling

## Base URL and Well-Known Metadata

- Local: `http://localhost:8080/oid4vci`
- Mounted by plugin ID (`oid4vci`) in the core server.
- Canonical metadata endpoint is served at `/.well-known/openid-credential-issuer/oid4vci` (issuer-derived path).

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-credential-issuer/oid4vci` | `GET` | Canonical credential issuer metadata (issuer-derived path) |
| `/credential-offer/{offerID}` | `GET` | Resolve by-reference credential offer |
| `/token` | `POST` | Exchange grant for access token + `c_nonce` |
| `/nonce` | `POST` | Rotate `c_nonce` for active access token |
| `/credential` | `POST` | Submit proof and request credential |
| `/deferred_credential` | `POST` | Poll deferred transaction |
| `/offers/pre-authorized` | `POST` | Create pre-authorized offer |
| `/offers/pre-authorized/by-value` | `POST` | Create by-value pre-authorized offer |
| `/offers/pre-authorized/deferred` | `POST` | Create deferred pre-authorized offer |

## Real Execution Guarantees

- Access tokens are issued by issuer keys; proof JWTs are signed by wallet keys and verified against `cnf.jwk`.
- Proof JWT header `typ` is validated as `openid4vci-proof+jwt` before credential issuance.
- `credential` responses return real artifacts in the negotiated format (`dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, or `ldp_vc`) from live handler execution using wallet-bound subject data.
- Issued credentials are persisted into a shared wallet credential store for downstream OID4VP presentation lineage.
- `c_nonce` freshness is enforced at runtime (`invalid_nonce` on stale replay/mismatch).
- Looking Glass events are emitted from real request handling, including security rejections.

## Failure Semantics

- Missing proof: `invalid_proof`
- Missing or wrong `tx_code` when required: `invalid_grant`
- Stale or mismatched nonce-bound proof: `invalid_nonce`
- Deferred issuance not ready: `issuance_pending`

## Demo Flow IDs

- `oid4vci-pre-authorized`
- `oid4vci-pre-authorized-tx-code`
- `oid4vci-deferred-issuance`
