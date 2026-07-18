# OID4VCI (within protocolsoup-federation)

OpenID for Verifiable Credential Issuance (OID4VCI 1.0) endpoints exposed by the federation service.

## Implementation Docs

- Backend protocol README: [`backend/internal/protocols/oid4vci/README.md`](../../backend/internal/protocols/oid4vci/README.md)

## Scope

- Pre-authorized code issuance
- Authorization code issuance (RFC 8414 AS metadata discovery of the
  mockidp-backed `/oidc/authorize` + `/oid4vci/token`)
- Optional `tx_code` enforcement
- `c_nonce`-bound proof validation
- OAuth 2.0 Attestation-Based Client Authentication at the token endpoint
  (opt-in via `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM`)
- OID4VCI 1.0 Appendix D key attestation on the proof JWT, per credential
  configuration (opt-in via `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM`)
- JWE-encrypted credential/deferred-credential responses
  (`credential_response_encryption`)
- Deferred issuance with `transaction_id`
- Replay/freshness denial handling

The attestation and encryption items are HAIP-related API building blocks, not
a complete HAIP conformance claim. DPoP is not implemented, and the current
Looking Glass/wallet flows do not exercise these controls end to end.

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
| `/credential-offer/{offerID}` | `GET` | Resolve by-reference credential offer |
| `/token` | `POST` | Exchange grant (`pre-authorized_code` or `authorization_code`) for access token + `c_nonce`; accepts `OAuth-Client-Attestation`/`-PoP` headers |
| `/nonce` | `POST` | Rotate `c_nonce` for active access token |
| `/credential` | `POST` | Submit proof and request credential |
| `/deferred_credential` | `POST` | Poll deferred transaction |
| `/offers/pre-authorized` | `POST` | Create pre-authorized offer |
| `/offers/pre-authorized/by-value` | `POST` | Create by-value pre-authorized offer |
| `/offers/pre-authorized/deferred` | `POST` | Create deferred pre-authorized offer |

## Real Execution Guarantees

- Access tokens are issued by issuer keys; proof JWTs are signed by wallet keys and verified against `cnf.jwk`.
- Proof JWT header `typ` is validated as `openid4vci-proof+jwt` before credential issuance.
- `credential` responses return real artifacts in the negotiated format (`dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`, or `mso_mdoc`) from live handler execution using wallet-bound subject data.
- `mso_mdoc` (ISO/IEC 18013-5 mDL, doctype `org.iso.18013.5.1.mDL`) is issued as base64url-encoded CBOR `IssuerSigned`, with `IssuerAuth` signed (COSE_Sign1, ES256) by a document-signer key whose certificate chains to an IACA root per the ISO/IEC 18013-5 Annex B profile; the holder device key is bound into the MSO from the proof.
- Issued credentials are persisted into a shared wallet credential store for downstream OID4VP presentation lineage.
- `c_nonce` freshness is enforced at runtime (`invalid_nonce` on stale replay/mismatch).
- Client attestation, when presented, is authenticated by real `x5c` chain validation against `OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM` and real signature verification of both the attestation and PoP JWTs — never accepted on trust anchor absence.
- Key attestation, when a credential configuration requires it (`MobileDrivingLicenceMsoMdocHAIP`), is validated the same way against `OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM`, and the holder's proof key must be among the attestation's `attested_keys`.
- Encrypted credential responses are real JWE (ECDH-ES + A128GCM/A256GCM) encryption via `go-jose`, not a stub — the response body is genuinely undecryptable without the wallet's ephemeral private key.
- Looking Glass events are emitted from real request handling, including security rejections.
- Authorization-code and HAIP-related issuance controls are covered by backend
  HTTP tests; the Looking Glass flow list below exposes only pre-authorized
  issuance variants.

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
