# OID4VP (within protocolsoup-federation)

OpenID for Verifiable Presentations (OID4VP 1.0) verifier endpoints exposed by the federation service.

## Implementation Docs

- Backend protocol README: [`backend/internal/protocols/oid4vp/README.md`](../../backend/internal/protocols/oid4vp/README.md)

## Scope

- DCQL-first request contract (`dcql_query` xor scope alias)
- `direct_post` and `direct_post.jwt` response modes
- Signed request object generation (`typ=oauth-authz-req+jwt`)
- Verifier policy evaluation (nonce, audience, expiry, holder binding)
- Policy denial handling with parameter-level diagnostics

## Base URL

- Local: `http://localhost:8080/oid4vp`
- Mounted by plugin ID (`oid4vp`) in the core server.

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/request/create` | `POST` | Create OID4VP request object |
| `/request/{requestID}` | `GET` | Retrieve request object by URI |
| `/request/{requestID}` | `POST` | Retrieve request object by POST |
| `/verifier-attestation/.well-known/openid-configuration` | `GET` | Verifier attestation OpenID discovery |
| `/verifier-attestation/.well-known/oauth-authorization-server` | `GET` | Verifier attestation AS metadata |
| `/verifier-attestation/jwks` | `GET` | Verifier attestation JWKS |
| `/response` | `POST` | Wallet submission endpoint (`direct_post` / `direct_post.jwt`) |
| `/result/{requestID}` | `GET` | Fetch verifier policy result |

## Real Execution Guarantees

- Request objects are signed with verifier keys, while VP and `direct_post.jwt` response signatures are validated against wallet keys.
- `direct_post.jwt` responses are wallet-signed, verifier-encrypted, and decrypted/validated in live handler logic (`typ`, subject, audience, expiry).
- Policy decisions are derived from actual VP token validation results, including `vp+jwt` type checks, subject/key holder binding, and presented credential verification against wallet-held issuance state.
- For `redirect_uri` client IDs, the `client_id` equals the `response_uri` and trust is established by the URI context.
- For `decentralized_identifier` client IDs, verifier trust resolution performs live did:web document fetch and ID/material validation.
- For `verifier_attestation` client IDs, the verifier signs request objects with an attestation key pair and publishes JWKS at the attestation issuer URL. Ephemeral key auto-provisioned when `OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM` is unset.
- For `x509_san_dns` client IDs, the request object carries an `x5c` JOSE header with the certificate chain. The wallet validates the PKIX chain, verifies the leaf SAN matches the `client_id` DNS name, confirms the `response_uri` host matches, and verifies the JWT signature against the leaf public key. Ephemeral self-signed CA + leaf chain auto-provisioned when PEM env vars are unset.
- Looking Glass includes security-warning evidence for denied presentations.

## Failure Semantics

- Contract violations (`dcql_query` with scope alias): `invalid_request`
- Unknown state/session: `invalid_request`
- Invalid `direct_post.jwt` payload/signature/audience/expiry: `invalid_request`
- Verifier policy denial: response includes machine-readable reasons and check flags

## Demo Flow IDs

- `oid4vp-direct-post`
- `oid4vp-direct-post-jwt`
