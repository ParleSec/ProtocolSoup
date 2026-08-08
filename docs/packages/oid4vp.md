# OID4VP (within protocolsoup-federation)

OpenID for Verifiable Presentations (OID4VP 1.0) verifier endpoints exposed by the federation service.

## Implementation Docs

- Backend protocol README: [`backend/internal/protocols/oid4vp/README.md`](../../backend/internal/protocols/oid4vp/README.md)

## Scope

- DCQL-first request contract; scope aliases are not yet resolved to DCQL
- `direct_post` and `direct_post.jwt`; DC API code is scaffolding rather than conformance evidence
- SD-JWT VC, JWT VC, JSON-LD VC, and ISO `mso_mdoc` presentation formats

## Default presentation request

The default and canonical presentation request targets the ISO/IEC 18013-5 mobile driving licence (`mso_mdoc`, doctype `org.iso.18013.5.1.mDL`). An authorization request created without an explicit query receives this DCQL query. SD-JWT VC and the W3C formats remain selectable with explicit `dcql_query`.
- HAIP mode (`profile: "haip"`) enforcing the OpenID4VC High Assurance Interoperability Profile (HAIP 1.0)
- Signed request object generation (`typ=oauth-authz-req+jwt`)
- Verifier policy evaluation (nonce, audience, expiry, holder binding)
- Policy denial handling with parameter-level diagnostics

Looking Glass exposes the two redirect flows listed below. The repository has
no browser Digital Credentials API executor, and the wallet harness accepts
only `direct_post` / `direct_post.jwt`; private DC API-shaped tests are not
classified as browser-mediated conformance evidence.

## Base URL

- Local: `http://localhost:8080/oid4vp`
- Mounted by plugin ID (`oid4vp`) in the core server.

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/request/create` | `POST` | Create OID4VP request object |
| `/request/{requestID}` | `GET` | Retrieve request object by URI |
| `/request/{requestID}` | `POST` | Explicitly unsupported (`405 Method Not Allowed`) |
| `/verifier-attestation/.well-known/openid-configuration` | `GET` | Verifier attestation OpenID discovery |
| `/verifier-attestation/.well-known/oauth-authorization-server` | `GET` | Verifier attestation AS metadata |
| `/verifier-attestation/jwks` | `GET` | Verifier attestation JWKS |
| `/response` | `POST` | Wallet submission endpoint (`direct_post` / `direct_post.jwt` correlated by exact `state`) |
| `/result/{requestID}` | `GET` | Fetch verifier policy result |

## Real Execution Guarantees

- Request objects are signed with verifier keys, while VP and `direct_post.jwt` response signatures are validated against wallet keys.
- `direct_post.jwt` responses are wallet-signed, verifier-encrypted, and decrypted/validated in live handler logic (`typ`, subject, audience, expiry).
- Policy decisions are derived from actual VP token validation results, including `vp+jwt` type checks, subject/key holder binding, and presented credential verification against wallet-held issuance state.
- For `redirect_uri` client IDs, the `client_id` equals the `response_uri` and trust is established by the URI context.
- For `decentralized_identifier` client IDs, verifier trust resolution performs live did:web document fetch and ID/material validation.
- For `verifier_attestation` client IDs, the verifier signs request objects with an attestation key pair and publishes JWKS at the attestation issuer URL. Ephemeral key auto-provisioned when `OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM` is unset.
- For `x509_san_dns` client IDs, the request object carries an `x5c` JOSE header with the leaf/intermediate chain, excluding the trust anchor. The wallet validates the PKIX chain, leaf SAN, response URI host, and JWT signature.
- For ISO `mso_mdoc` requests (DCQL `format: mso_mdoc`), the `vp_token` is a DCQL-keyed object of base64url CBOR `DeviceResponse` values. The verifier reconstructs the OID4VP 1.0 `OpenID4VPHandover` (Appendix B.2.6.1) from the request `client_id`, `nonce`, `response_uri`, and the RFC 7638 thumbprint of its response-encryption key, then verifies the document-signer chain to a configured IACA root (`MDOC_IACA_ROOT_PEM` / `MDOC_IACA_ROOT_PEM_FILE`), the disclosed digests, `validityInfo`, and the detached `deviceSignature`. With `direct_post.jwt` the verifier provisions an ephemeral EC ECDH-ES key in `client_metadata.jwks` and decrypts the wallet's ECDH-ES + A128GCM/A256GCM JWE; the handover `jwkThumbprint` is bound to the encryption key (anti-substitution). HAIP provisions the same ECDH-ES response encryption for SD-JWT VC.
- Looking Glass includes security-warning evidence for denied presentations.

## HAIP mode and the W3C Digital Credentials API

- **HAIP mode** is opt-in per request via `profile: "haip"`. It *constrains* (it does not merely permit): in HAIP mode the verifier rejects out-of-profile choices — a scope alias instead of DCQL, an unencrypted response mode, or any signed-request scheme other than `x509_hash` (the HAIP-mandated Client Identifier Prefix). HAIP / DC API sessions advertise both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported`. The general (non-HAIP) paths are unchanged.
- **`x509_hash` Client Identifier Prefix**: the `client_id` is `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`; the request object carries `x5c` without the root trust anchor. When a persistence root is configured the signing certificate is reloaded across restarts.
- **AKI Trusted Authorities Query** (HAIP 1.0 Section 5; OID4VP 1.0 Section 6.1.1): in HAIP mode the verifier adds an `aki` Trusted Authorities Query to each `mso_mdoc` credential in the `dcql_query`, with the value set to the base64url `SubjectKeyIdentifier` of the configured IACA root. The verifier validates both the certificate path and that the document-signer certificate's Authority Key Identifier matches the query. A credential that already declares `trusted_authorities` is left untouched, and non-mdoc credentials are never modified.
- **W3C Digital Credentials API**: the repository contains handover and response-processing building blocks but does not invoke the browser API; the wallet harness rejects these modes. It is unsupported for current certification.
- **DC API handover** (`OpenID4VPDCAPIHandover`, OID4VP 1.0 Appendix B.2.6.2) is a *distinct* SessionTranscript variant over `[origin, nonce, jwkThumbprint]` — not the redirect `OpenID4VPHandover` over `[client_id, nonce, jwkThumbprint, response_uri]`. The verifier selects it by invocation path.
- **Attestation**: HAIP 1.0 makes attestation *support* mandatory but leaves the wire format an Ecosystem extension point; no single attestation format is pinned, so none is required by the presentation profile. The `verifier_attestation` scheme remains available only outside HAIP mode.

## Failure Semantics

- Contract violations (`dcql_query` with scope alias): `invalid_request`
- HAIP out-of-profile choice (in `profile: "haip"` mode): `invalid_request`
- Unknown, missing, or mismatched redirect-mode `state`: `invalid_request`
- Invalid `direct_post.jwt` / `dc_api.jwt` payload/signature/audience/expiry: `invalid_request`
- Verifier policy denial: response includes machine-readable reasons and check flags

## Demo Flow IDs

- `oid4vp-direct-post`
- `oid4vp-direct-post-jwt`
