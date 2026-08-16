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
no browser Digital Credentials API executor. The hosted wallet harness accepts
`direct_post` / `direct_post.jwt` and publishes `/authorize` for HAIP
`direct_post.jwt` wallet handoff; `dc_api.jwt` remains deferred.

## Base URL

- Local: `http://localhost:8080/oid4vp`
- Mounted by plugin ID (`oid4vp`) in the core server.

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/request/create` | `POST` | Create OID4VP request object |
| `/request/{requestID}` | `GET` | Retrieve request object by URI |
| `/request/{requestID}` | `POST` | Retrieve a `request_uri_method=post` object, binding the first `wallet_nonce`; exact retries return the same JWT |
| `/verifier-attestation/.well-known/openid-configuration` | `GET` | Verifier attestation OpenID discovery |
| `/verifier-attestation/.well-known/oauth-authorization-server` | `GET` | Verifier attestation AS metadata |
| `/verifier-attestation/jwks` | `GET` | Verifier attestation JWKS |
| `/response` | `POST` | Wallet submission endpoint; plain responses correlate by exact `state`, while encrypted HAIP responses select the ephemeral key by JWE `kid` and then require the decrypted `state` to match exactly. Returns `200 OK` with `{}` for the general profile or a `redirect_uri` pointing to the persisted result for HAIP §5.1. |
| `/result/{requestID}` | `GET` | Fetch verifier policy result |

## Real Execution Guarantees

- Request objects are signed with verifier keys and use the OID4VP `https://self-issued.me/v2` wallet audience, while VP and `direct_post.jwt` response signatures are validated against wallet keys.
- Authorization request nonces encode 32 cryptographically random bytes (256 bits), exceeding the OID4VP §5.2 minimum-entropy recommendation.
- `direct_post.jwt` responses are verifier-encrypted JWEs (ephemeral ECDH-ES advertised in `client_metadata.jwks`) whose JSON payload carries `vp_token` and `state` (OID4VP 1.0 Section 8.3). The HTTP form contains only `response`.
- Policy decisions are derived from actual VP token validation results, including `vp+jwt` type checks, subject/key holder binding, and issuer verification. First-party credentials retain wallet-held issuance lineage; independently issued SD-JWT VCs require a certificate chain rooted in `OID4VP_SD_JWT_TRUST_ANCHOR_PEM`, and mdoc presentations require the configured IACA root.
- For `redirect_uri` client IDs, the `client_id` equals the `response_uri` and trust is established by the URI context.
- For `decentralized_identifier` client IDs, verifier trust resolution performs live did:web document fetch and ID/material validation.
- For `verifier_attestation` client IDs, the verifier signs request objects with an attestation key pair and publishes JWKS at the attestation issuer URL. Ephemeral key auto-provisioned when `OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM` is unset.
- For `x509_san_dns` client IDs, the request object carries an `x5c` JOSE header with the leaf/intermediate chain, excluding the trust anchor. The wallet validates the PKIX chain, leaf SAN, response URI host, and JWT signature.
- For ISO `mso_mdoc` requests (DCQL `format: mso_mdoc`), the `vp_token` is a DCQL-keyed object of base64url CBOR `DeviceResponse` values. The verifier reconstructs the OID4VP 1.0 `OpenID4VPHandover` (Appendix B.2.6.1) from the request `client_id`, `nonce`, `response_uri`, and the RFC 7638 thumbprint of its response-encryption key, then verifies the document-signer chain to the combined configured and locally persisted IACA roots (`MDOC_IACA_ROOT_PEM`, `MDOC_IACA_ROOT_PEM_FILE`, and the issuer PKI store), the disclosed digests, `validityInfo`, and the detached `deviceSignature`. Annex B document-signer profile checks (CA=false, digitalSignature, mDL DS EKU) apply to IACA→DS chains; when IssuerAuth is signed by the configured trust anchor itself (self-signed trust-anchor-as-document-signer shape), those DS-only checks are skipped after path validation. For HAIP `trusted_authorities` (`type=aki`), a self-signed trust-anchor signer that omits AuthorityKeyIdentifier is matched by its SubjectKeyIdentifier. With `direct_post.jwt` the verifier provisions an ephemeral EC ECDH-ES key in `client_metadata.jwks` and decrypts the wallet's ECDH-ES + A128GCM/A256GCM JWE; the handover `jwkThumbprint` is bound to the encryption key (anti-substitution). HAIP provisions the same ECDH-ES response encryption for SD-JWT VC.
- Looking Glass includes security-warning evidence for denied presentations.

## HAIP mode and the W3C Digital Credentials API

- **HAIP mode** is opt-in per request via `profile: "haip"`. It *constrains* (it does not merely permit): in HAIP mode the verifier rejects out-of-profile choices — a scope alias instead of DCQL, an unencrypted response mode, or any signed-request scheme other than `x509_hash` (the HAIP-mandated Client Identifier Prefix). HAIP / DC API sessions advertise both `A128GCM` and `A256GCM` in `encrypted_response_enc_values_supported`. Non-HAIP `direct_post.jwt` also provisions ECDH-ES (A128GCM) so Looking Glass SD-JWT presentations can omit sibling `state` per OID4VP §8.3.1.
- **`x509_hash` Client Identifier Prefix**: the `client_id` is `x509_hash:<base64url(SHA-256(leaf-cert-DER))>`; the request object carries `x5c` without the root trust anchor. When a persistence root is configured the signing certificate is reloaded across restarts.
- **AKI Trusted Authorities Query** (HAIP 1.0 Section 5; OID4VP 1.0 Section 6.1.1): in HAIP mode the verifier adds an `aki` Trusted Authorities Query to each `mso_mdoc` credential in the `dcql_query`, with the value set to the base64url `SubjectKeyIdentifier` of the configured IACA root. The verifier validates both the certificate path and that the document-signer certificate's Authority Key Identifier matches the query. A credential that already declares `trusted_authorities` is left untouched, and non-mdoc credentials are never modified.
- **W3C Digital Credentials API**: the repository contains handover and response-processing building blocks but does not invoke the browser API. Wallet `dc_api.jwt` remains deferred pending a native provider.
- **Wallet HAIP (`direct_post.jwt`)**: the hosted wallet (`https://wallet.protocolsoup.com/authorize`) supports HAIP `direct_post.jwt` for `sd_jwt_vc` and `iso_mdl` with `x509_hash` + signed `request_uri`. Additional request-object CAs may be configured via `WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM`. Per OID4VP §6.4.1, a matching credential query with absent/empty `claims` returns only mandatory presentation material (no SD-JWT disclosures; mdoc `issuerAuth`/`DeviceSigned` without selectively disclosable elements). Looking Glass HAIP on OID4VP issues the key-attested configuration of the selected format when attestation is configured, and falls back to the general credential of the matching format when it is not. HAIP 1.0 Section 5 presentation does not require HAIP 1.0 Sections 4.4.1 / 4.5.1 wallet or key attestation.
- **DC API handover** (`OpenID4VPDCAPIHandover`, OID4VP 1.0 Appendix B.2.6.2) is a *distinct* SessionTranscript variant over `[origin, nonce, jwkThumbprint]` — not the redirect `OpenID4VPHandover` over `[client_id, nonce, jwkThumbprint, response_uri]`. The verifier selects it by invocation path.
- **Attestation**: HAIP 1.0 makes attestation *support* mandatory but leaves the wire format an Ecosystem extension point; no single attestation format is pinned, so none is required by the presentation profile. The `verifier_attestation` scheme remains available only outside HAIP mode.
- **POST request URI**: create the request with `request_uri_method: "post"`.
  The wallet must supply `wallet_nonce` as form data; `wallet_metadata` is
  optional. The verifier signs the nonce into the returned request object and
  rejects a later fetch that changes it. Looking Glass exposes this under
  Advanced as a GET/POST selector; selecting POST also appends
  `request_uri_method=post` to the generated `openid4vp://` wallet-handoff
  deep link.

## Failure Semantics

- Contract violations (`dcql_query` with scope alias): `invalid_request`
- HAIP out-of-profile choice (in `profile: "haip"` mode): `invalid_request`
- Unknown, missing, or mismatched redirect-mode `state`: `invalid_request`
- Invalid `direct_post.jwt` / `dc_api.jwt` payload/signature/audience/expiry: `invalid_request`
- Verifier policy denial: response includes machine-readable reasons and check flags

## Demo Flow IDs

- `oid4vp-direct-post`
- `oid4vp-direct-post-jwt`
