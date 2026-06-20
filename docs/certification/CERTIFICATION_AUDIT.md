# OpenID Connect OP Certification Audit

Status: Phase 0 reconnaissance (Sections 1-10) plus Phase 2 remediation status
(Section 11). Sections 1-10 record the verified state of the ProtocolSoup
OpenID Connect OpenID Provider (OP) before any behaviour changes and are kept as
the recorded baseline. Section 11 tracks how each gap was resolved. Every path
below was opened and read directly. Scope is OpenID Connect OP only.

Terminology note: ProtocolSoup pursues OIDF self-certification. The correct terms
are "self-certified" and "OIDF-certified". This workstream does not use the word
that begins with "accred".

## 1. Service location and route mounting

The OP is not a standalone service. It is a Go protocol plugin in the main
backend binary, sharing the `mockidp.MockIdP` identity store and a single
`crypto.KeySet` with the OAuth 2.0 plugin.

| Concern | Verified location |
|---------|-------------------|
| OIDC plugin | [`backend/internal/protocols/oidc/`](../../backend/internal/protocols/oidc/) |
| Shared OP state (users, clients, codes, tokens, PKCE) | [`backend/internal/mockidp/provider.go`](../../backend/internal/mockidp/provider.go) |
| User claims and PKCE helpers | [`backend/internal/mockidp/users.go`](../../backend/internal/mockidp/users.go) |
| Signing keys and JWKS | [`backend/internal/crypto/keys.go`](../../backend/internal/crypto/keys.go) |
| JWT creation and validation | [`backend/internal/crypto/jwt.go`](../../backend/internal/crypto/jwt.go) |
| Plugin registration | [`backend/cmd/server/main.go`](../../backend/cmd/server/main.go) lines 47-51 |
| Route mounting at `/{id}` | [`backend/internal/core/server.go`](../../backend/internal/core/server.go) line 132 |
| Issuer set from `SHOWCASE_BASE_URL` | [`backend/internal/core/bootstrap.go`](../../backend/internal/core/bootstrap.go) line 52 |

Routes are registered in [`backend/internal/protocols/oidc/plugin.go`](../../backend/internal/protocols/oidc/plugin.go)
`RegisterRoutes` (lines 74-92) and mounted under `/oidc` by the core server.

## 2. Verified endpoints

| Endpoint | Route (effective) | Handler | Verified at |
|----------|-------------------|---------|-------------|
| Discovery | `/oidc/.well-known/openid-configuration` | `handleDiscovery` | `discovery.go` lines 11-40 |
| JWKS | `/oidc/.well-known/jwks.json` and `/oidc/jwks` | `handleJWKS` | `discovery.go` lines 43-49 |
| Authorization (GET) | `/oidc/authorize` | `handleAuthorize` | `userinfo.go` lines 42-188 |
| Authorization (POST login) | `/oidc/authorize` | `handleAuthorizeSubmit` | `userinfo.go` lines 191-383 |
| Token | `/oidc/token` | `handleToken` | `userinfo.go` lines 387-460 |
| UserInfo (GET and POST) | `/oidc/userinfo` | `handleUserInfo` | `claims.go` lines 13-101 |
| Revocation | `/oauth2/revoke` | OAuth2 plugin | advertised by discovery |
| Introspection | `/oauth2/introspect` | OAuth2 plugin | advertised by discovery |

There is no dynamic client registration endpoint and no logout endpoint of any
kind (RP-initiated, session management, front-channel, or back-channel).

## 3. Public deployment

Verified in [`fly.toml`](../../fly.toml).

- App: `protocolsoup`, primary region `syd`, single combined backend plus
  Next.js frontend behind a reverse proxy.
- Issuer: `SHOWCASE_BASE_URL = https://protocolsoup.com`.
- Alternate host: `https://protocolsoup.fly.dev`.
- One persistent Fly volume `protocolsoup_data` mounted at `/data`
  (`[[mounts]]`, lines 72-74). Fly supports a single mount per machine, so any
  persistent key material must live under `/data`.

The deployment intended for certification is this public deployment at
`https://protocolsoup.com`, not a bespoke test rig.

Conformance suite target endpoints (as deployed today):

| Endpoint | URL |
|----------|-----|
| Issuer | `https://protocolsoup.com` |
| Discovery | `https://protocolsoup.com/oidc/.well-known/openid-configuration` |
| JWKS | `https://protocolsoup.com/oidc/.well-known/jwks.json` |
| Authorize | `https://protocolsoup.com/oidc/authorize` |
| Token | `https://protocolsoup.com/oidc/token` |
| UserInfo | `https://protocolsoup.com/oidc/userinfo` |

## 4. CI and build

Verified under [`.github/workflows/`](../../.github/workflows/).

- `ci-cd.yml`: Snyk, lint, tests, builds, Fly deploy on `master`.
- `protocol-conformance.yml`: OID4VCI and OID4VP runtime tests only. No OIDC OP
  conformance job exists today.
- The OP ships inside the `protocolsoup` Fly app via
  [`docker/Dockerfile.fly`](../../docker/Dockerfile.fly), entry binary
  [`backend/cmd/server/main.go`](../../backend/cmd/server/main.go).
- Go module `github.com/ParleSec/ProtocolSoup`, CI Go `1.25.9`.

## 5. Signing keys and JWKS management

Verified in [`crypto/keys.go`](../../backend/internal/crypto/keys.go) and
[`core/bootstrap.go`](../../backend/internal/core/bootstrap.go).

- `crypto.NewKeySet()` generates RSA 2048, EC P-256, and Ed25519 keys at process
  start with random key IDs. Keys are held in memory only.
- No persistence: no file, database, secrets manager, or environment material
  for the OP signing keys.
- `KeySet.Rotate()` exists (keys.go lines 232-263) but has no callers.
- `PublicJWKS()` (keys.go lines 161-172) returns exactly the three current public
  keys. There is no retention of retired keys.
- ID tokens, access tokens, and refresh tokens are all signed with RS256 using
  the RSA key (jwt.go lines 62-66, 135-138, 194-197). The EC and Ed25519 keys are
  published in JWKS but never used for OIDC token issuance.

Blocker: ephemeral keys. On restart, every `kid` changes and all previously
issued tokens become unverifiable against the new JWKS. A certified deployment
requires persistent signing keys with historical JWKS retention.

## 6. Implemented capabilities (verified against handlers)

| Capability | State |
|------------|-------|
| `response_type=code` (Authorization Code) | Implemented, code in query |
| `response_type` implicit (`id_token`, `id_token token`) | Implemented, fragment |
| `response_type` hybrid (`code id_token`, `code token`, `code id_token token`) | Implemented, fragment |
| `grant_type=authorization_code` on `/oidc/token` | Implemented |
| `grant_type=refresh_token` on `/oidc/token` | Implemented, with rotation |
| `grant_type=client_credentials` on `/oidc/token` | Not implemented (OAuth2 plugin only) |
| PKCE (S256, plain) | Validated at token endpoint if a challenge was sent |
| Client auth `client_secret_basic` | Implemented (`r.BasicAuth()`) |
| Client auth `client_secret_post` | Implemented (form `client_secret`) |
| Client auth `none` (public client) | Implemented |
| Client auth `private_key_jwt`, `tls_client_auth` | Not implemented |
| UserInfo (JSON) | Implemented, scope-filtered |
| UserInfo (signed JWT response) | Not implemented |
| `nonce` echo into ID token | Implemented |
| `at_hash` / `c_hash` for implicit and hybrid | Implemented (jwt.go lines 118-128) |
| `azp` for multiple audiences | Implemented but never triggered (single audience only) |
| Discovery and JWKS | Implemented |
| Dynamic client registration | Not implemented |
| Logout (any profile) | Not implemented |
| Request object (`request`, `request_uri`) | Not implemented |
| `claims` parameter | Not implemented |

Static demo clients (provider.go lines 112-161): `demo-app` (confidential,
auth code plus refresh), `public-app` (public, auth code plus refresh),
`machine-client` (confidential, client_credentials only).

## 7. Discovery document, advertised versus delivered

Current document (discovery.go lines 14-35):

```json
{
  "issuer": "https://protocolsoup.com",
  "authorization_endpoint": "https://protocolsoup.com/oidc/authorize",
  "token_endpoint": "https://protocolsoup.com/oidc/token",
  "userinfo_endpoint": "https://protocolsoup.com/oidc/userinfo",
  "jwks_uri": "https://protocolsoup.com/oidc/.well-known/jwks.json",
  "revocation_endpoint": "https://protocolsoup.com/oauth2/revoke",
  "introspection_endpoint": "https://protocolsoup.com/oauth2/introspect",
  "scopes_supported": ["openid", "profile", "email", "roles"],
  "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code id_token token"],
  "response_modes_supported": ["query", "fragment"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "roles"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

Mismatches that fail conformance the moment the suite reads metadata:

| Advertised | Reality | Resolution |
|------------|---------|------------|
| `id_token_signing_alg_values_supported: ES256` | ID tokens always signed RS256 | Stop advertising ES256, or sign ES256. RS256 only is the honest minimum. |
| `grant_types_supported: client_credentials` | `/oidc/token` rejects it | Remove from OIDC discovery (it belongs to the OAuth2 AS). |
| `claims_supported: given_name, family_name` | `UserClaims()` never sets them | Populate the claims, or remove them from the list. |
| `claims_supported` omits `at_hash, c_hash` | They are issued | Add them so metadata matches issuance. |

## 8. Negative-path and enforcement gaps (spec-derived)

These are where OP certification is won or lost.

1. Authorization error delivery. Per RFC 6749 Section 4.1.2.1 and 4.2.2.1, once a
   valid `client_id` and `redirect_uri` are established, the OP MUST return errors
   to the client by redirecting to `redirect_uri` with `error` (and `state`),
   using the query component for the code flow and the fragment for
   implicit/hybrid. Current code (`userinfo.go`) returns a JSON body from the OP
   for every authorization error via `writeOIDCError`, and it validates
   `redirect_uri` after checking scope, `response_type`, and `nonce`. Both the
   delivery channel and the ordering are wrong.

2. Validation ordering. `client_id` and `redirect_uri` must be validated first
   (errors shown to the user agent, never redirected, per RFC 6749 4.1.2.1).
   All other request errors must then redirect to the validated `redirect_uri`.

3. `prompt`, `max_age`, `id_token_hint` are not parsed. The OP cannot honour
   `prompt=none` (must return `login_required` or `interaction_required` to the
   `redirect_uri` when no end-user session exists), nor `prompt=login` (force
   re-authentication), nor `max_age` (force re-auth and set `auth_time`).
   This needs a minimal authenticated-session concept; today login is per request
   with no session at all.

4. `response_mode` is ignored. The OP hardcodes query for code and fragment for
   implicit/hybrid rather than honouring the requested `response_mode`, and it
   does not reject invalid combinations.

5. PKCE is not enforced for public clients at the authorization endpoint. A
   public client can obtain a code with no `code_challenge`.

6. Refresh-issued ID token drops `nonce`. OIDC Core Section 12.2 says the `nonce`
   Claim, if present, MUST be the value from the original authentication. The
   refresh path passes an empty nonce (`userinfo.go` line 707).

## 9. Gap classification

Spec-derived enforcement gaps (must fix to pass, no new capability invented):

- Authorization error delivery and validation ordering (Section 8.1, 8.2).
- `prompt` and `max_age` handling with a minimal session (Section 8.3).
- `response_mode` handling (Section 8.4).
- PKCE enforcement for public clients (Section 8.5).
- Refresh `nonce` propagation (Section 8.6).
- Discovery accuracy: ES256, client_credentials, given_name/family_name,
  at_hash/c_hash (Section 7).

Configuration gaps (fix deployment, not behaviour):

- Ephemeral signing keys with no historical JWKS retention (Section 5). Resolve
  with persistent keys stored under the existing `/data` volume.
- Canonical discovery URL. The issuer is `https://protocolsoup.com` but discovery
  is only served under `/oidc`. OIDC Discovery Section 4 expects
  `{issuer}/.well-known/openid-configuration`. A root-level discovery route is
  required, mirroring the existing OID4VCI well-known handling in
  [`core/server.go`](../../backend/internal/core/server.go) lines 134-141.

Out of scope for this workstream (deferred, not cancelled): dynamic client
registration, logout profiles, `private_key_jwt`, `tls_client_auth`, request
objects, and the `claims` parameter.

## 10. Reachable OP profiles

Given the verified capabilities, the genuinely reachable OIDF OP test plans are
the discovery-based, statically-registered variants of:

- Config OP (discovery/metadata only; no variant axes, no authorization flow).
- Basic OP (Authorization Code), with `client_secret_basic` and
  `client_secret_post`.
- Implicit OP.
- Hybrid OP.

Dynamic registration variants and logout profiles are not reachable without
adding capabilities, which is out of scope. No profile will be claimed unless a
real conformance run passes it with retained logs.

## 11. Remediation status (Phase 2)

Each gap from Sections 5 to 9 is resolved below with the implementing files, the
normative source, and the regression test that pins the rule independently of
the OIDF suite. "Verified" here means a platform regression test asserts the
rule. The certification evidence of record is produced and retained by the OIDF
hosted portal (`https://www.certification.openid.net`); the CI workflow
`.github/workflows/oidc-conformance.yml` re-runs the same suite for ongoing drift
monitoring only (uploading `oidc-op-conformance-monitoring-logs`). Profile claims
still depend on a real conformance run.

| Gap | Resolution | Spec | Test | Status |
|-----|------------|------|------|--------|
| Ephemeral signing keys (5) | `LoadOrCreateKeySet` persists the RSA key under `/data/keys`; `Rotate()` retains retired public keys in JWKS | OIDC Core 1.0 Section 10.1.1 | `crypto/keys_persistence_test.go` | Verified |
| Canonical discovery URL (9) | Root `/.well-known/openid-configuration` route delegates to the OIDC handler | OIDC Discovery 1.0 Section 4 | `oidc/discovery_test.go` (issuer-prefixed endpoints) | Verified |
| Discovery accuracy: ES256, client_credentials, claims (7) | Removed ES256 and client_credentials; added at_hash, c_hash, updated_at; given_name/family_name now populated | OIDC Discovery 1.0 Section 3 | `oidc/discovery_test.go` | Verified |
| Authorization error delivery and ordering (8.1, 8.2) | client_id/redirect_uri validated first and never redirected; all later errors redirect with error and state in the correct channel | RFC 6749 Section 4.1.2.1 | `oidc/authorize_test.go` | Verified |
| `prompt` and `max_age` (8.3) | Minimal cookie session; prompt=none returns login_required, prompt=login and stale max_age force re-auth; auth_time carried from authentication time | OIDC Core 1.0 Section 3.1.2.1, 3.1.2.6 | `oidc/authorize_test.go`, `oidc/authorize_helpers_test.go` | Verified |
| `response_mode` (8.4) | Requested mode honoured where valid; query rejected for front-channel token responses; unknown modes rejected | OAuth 2.0 Multiple Response Type Encoding Section 2.1 | `oidc/authorize_test.go`, `oidc/authorize_helpers_test.go` | Verified |
| PKCE for public clients (8.5) | Public client without code_challenge rejected; unsupported code_challenge_method rejected | RFC 7636 Section 4.4.1 | `oidc/authorize_test.go` | Verified |
| Refresh-issued ID token (8.6) | auth_time preserved from original authentication across refresh and rotation; nonce omitted (permitted by Section 12.2) | OIDC Core 1.0 Section 12.2 | `oidc/refresh_test.go` | Verified |
| given_name/family_name claims (7) | Populated in `mockidp` demo users and emitted under the profile scope | OIDC Core 1.0 Section 5.1 | `oidc/discovery_test.go` (advertised), exercised via UserInfo | Verified |

Out-of-scope items from Section 9 remain deferred: dynamic client registration,
logout profiles, `private_key_jwt`, `tls_client_auth`, and request objects. The
OP does not advertise any of these. The `claims` request parameter is now
supported and advertised (see Section 13).

## 12. Conformance enablement (Phase 2, suite prerequisites)

These changes wire the deployment so the OIDF suite can actually complete its
flows against the real OP. They are configuration and standards-compliance
fixes, not suite-specific branches.

| Item | Resolution | Spec | Test | Status |
|------|------------|------|------|--------|
| Static-client registration | Two confidential clients (`conformance-client`, `conformance-client-2`) are provisioned from `OIDC_CONFORMANCE_REDIRECT_URIS` + secret in `core/bootstrap.go`; a second client is required because the suite verifies code-to-client binding. Never registered without a secret | OIDF OP static-client setup; RFC 6749 Section 3.1.2.3 | `core/bootstrap_test.go`, `oidc/conformance_test.go` | Verified |
| Suite callback redirect URIs | Exact suite callbacks for both suite hosts and every harness alias are listed in `fly.toml`; matched verbatim at the authorization endpoint | RFC 6749 Section 3.1.2.3 | `oidc/conformance_test.go` (accepted vs rejected) | Verified |
| Authorization code bound to client | A code issued to one client is refused (`invalid_grant`) when redeemed by another, even with correct client authentication | OIDC Core 1.0 Section 3.1.3.2 | `oidc/conformance_test.go` | Verified |
| Token-endpoint client-auth failure | `invalid_client` via HTTP Basic returns `401` with `WWW-Authenticate: Basic`; token-endpoint errors never emit a Bearer challenge | RFC 6749 Section 5.2 | `oidc/conformance_test.go` | Verified |
| First-login `auth_time` consistency | First interactive login records `auth_time` from the session creation time, so a later silent reuse reports an identical `auth_time` for `max_age` evaluation | OIDC Core 1.0 Section 2, Section 3.1.2.1 | `oidc/authorize_test.go`, `oidc/refresh_test.go` | Verified |

The conformance clients exist only on a deployment that has set the conformance
secret. The certified production deployment may carry them permanently so the
certified configuration matches what is continuously tested; they add no
capability beyond the standard authorization-code endpoints.

## 13. Suite-driven protocol fixes (Phase 2)

These are spec-conformance fixes surfaced by running the OIDF suite against the
real OP. Each addresses an underlying normative requirement, not a single test
input, and is pinned by a regression test.

| Item | Resolution | Spec | Test | Status |
|------|------------|------|------|--------|
| Authorization endpoint POST | The endpoint now accepts authorization requests by both GET and POST. `handleAuthorizePost` routes a login-form submission (carries `login_request_id`) versus a direct authorization request, and `handleAuthorize` reads parameters from `r.Form` so query and form bodies are handled identically | OIDC Core 1.0 Section 3.1.2.1 | `oidc/conformance_test.go` (`TestAuthorizationEndpointAcceptsPost`) | Verified (also probed live: POST returns the login page, not an error) |
| Scope-claim placement | When the flow issues an access token (code, hybrid, `id_token token`), scope-requested claims are served only from UserInfo; the ID Token carries them solely for `response_type=id_token`. Applied to the token endpoint, refresh grant, and the front-channel ID Token | OIDC Core 1.0 Section 5.4 | `oidc/conformance_test.go` (`TestCodeFlowIDTokenOmitsScopeAndCustomClaims`, `TestUserInfoReturnsScopeClaims`) | Verified |
| Full profile-scope claim set | The demo user records carry the complete OIDC Core 5.4 profile attribute set (`middle_name`, `nickname`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale` in addition to the existing `name`/`given_name`/`family_name`/`preferred_username`/`updated_at`), so the `profile` scope returns all of them from UserInfo. Values are genuine attributes on the user record (not synthesised per request) and are advertised in `claims_supported`. This clears the `VerifyScopesReturnedInUserInfoClaims` warning on `oidcc-scope-profile` without fabricating data | OIDC Core 1.0 Section 5.4; OIDC Discovery 1.0 Section 3 | `oidc/conformance_test.go` (`TestUserInfoReturnsFullProfileScopeClaims`), `oidc/discovery_test.go` | Verified |
| UserInfo token in POST body | UserInfo accepts the access token in the `Authorization` header or in a form-encoded `access_token` body parameter; two methods in one request is `invalid_request` | RFC 6750 Section 2, OIDC Core 1.0 Section 5.3.1 | `oidc/conformance_test.go` (`TestUserInfoAcceptsAccessTokenInPostBody`, `TestUserInfoRejectsMultipleTokenMethods`) | Verified |
| `request` / `request_uri` rejected | The OP supports neither parameter. A `request` parameter is rejected with `request_not_supported` and `request_uri` with `request_uri_not_supported`, before any other request validation so the object cannot mask the rejection. Previously the parameter was silently ignored, which made the OP fall back to the bare top-level params and strip the `scope`/`state`/`nonce` the suite carries inside the object (the source of the `state`-missing, `nonce`-mismatch and UserInfo-missing-claim sub-conditions on `oidcc-unsigned-request-object-...`). Discovery now advertises `request_parameter_supported` and `request_uri_parameter_supported` as `false` (the latter defaults to `true`, so it is emitted explicitly) | OIDC Core 1.0 Section 6.2.1, 6.3.1; OIDC Discovery 1.0 Section 3 | `oidc/conformance_test.go` (`TestAuthorizationRejectsRequestObject`), `oidc/discovery_test.go` | Verified |

| Authentication context (`acr`/`amr`) | The OP reports the authentication it genuinely performs (single-factor password) as `acr` `urn:protocolsoup:ac:password` and `amr` `["pwd"]`, advertised in `acr_values_supported` and present on code, hybrid/implicit, and refresh-issued ID Tokens. It is reported truthfully and never echoes a requested assurance level the OP does not satisfy, so a client requesting the advertised value via `acr_values` receives it back. This clears the `ValidateIdTokenACRClaimAgainstAcrValuesRequest` warning on `oidcc-ensure-request-with-acr-values-succeeds` without fabricating an assurance level | OIDC Core 1.0 Section 2, RFC 8176 | `oidc/conformance_test.go` (`TestAcrValuesReturnsAdvertisedContext`, `TestFullCodeFlowClaimsPlacement`), `oidc/discovery_test.go` | Verified |
| Access-token revocation on code replay | A redeemed authorization code is recorded together with the access (and refresh) tokens it minted. Replaying the code is denied with `invalid_grant` (MUST) and additionally revokes those tokens (SHOULD): the access token's `jti` is added to the existing revocation store and the UserInfo endpoint now consults it, so the token previously issued from the replayed code is rejected with `401 invalid_token`. Replay records are pruned after the access-token lifetime, since an expired token needs no revocation. This clears the `EnsureHttpStatusCodeIs4xx` warning on `oidcc-codereuse` with genuine revocation rather than a stateless-token excuse | RFC 6749 Section 4.1.2; RFC 6750 Section 3.1; RFC 7009 | `oidc/conformance_test.go` (`TestAuthorizationCodeReplayRevokesAccessToken`) | Verified |
| `claims` request parameter | The OP honours the `claims` parameter (OIDC Core 1.0 Section 5.5). Claims requested under `userinfo` are returned from UserInfo; claims requested under `id_token` are returned in the ID Token (delivered to one location only, never duplicated). The requested UserInfo claim names travel with the access token so UserInfo can serve them; values come from the user record and an absent value is omitted, not errored (Section 5.5.1). A malformed `claims` value is rejected as `invalid_request`. Discovery advertises `claims_parameter_supported: true` (default is false, so emitted explicitly). This clears the `EnsureUserInfoContainsName` warning on `oidcc-claims-essential`, which sends `scope=openid` and requests `name` essential in userinfo, without widening the default scope set | OIDC Core 1.0 Section 5.5, 5.5.1; OIDC Discovery 1.0 Section 3 | `oidc/conformance_test.go` (`TestClaimsParameterCodeFlowReturnsNameFromUserInfo`, `TestClaimsParameterIDTokenMemberReturnsNameInIDToken`, `TestAuthorizationRejectsMalformedClaims`), `oidc/discovery_test.go` | Verified |
| `address` / `phone` scopes | The demo user records carry a real structured address and a phone number, so the `address` and `phone` scopes are supported and advertised in `scopes_supported`. The `address` scope returns the `address` claim as a JSON object containing only populated members (`formatted`, `street_address`, `locality`, `region`, `postal_code`, `country`); a blank object or blank member is never emitted, which the suite's `ValidateUserInfoStandardClaims` would reject. The `phone` scope returns `phone_number` (string) and `phone_number_verified` (boolean). `claims_supported` advertises `address`, `phone_number`, and `phone_number_verified`. This converts `oidcc-scope-address`, `oidcc-scope-phone`, and `oidcc-scope-all` from SKIPPED to executed with genuine data rather than fabricated values | OIDC Core 1.0 Section 5.1, 5.1.1, 5.4; OIDC Discovery 1.0 Section 3 | `oidc/conformance_test.go` (`TestUserInfoReturnsAddressAndPhoneScopeClaims`), `oidc/discovery_test.go` | Verified |

`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
passes on the "rejected as unsupported" branch; the request-object/`request_uri`
modules that require support are `SKIPPED` once discovery advertises no support,
which is a valid certification result. Select request type `plain_http_request`
for the Basic profile run so the remaining modules use plain requests.

### `prompt=none` not-logged-in (operator cookie step, no OP change)

The OP returns `login_required` to the redirect URI whenever no end-user session
cookie is present, confirmed live:
`GET /oidc/authorize?...&prompt=none` with no cookie returns
`302 .../callback?error=login_required&state=...`. A code is only issued when a
valid session cookie is genuinely presented, which is the correct behaviour
(OIDC Core 1.0 Section 3.1.2.6).

The `oidcc-prompt-none-not-logged-in` module is an operator-interaction test, not
an automated one. Its own summary (conformance-suite
`OIDCCPromptNoneNotLoggedIn.java`) states: "Please remove any cookies you may have
received from the OpenID Provider before proceeding." The module adds
`prompt=none` and checks the callback is an interaction-required error; it does
**not** clear cookies itself. It runs immediately after `oidcc-prompt-login`,
which establishes a session, so a returned `code` means that session cookie was
still in the browser.

Selectively ignoring a valid session for this request would be a spec violation:
the next module, `oidcc-prompt-none-logged-in`, requires a `code` to be returned
when a session is present. The OP therefore cannot and must not change. To pass:

1. Run the plan up to `oidcc-prompt-none-not-logged-in`.
2. Before that module performs its request, clear the OP cookies for the OP
   origin (browser DevTools, Application, Cookies, delete `ps_oidc_auth` for
   `https://protocolsoup.com`), or use a private window that has not logged in.
3. Re-run just that module. With no session cookie the OP returns
   `login_required` and the module passes.

### SHOULD-level items

Access-token revocation after authorization-code reuse (RFC 6749 Section 4.1.2,
SHOULD) was previously a documented gap because access tokens are stateless JWTs.
It is now genuinely enforced: the tokens a code minted are tracked and revoked
when the code is replayed, and UserInfo rejects a revoked token (see "Access-token
revocation on code replay" in Section 13). No known SHOULD-level gaps remain that
affect the Basic, Implicit, or Hybrid OP profiles.
