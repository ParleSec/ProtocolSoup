# OpenID Connect OP: OIDF Self-Certification Submission Package

This document is the maintainer handover for submitting the ProtocolSoup
OpenID Provider (OP) for OpenID Foundation (OIDF) self-certification. It records
the targeted profiles, the conformance suite version, where the evidence comes
from, and the exact human steps that remain. It does not claim a pass that has
not been produced by a real conformance run.

## Scope

OpenID Connect OP only. The OP is the Go plugin at
`backend/internal/protocols/oidc/` backed by `backend/internal/mockidp/` and the
key management in `backend/internal/crypto/`, deployed as part of the Fly.io
monolith. Conformance is driven entirely through standard OP endpoints against
the real deployment. There is no suite-specific branch in the OP.

## Targeted certification profiles

The harness (`scripts/conformance-run.sh`) drives these OIDF OP test plans. One
OpenID Connect certification covers every profile the deployment passes, so the
full supported set is run:

| Plan | Variant axes | Harness label |
|------|--------------|---------------|
| `oidcc-config-certification-test-plan` | none (discovery/metadata only) | `config` |
| `oidcc-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client`, `client_secret_basic` | `basic` |
| `oidcc-basic-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client`, `client_auth_type=client_secret_post` | `basic-post` |
| `oidcc-implicit-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` | `implicit` |
| `oidcc-hybrid-certification-test-plan` | `server_metadata=discovery`, `client_registration=static_client` | `hybrid` |

Config OP (`oidcc-config-certification-test-plan`) validates only the discovery
document and JWKS. It takes no variant axes and runs no authorization flow, so
it needs no redirect URI or end-user login; it is a separate certifiable profile
covered by the same submission because the OP already serves an accurate
discovery document (`oidc-op-discovery-metadata-accuracy`).

### Deliberately out of scope

These are genuine non-capabilities, not profiles skipped to dodge a test:

- Dynamic client registration (no DCR endpoint). Static-client variants only.
- OIDC logout (no RP-initiated, front-channel, or back-channel logout endpoints).
- `private_key_jwt` and `tls_client_auth` token-endpoint authentication.
- Request object / `request_uri`.

The OP advertises only what it delivers (see `discovery.go` and the
`oidc-op-discovery-metadata-accuracy` requirement). It does not advertise any of
the above.

## Token-endpoint client authentication

The OP supports `client_secret_basic`, `client_secret_post`, and `none` (public
clients, which are required to use PKCE). Both confidential methods are
exercised by the `basic` and `basic-post` runs above. A failed client
authentication that used HTTP Basic returns `401` with a matching
`WWW-Authenticate: Basic` challenge, and token-endpoint errors never carry a
Bearer challenge (RFC 6749 Section 5.2).

## Conformance client registration (required before any run)

The OIDF OP profiles with static clients require **two confidential clients**:
the suite uses the second one to verify that an authorization code is bound to
the client it was issued to. Both must be registered with the suite callback as
an **exact** redirect URI (RFC 6749 Section 3.1.2.3 simple string comparison):

- Local suite: `https://localhost.emobix.co.uk:8443/test/a/<alias>/callback`
- Hosted suite: `https://www.certification.openid.net/test/a/<alias>/callback`

These clients are provisioned by the OP from environment, so no suite-specific
code path exists:

- `OIDC_CONFORMANCE_REDIRECT_URIS` (comma-separated, exact URIs) is set in
  `fly.toml` and already lists both suite hosts for every harness alias
  (`protocolsoup-basic`, `protocolsoup-basic-post`, `protocolsoup-implicit`,
  `protocolsoup-hybrid`). Add your chosen hosted-cert alias here if it differs.
- `OIDC_CONFORMANCE_CLIENT_SECRET` must be set as a Fly secret. The two clients
  are **only** registered when this secret is present, so a deployment that has
  not opted in is unaffected (and a secretless confidential client is never
  created).
- `OIDC_CONFORMANCE_CLIENT_ID` / `OIDC_CONFORMANCE_CLIENT2_ID` default to
  `conformance-client` / `conformance-client-2`. The harness uses the same
  defaults, so they line up without extra configuration.
- `OIDC_CONFORMANCE_CLIENT2_SECRET` is optional; when unset the second client
  reuses the first secret (still a distinct registration).

The suite logs in as the demo end user `alice@example.com`, so the deployment
must set `MOCKIDP_ALICE_PASSWORD` to a known value and the harness
`OIDC_CONFORMANCE_PASSWORD` must equal it.

## Conformance suite version

- The certification run uses the OIDF hosted suite; record the suite version the
  portal reports for the submitted run (shown per test, e.g. `5.1.45`).
- The monitoring CI uses pinned local images in
  `docker/docker-compose.conformance.yml`:
  `registry.gitlab.com/openid/conformance-suite/{server,nginx}:release-v5.1.43`,
  MongoDB `mongo:6.0.13`. Keep this version close to the portal's so monitoring
  reflects the same checks; never run with the `latest` tag.

## Where the certification evidence comes from

The certification evidence of record is produced and retained by the OIDF hosted
conformance suite at `https://www.certification.openid.net`. A maintainer runs
the targeted OP test plans there against the live deployment and submits the
per-module logs the portal retains for each passed profile. The CI workflow
below does **not** produce certification evidence.

## Ongoing conformance monitoring (CI)

After certification, `.github/workflows/oidc-conformance.yml` re-runs the same
OIDF suite (pinned in `docker/docker-compose.conformance.yml`) against the
deployment on every OIDC-affecting change and weekly, so a regression that breaks
conformance fails CI early. This is drift monitoring, not evidence of record:

- The `op-conformance` job starts the pinned suite, runs the plans through
  `conformance-run.sh`, runs the reflexive adjudicator
  (`scripts/conformance/divergence.py`), and uploads the per-module logs as the
  `oidc-op-conformance-monitoring-logs` artifact (30-day retention) purely for
  diagnosing a failed run.
- When the conformance secrets are absent, the job runs a harness self-check
  only and claims no result. No pass is ever synthesised.
- Go normative regression tests are not duplicated here; the main CI/CD pipeline
  (`ci-cd.yml`) already runs the full backend test suite, including
  `internal/protocols/oidc`, `internal/crypto`, and `internal/mockidp`.

The platform's self-adjudication lives in `docs/compliance/oidc-op-musts.json`;
the reflexive audit step flags any divergence between that claim and the real
suite result.

## Required CI secrets

Configure these repository secrets so the monitoring `op-conformance` job runs
the suite (without them it self-checks only; certification itself does not depend
on these):

| Secret | Meaning |
|--------|---------|
| `OIDC_CONFORMANCE_TARGET_BASE_URL` | Public issuer base, e.g. `https://protocolsoup.com` |
| `OIDC_CONFORMANCE_CLIENT_ID` | First confidential client id (default `conformance-client`) |
| `OIDC_CONFORMANCE_CLIENT_SECRET` | Confidential client secret (same value set as a Fly secret on the deployment) |
| `OIDC_CONFORMANCE_CLIENT2_ID` | Second confidential client id (default `conformance-client-2`) |
| `OIDC_CONFORMANCE_CLIENT2_SECRET` | Optional; second client secret (defaults to the first) |
| `OIDC_CONFORMANCE_USERNAME` | Conformance end-user login (e.g. `alice@example.com`) |
| `OIDC_CONFORMANCE_PASSWORD` | Conformance end-user password |

The same `OIDC_CONFORMANCE_CLIENT_SECRET` value must be set on the deployment so
the OP registers the two conformance clients (see the client-registration
section above). The end-user password must match the deployed
`MOCKIDP_ALICE_PASSWORD`.

## Deployment reality (must match what is certified)

- Signing keys are persistent. `SHOWCASE_KEY_STORE_PATH=/data/keys` (set in
  `fly.toml`) loads the RSA signing key from the mounted volume on every start,
  so tokens stay verifiable across restarts.
- Retired public keys are retained in JWKS after rotation, so previously issued
  tokens remain verifiable (`crypto/keys.go`, `crypto/keystore.go`).
- The discovery document is served at the issuer root
  (`/.well-known/openid-configuration`) so a Relying Party derives it correctly
  from the issuer (OpenID Connect Discovery 1.0 Section 4).
- The two conformance clients are registered from environment
  (`registerConformanceClients` in `internal/core/bootstrap.go`) only when both
  `OIDC_CONFORMANCE_REDIRECT_URIS` and `OIDC_CONFORMANCE_CLIENT_SECRET` are set.
  They share the same standard authorization-code endpoints as every other
  client; nothing about the request path is suite-specific.

## Producing the certification run (OIDF portal)

The submitted evidence is produced on the hosted portal, not in CI:

1. Confirm the deployment is live and reachable at the issuer base URL, and that
   the conformance clients are registered (see client-registration section).
2. Sign in at `https://www.certification.openid.net` and create each targeted OP
   test plan against the live deployment's discovery URL.
3. Run every module in each plan and confirm it passes (or is a legitimate
   SKIPPED/REVIEW for an unsupported optional feature).
4. Publish/submit the per-module logs the portal retains for each passed profile.

## Pre-flight and ongoing monitoring (local or CI)

Optional, for catching regressions before they reach the portal. This is the
same suite software, driven against the deployment, but it is monitoring only:

```bash
cd ProtocolLens
docker compose -f docker/docker-compose.conformance.yml up -d --wait
OIDC_TARGET_BASE_URL=... OIDC_CLIENT_SECRET=... OIDC_PASSWORD=... \
  bash scripts/conformance-run.sh
docker compose -f docker/docker-compose.conformance.yml down -v
```

The CI equivalent (`.github/workflows/oidc-conformance.yml`) runs the same
harness and uploads `oidc-op-conformance-monitoring-logs` for diagnostics; its
`DIVERGENCES.md` should report no overclaims.

## Last certification run

To be completed from the OIDF portal record of the submitted run.

- Date (UTC):
- Portal plan/run URLs:
- Suite version (from the portal):
- Profiles passed:

## Human-in-the-loop submission steps

These steps are intentionally left to a maintainer and are not automated:

1. Create or sign in to an account at `https://certification.openid.net`.
2. Start a new OpenID Connect OP certification and complete any required
   payment.
3. Run the targeted OP test plans in the portal against the live deployment and
   submit the per-module logs the portal retains for each passed profile.
4. Complete the certification declaration, using the terms "self-certified" and
   "OIDF-certified" as appropriate.

## Related documents

- `docs/certification/CERTIFICATION_AUDIT.md`: full audit of endpoints,
  capabilities, and the gap list with remediation status.
- `docs/compliance/oidc-op-musts.json`: per-requirement self-adjudication mapped
  to suite modules and regression tests.
