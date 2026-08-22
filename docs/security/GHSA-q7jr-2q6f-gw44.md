# Maintainer packet: GHSA-q7jr-2q6f-gw44

**Do this packet first, then request a CVE.** GitHub is a CNA. Whatever is in the GHSA **Description** when you click **Request CVE** is what their security team uses for the CVE record. The reporter submission still contains a working proof of concept. That must not be the CVE text.

| Item | Value |
|------|--------|
| Advisory | https://github.com/ParleSec/ProtocolSoup/security/advisories/GHSA-q7jr-2q6f-gw44 |
| GHSA | `GHSA-q7jr-2q6f-gw44` |
| CVE | *none yet — do not request until the description below is saved on the draft* |
| State (2026-08-22) | `draft`, submission accepted |
| Reporter credit | [EQSTLab](https://github.com/EQSTLab) (`credits[].type = reporter`, currently `pending`) |
| CWE | CWE-918 |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` → **7.2 High** |
| Public description to paste | [GHSA-q7jr-2q6f-gw44.github-description.md](GHSA-q7jr-2q6f-gw44.github-description.md) |
| API body (same text) | [GHSA-q7jr-2q6f-gw44.github-patch.json](GHSA-q7jr-2q6f-gw44.github-patch.json) |

## Corrections versus the reporter form

| Field | Reporter submitted | Use this instead | Why |
|-------|--------------------|------------------|-----|
| Vulnerable versions | `4.1.0` only | `>= 2.0.0, <= 4.1.0` | `validateExternalURL` + default `http.Client` exist on tags **v2.0.0, v3.0.0, v4.0.0, v4.1.0**. **v1.0.0** does not contain the function. |
| Patched versions | empty | keep empty until the fixing tag is pushed | Publishing with no patch is allowed but Dependabot will alert with no upgrade target. Do not invent `4.1.1` before it exists. |
| Description | Full exploit scripts, Docker PoC, marker strings | [github-description.md](GHSA-q7jr-2q6f-gw44.github-description.md) | CVE.org must not republish a copy-paste exploit. Root cause and impact stay; reproduction recipes go. |
| Package | `github.com/ParleSec/ProtocolSoup` / Go | keep | Matches `backend/go.mod`. GitHub has no container ecosystem; name the wallet image in prose. |
| Severity | High / 7.2 | keep the vector, not a hand-picked label | Use **Assess severity using CVSS** (or `cvss_vector_string`), not a separate `severity` enum. |

## Apply this packet to the draft GHSA

The local `gh` token in this workspace returned **403** on `PATCH` (`Resource not accessible by personal access token`). Use a token or GitHub App with **Repository security advisories: write**, or edit in the UI.

**UI (reliable):**

1. Open the advisory → **Edit advisory**.
2. Replace **Title** with: `Wallet harness SSRF via incomplete request_uri destination checks`.
3. Replace **Description** with the full contents of `GHSA-q7jr-2q6f-gw44.github-description.md` (overwrite the reporter PoC).
4. Affected product: Go / `github.com/ParleSec/ProtocolSoup` / affected `>= 2.0.0, <= 4.1.0` / patched *blank*.
5. Severity: **Assess using CVSS** → paste `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N`.
6. CWE: `CWE-918`. Credit: `EQSTLab` / Reporter.
7. **Update security advisory**. Re-read the preview: no `curl` exploit, no Dockerfile, no `poc.py`.
8. Only then **Request CVE**.

**API** (from `ProtocolLens/`):

```bash
gh api --method PATCH \
  /repos/ParleSec/ProtocolSoup/security-advisories/GHSA-q7jr-2q6f-gw44 \
  --input docs/security/GHSA-q7jr-2q6f-gw44.github-patch.json
```

## Ordered checklist (CVE-correct)

1. **Replace the GHSA description** with [github-description.md](GHSA-q7jr-2q6f-gw44.github-description.md). Confirm the UI no longer contains exploit commands or container build recipes.
2. **Set affected versions** to `>= 2.0.0, <= 4.1.0`. Ecosystem **Go**, package **`github.com/ParleSec/ProtocolSoup`**. Leave patched versions blank.
3. **Keep CWE-918** and **CVSS 3.1 vector** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N`.
4. **Accept reporter credit** for `EQSTLab` (GitHub: credits → reporter). Do not add extra credits unless someone else reported independently.
5. **Request CVE** on the draft (**Request CVE**, not **Publish advisory**). Wait for GitHub to attach `CVE-YYYY-NNNNN`. Typical turnaround is days, not minutes.
6. **Land the code fix** on `master` (wallet outbound URL policy). Do not put proof-of-concept files in the repository.
7. **Cut a patch release** from `master` per [release process](https://docs.protocolsoup.com/developers/release-process/) (`SECURITY.md`: security fixes land on the latest minor). Latest release is **v4.1.0**, so the fixing tag is **v4.1.1** unless a later tag already exists by then. Tags are immutable; do not retag v4.1.0.
8. **Edit the GHSA again**: set **Patched versions** to `4.1.1` (no `v` prefix). Add the release URL under References.
9. **Publish advisory**. This makes the GHSA public, starts GitHub Advisory Database review, and (with a CVE already assigned) completes public CVE publication.
10. **Deploy** `protocolsoup-wallet` so `wallet.protocolsoup.com` and GHCR `latest` are no longer vulnerable. Confirm `/health` `BUILD_COMMIT` is the patched SHA.
11. **Reply to the reporter** on the advisory (credit accepted, CVE id, patched tag).

Do **not**:

- Click **Publish advisory** before a patched tag exists unless you intentionally want a published vuln with no upgrade path.
- Request a CVE while the description still contains the reporter PoC.
- Open a public GitHub Issue that restates exploit steps.
- File a second CVE for `GET /authorize` or OID4VCI import: same helper, same CWE, same patch.
- Change `WALLET_ALLOW_EXTERNAL_VERIFIERS` default to `false` as the “fix.” That is a workaround for locked-down deploys; the hosted wallet still needs third-party `request_uri`.

## GitHub form fields (copy exactly)

| UI field | Value |
|----------|--------|
| Title / summary | Wallet harness SSRF via incomplete `request_uri` destination checks |
| CVE identifier | Request CVE ID later (until GitHub assigns one) |
| Ecosystem | Go |
| Package name | `github.com/ParleSec/ProtocolSoup` |
| Affected versions | `>= 2.0.0, <= 4.1.0` |
| Patched versions | *(empty until v4.1.1 exists)* then `4.1.1` |
| Vulnerable functions | leave empty (this is a `cmd` binary, not an exported library API) |
| Severity | CVSS 3.1 vector below (do not also set the High enum) |
| CWE | `CWE-918` |
| Credits | `EQSTLab`, type **Reporter** |

## CVSS 3.1 justification (keep 7.2)

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N`

| Metric | Value | Reason |
|--------|-------|--------|
| AV | Network | `POST /api/resolve` is a network HTTP API. Hosted wallet is Internet-reachable. |
| AC | Low | A public HTTPS URL that redirects, or a DNS name the wallet resolver will look up, is enough. No privileged position or race is required for the redirect path. |
| PR | None | No session, cookie, or bearer token is required. |
| UI | None | The attacker calls the API directly. |
| S | Changed | The wallet process reaches **other** HTTP authorities (internal listeners, link-local metadata) that are not the wallet's own security scope. |
| C | Low | Confirmed disclosure is a **non-2xx body oracle** plus whatever a 2xx compact JWS happens to contain. Not scored High: no demonstrated credential dump from IMDS in the reporter's confirmed impact. Operators with reachable cloud metadata should still treat this as urgent. |
| I | Low | The wallet can GET/POST to internal HTTP services with a fixed POST shape (`wallet_nonce`). Not arbitrary method/body, not RCE. |
| A | None | No crash or resource exhaustion was demonstrated. |

Do not raise to Critical without a demonstrated High confidentiality or integrity impact (for example, proven IMDS credential theft in the default hosted topology). Do not drop to Medium: unauthenticated, default-on, scope-changed SSRF with an oracle is High.

## Affected inventory (operators)

| Artifact | Vulnerable | Notes |
|----------|------------|--------|
| Git tags `v2.0.0` `v3.0.0` `v4.0.0` `v4.1.0` | Yes | First introduction: wallet harness on **v2.0.0**. |
| Git tag `v1.0.0` | No | No `validateExternalURL`. |
| `ghcr.io/parlesec/protocolsoup-wallet:v2.0.0` … `:v4.1.0` | Yes | Same tree as the git tag. |
| `ghcr.io/parlesec/protocolsoup-wallet:latest` | Yes until rebuild after the fix | Mutable; not a support pin. |
| `https://wallet.protocolsoup.com` | Yes until Fly deploy of the patched image | Default `WALLET_ALLOW_EXTERNAL_VERIFIERS=true`. |
| `protocolsoup-federation` / `protocolsoup-vc` / others | No | Different binaries. OIDC `request_uri` fetch in the federation image is a **separate** client with its own SSRF helper; out of scope for this GHSA unless a distinct bug is shown. |

## Patch mapping (code)

In-tree work for this GHSA (do not describe these as exploit steps in the CVE):

- `backend/cmd/walletharness/outbound.go` — resolve, prefix policy, redirect `CheckRedirect`, `DialContext` pin, no HTTP proxy.
- `backend/cmd/walletharness/main.go` — production client construction; `fetchRequestObject` validates first; non-2xx errors omit upstream bodies; RFC 9101 https for untrusted URLs.
- `backend/cmd/walletharness/outbound_test.go` — defensive tests (rejected destinations, no body leak, redirect not dialed).
- Wallet docs: `docs/packages/wallet.md`, `docs/starlight/src/content/docs/deploy/services/wallet.mdx`, `docs/starlight/src/content/docs/deploy/environment-variables.mdx`.

## Workaround (operations)

```text
WALLET_ALLOW_EXTERNAL_VERIFIERS=false
```

Effect: untrusted hosts are rejected before fetch. Looking Glass against the configured target/issuer still works. External verifiers and external OID4VCI import do not.

## Timeline

| When (UTC dates on the GHSA) | Event |
|------------------------------|--------|
| 2026-08-17 | EQSTLab submitted the private report (`GHSA-q7jr-2q6f-gw44`). |
| 2026-08-22 | Submission accepted; advisory remains `draft`. |
| *after description rewrite* | Request CVE. |
| *after merge + tag v4.1.1* | Set patched versions; publish GHSA; deploy wallet. |

## After GitHub assigns a CVE

1. Record `CVE-YYYY-NNNNN` in [security-advisories.mdx](../starlight/src/content/docs/developers/security-advisories.mdx) and in this table.
2. Add the CVE to the v4.1.1 release highlights (one sentence, link the GHSA, no PoC).
3. Do not edit `CHANGELOG.md` by hand (`git-cliff` overwrites it); the release highlights file / tag annotation is the place for the CVE sentence.
