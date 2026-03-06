# ProtocolSoup Docs Platform POC (Phase 0 Day 1)

This folder is a platform-comparison sandbox for `docs.protocolsoup.com`.

It provides one shared documentation source for both candidate approaches:

- API-first (Redocly-style): OpenAPI linting and API reference rendering.
- Narrative-first with embedded API refs (Mintlify-style): docs IA and OpenAPI-driven endpoint pages.

## Day 1 Deliverables In This Folder

- IA skeleton pages for public docs:
  - `index.mdx`
  - `start-here/overview.mdx`
  - `ghcr/overview.mdx`
  - `api-reference/overview.mdx`
  - `protocols-and-specs/overview.mdx`
- OpenAPI seeds for representative POC services:
  - `openapi/gateway.yaml`
  - `openapi/scim.yaml`
- Candidate config files:
  - `docs.json` (Mintlify)
  - `redocly.yaml` (Redocly CLI)

## Quick Validation Commands

Run from `ProtocolLens/docs/poc`.

### Redocly-style Validation

```bash
npx @redocly/cli lint --config redocly.yaml gateway@v1 scim@v1
npx @redocly/cli build-docs openapi/gateway.yaml -o .tmp/gateway.html
npx @redocly/cli build-docs openapi/scim.yaml -o .tmp/scim.html
```

### Mintlify-style Validation

```bash
npx mint dev
```

Then open the local URL printed by the CLI and verify:

- navigation structure,
- API reference tab for both OpenAPI specs,
- endpoint page generation and search behavior.

## Notes

- These OpenAPI files are intentionally scoped to POC evaluation and are not the full production specs.
- POC updates should be reflected in `docs/DOCS_UPLIFT_PHASE0_SCORECARD.md`.
- If Mint local preview fails with an `EPERM` rename error for `C:\Users\<user>\.mintlify`, clear the stale `.mintlify` cache directory and retry.
