# Content frontmatter schema

This file is the source of truth for the artefact frontmatter consumed by the
palette content validator (`backend/cmd/content-validate`) and the indexer
(`backend/cmd/palette-indexer`). The frontmatter is intentionally minimal and
declarative. Behavioural prose belongs in the artefact body, not in fields.

## File layout

```
content/
  taxonomy.yaml          # controlled vocabulary for every axis
  aliases.yaml           # synonym map
  SCHEMA.md              # this file
  protocols/             # one file per protocol catalog entry
    {protocol-id}.md
  flows/                 # one file per runnable flow definition
    {protocol-id}/
      {flow-id}.md
  concepts/              # one file per cross-cutting concept page
    {concept-id}.md
  walkthroughs/          # one file per long-form walkthrough
    {walkthrough-id}.md
  assertions/            # one file per spec assertion (auto-generated later)
    {assertion-id}.md
```

The validator discovers artefacts by walking `content/**/*.md`. The directory
relative to `content/` determines the artefact `type`:

| Directory       | Artefact type   |
| --------------- | --------------- |
| `protocols/`    | `protocol`      |
| `flows/`        | `flow`          |
| `concepts/`     | `concept`       |
| `walkthroughs/` | `walkthrough`   |
| `assertions/`   | `spec-assertion`|

## Frontmatter contract

Every artefact opens with a YAML document delimited by `---`. Unknown fields
fail validation; this prevents drift over time.

### Required fields

| Field            | Type              | Notes |
| ---------------- | ----------------- | ----- |
| `id`             | string            | Stable artefact id, kebab-case. Must match the filename. |
| `name`           | string            | Short human-readable name. |
| `use_cases`      | list[string]      | Each value must exist in `taxonomy.yaml#use_cases`. |
| `actors`         | list[string]      | Each value must exist in `taxonomy.yaml#actors`. |
| `problem_domains`| list[string]      | Each value must exist in `taxonomy.yaml#problem_domains`. |

### Recommended fields

| Field              | Type              | Notes |
| ------------------ | ----------------- | ----- |
| `protocol`         | string            | Protocol id this artefact belongs to. Required for `flow` artefacts. |
| `protocols`        | list[string]      | For cross-cutting concepts that span more than one protocol. Mutually exclusive with `protocol`. |
| `patterns`         | list[string]      | Each value must exist in `taxonomy.yaml#patterns`. |
| `related_concepts` | list[string]      | Concept artefact ids this artefact relates to. Each must resolve to an existing artefact. |
| `prerequisites`    | list[string]      | Artefact ids that should be understood first. Each must resolve to an existing artefact. |

### Optional fields

| Field               | Type           | Notes |
| ------------------- | -------------- | ----- |
| `normative_anchors` | list[object]   | List of `{rfc: string, sections: list[string]}` references. |
| `runnable`          | bool           | `true` for executable flows. Default `false`. |
| `status`            | string         | `live` (default), `planned`, or `deprecated`. |
| `href`              | string         | Canonical site URL. Defaults computed from `type` + `id`. **Ignored for inline-only types** (`concept`, `walkthrough`, `spec-assertion`); see "Inline-only artefacts" below. |
| `summary`           | string         | One-line summary surfaced as a result subtitle. Keep declarative. |
| `aliases`           | list[string]   | Free-form synonyms specific to this artefact, indexed in the FTS5 aliases column. |
| `backend_id`        | string         | Flow id used by the backend `/api/protocols/.../demo/...` endpoint. Required for runnable flows whose backend id differs from `id`. |

## Type-specific rules

### `protocol`

- File path: `content/protocols/{id}.md`
- `protocol` field must be omitted (the artefact *is* the protocol). The
  validator infers the protocol attribute from `id`.
- `runnable` is forced to `false`.

### `flow`

- File path: `content/flows/{protocol-id}/{id}.md`
- `protocol` is required and must equal the parent directory.
- `runnable` defaults to `true`. Set to `false` for non-executable flow walks.
- If `runnable` is `true` and the backend flow id differs from `id`, set
  `backend_id`.

### `concept`

- File path: `content/concepts/{id}.md`
- Either `protocol` or `protocols` may be set, depending on whether the
  concept is single-protocol or cross-cutting.
- `runnable` is forced to `false`.

### `walkthrough`

- File path: `content/walkthroughs/{id}.md`
- Must reference at least one flow via `related_concepts` or `prerequisites`.

### `spec-assertion`

- File path: `content/assertions/{id}.md`
- `normative_anchors` is required and must contain at least one entry.
- Additional field `normative_level` (one of `MUST`, `SHOULD`, `MAY`,
  `MUST NOT`, `SHOULD NOT`) is required.

## Inline-only artefacts

`concept`, `walkthrough`, and `spec-assertion` artefacts are **inline-only**:
their canonical surface is the palette's expanded result row (full markdown
body, normative anchors, related-concept chips) rather than a dedicated page
route. The Next.js app intentionally does not serve `/concept/{id}`,
`/walkthrough/{id}`, or `/assertion/{id}`.

Consequences for content authors:

- The `href` field is **ignored** for these types. The backend
  (`palette.Artefact.DefaultHref`) returns an empty string regardless of
  what frontmatter sets, so a phantom URL can never reach the surface.
- Keep the body self-contained: it must answer the user's query on its own,
  because the palette row is the final destination.
- Cross-link via `related_concepts` (and free-text references inside the
  body). Related-concept chips in the surface re-query the palette with
  the linked concept's id — they do not navigate to a page.

`protocol` and `flow` artefacts continue to have canonical pages
(`/protocol/{id}` and `/protocol/{protocolId}/flow/{flowId}`) and their
`href` field is honoured normally.

## Validation failures

The validator fails the build on any of:

- Unknown axis value (i.e. not present in `taxonomy.yaml`).
- Missing required field for the artefact type.
- Duplicate alias key in `aliases.yaml`.
- Edge reference to a non-existent artefact (via `related_concepts` or `prerequisites`).
- `id` does not match the filename stem.
- `flow` artefact whose `protocol` does not match the parent directory.
- Unknown top-level frontmatter field.
- Markdown file outside the recognised directories listed in **File layout**.

Run locally with:

```sh
cd ProtocolLens/backend
go run ./cmd/content-validate -content ../content
```

CI runs the same command on every PR that touches `content/**`.

## Body

The body that follows the frontmatter is plain markdown. It is indexed into
the FTS5 `body` column and presented in result rows as a short summary. Keep
it short, declarative, and free of marketing language. The first paragraph is
treated as the result-card subtitle when `summary` is not set.
