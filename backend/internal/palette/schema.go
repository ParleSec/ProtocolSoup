package palette

// schemaDDL is the complete schema for the palette index. It is intentionally
// written as a single multi-statement script so the indexer can apply it as
// one Exec call and so its hash uniquely identifies the on-disk format
// version.
//
// The schema differs from the prose sketch in the prompt in one place: the
// aliases table uses a composite primary key so an ambiguous alias can map to
// multiple canonical targets (the prompt explicitly requires this behaviour;
// the sketched single-key schema does not).
const schemaDDL = `
CREATE VIRTUAL TABLE artefacts_fts USING fts5(
    id UNINDEXED,
    type UNINDEXED,
    name,
    body,
    aliases,
    tokenize='porter unicode61'
);

CREATE TABLE artefacts (
    id        TEXT PRIMARY KEY,
    type      TEXT NOT NULL,
    name      TEXT NOT NULL,
    protocol  TEXT,
    href      TEXT,
    runnable  INTEGER NOT NULL DEFAULT 0,
    status    TEXT NOT NULL,
    summary   TEXT,
    backend_id TEXT,
    payload   TEXT NOT NULL
);

CREATE TABLE axis_values (
    artefact_id TEXT NOT NULL,
    axis        TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (artefact_id, axis, value)
) WITHOUT ROWID;
CREATE INDEX idx_axis_values_value ON axis_values (axis, value);

CREATE TABLE edges (
    from_id TEXT NOT NULL,
    to_id   TEXT NOT NULL,
    kind    TEXT NOT NULL,
    PRIMARY KEY (from_id, to_id, kind)
) WITHOUT ROWID;
CREATE INDEX idx_edges_to ON edges (to_id);

CREATE TABLE aliases (
    alias     TEXT NOT NULL COLLATE NOCASE,
    canonical TEXT NOT NULL,
    axis      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (alias, canonical, axis)
) WITHOUT ROWID;
CREATE INDEX idx_aliases_alias ON aliases (alias COLLATE NOCASE);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
`

// EdgeKind is the closed set of edge relations stored in the edges table.
type EdgeKind string

const (
	// EdgeRelatedTo is a symmetric concept-to-concept link. The indexer
	// writes both directions so traversal does not need to consider order.
	EdgeRelatedTo EdgeKind = "related-to"

	// EdgePrerequisiteOf is a one-way link: the from artefact is a
	// prerequisite for understanding the to artefact.
	EdgePrerequisiteOf EdgeKind = "prerequisite-of"

	// EdgeGoverns is a one-way link from a spec-assertion artefact to
	// every artefact it normatively governs.
	EdgeGoverns EdgeKind = "governs"

	// EdgeProtocolOf is a one-way link from a flow to its protocol. It
	// makes flow ↔ protocol traversal cheap during the candidates stage.
	EdgeProtocolOf EdgeKind = "protocol-of"
)
