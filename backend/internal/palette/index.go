package palette

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// IndexVersion is the on-disk format version. Bump when the schema or the
// emitted JSON payload shape changes in a way clients must observe.
const IndexVersion = "1"

// BuildIndex constructs a SQLite palette index at outPath from the content
// tree rooted at contentRoot. The function is deterministic: with identical
// inputs it produces a byte-identical SQLite file, which lets CI compare
// build artefacts and lets atomic deploys be byte-precise.
//
// The build runs in three steps:
//
//  1. Validate the content tree. Any issue aborts the build; the indexer
//     refuses to emit a partial database.
//  2. Open a fresh SQLite database at a temporary path, apply schema, and
//     insert every row in deterministic order.
//  3. VACUUM the database so the file is compact and reproducible, then
//     atomically rename it into place.
//
// On any error the temporary file is removed.
func BuildIndex(contentRoot, outPath string) error {
	artefacts, taxonomy, aliasesFile, issues, err := ValidateContent(contentRoot)
	if err != nil {
		return fmt.Errorf("validate content: %w", err)
	}
	if len(issues) > 0 {
		var lines []string
		for _, i := range issues {
			lines = append(lines, i.Format())
		}
		return fmt.Errorf("content has %d validation issue(s):\n  %s", len(issues), strings.Join(lines, "\n  "))
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	tmpPath := outPath + ".tmp"
	_ = os.Remove(tmpPath)
	_ = os.Remove(outPath)

	if err := buildIntoFile(tmpPath, artefacts, taxonomy, aliasesFile); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, outPath, err)
	}
	return nil
}

func buildIntoFile(path string, artefacts []Artefact, taxonomy Taxonomy, aliases AliasesFile) error {
	dsn := fmt.Sprintf("file:%s?_pragma=page_size(4096)&_pragma=journal_mode(off)&_pragma=synchronous(off)&_pragma=locking_mode(exclusive)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schemaDDL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }

	if err := insertArtefacts(tx, artefacts); err != nil {
		rollback()
		return err
	}
	if err := insertAxisValues(tx, artefacts); err != nil {
		rollback()
		return err
	}
	if err := insertEdges(tx, artefacts); err != nil {
		rollback()
		return err
	}
	if err := insertAliases(tx, aliases); err != nil {
		rollback()
		return err
	}
	if err := insertMeta(tx, taxonomy); err != nil {
		rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	return nil
}

func insertArtefacts(tx *sql.Tx, artefacts []Artefact) error {
	stmtMain, err := tx.Prepare(`
        INSERT INTO artefacts(id, type, name, protocol, href, runnable, status, summary, backend_id, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		return fmt.Errorf("prepare artefacts: %w", err)
	}
	defer stmtMain.Close()

	stmtFTS, err := tx.Prepare(`
        INSERT INTO artefacts_fts(id, type, name, body, aliases)
        VALUES (?, ?, ?, ?, ?)
    `)
	if err != nil {
		return fmt.Errorf("prepare artefacts_fts: %w", err)
	}
	defer stmtFTS.Close()

	sorted := make([]Artefact, len(artefacts))
	copy(sorted, artefacts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	for _, a := range sorted {
		runnable := 0
		if a.IsRunnable() {
			runnable = 1
		}
		payload, err := buildPayload(a)
		if err != nil {
			return fmt.Errorf("payload for %s: %w", a.ID, err)
		}

		protocol := a.Protocol
		if protocol == "" && len(a.Protocols) == 1 {
			protocol = a.Protocols[0]
		}
		if protocol == "" && a.Type == ArtefactProtocol {
			protocol = a.ID
		}

		if _, err := stmtMain.Exec(
			a.ID,
			a.Type,
			a.Name,
			nullableString(protocol),
			a.DefaultHref(),
			runnable,
			a.EffectiveStatus(),
			nullableString(a.Summary),
			nullableString(a.BackendID),
			payload,
		); err != nil {
			return fmt.Errorf("insert artefact %s: %w", a.ID, err)
		}

		body := a.Body
		aliasesField := strings.Join(a.Aliases, " ")
		if _, err := stmtFTS.Exec(a.ID, a.Type, a.Name, body, aliasesField); err != nil {
			return fmt.Errorf("insert artefacts_fts %s: %w", a.ID, err)
		}
	}
	return nil
}

func insertAxisValues(tx *sql.Tx, artefacts []Artefact) error {
	stmt, err := tx.Prepare(`INSERT INTO axis_values(artefact_id, axis, value) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare axis_values: %w", err)
	}
	defer stmt.Close()

	type axisRow struct{ artefact, axis, value string }
	var rows []axisRow
	for _, a := range artefacts {
		for _, v := range a.UseCases {
			rows = append(rows, axisRow{a.ID, AxisUseCases, v})
		}
		for _, v := range a.Actors {
			rows = append(rows, axisRow{a.ID, AxisActors, v})
		}
		for _, v := range a.Patterns {
			rows = append(rows, axisRow{a.ID, AxisPatterns, v})
		}
		for _, v := range a.ProblemDomains {
			rows = append(rows, axisRow{a.ID, AxisProblemDomains, v})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].artefact != rows[j].artefact {
			return rows[i].artefact < rows[j].artefact
		}
		if rows[i].axis != rows[j].axis {
			return rows[i].axis < rows[j].axis
		}
		return rows[i].value < rows[j].value
	})
	for _, r := range rows {
		if _, err := stmt.Exec(r.artefact, r.axis, r.value); err != nil {
			return fmt.Errorf("insert axis_values (%s, %s, %s): %w", r.artefact, r.axis, r.value, err)
		}
	}
	return nil
}

func insertEdges(tx *sql.Tx, artefacts []Artefact) error {
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO edges(from_id, to_id, kind) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare edges: %w", err)
	}
	defer stmt.Close()

	type edgeRow struct {
		from string
		to   string
		kind string
	}
	var rows []edgeRow
	for _, a := range artefacts {
		for _, ref := range a.RelatedConcepts {
			rows = append(rows, edgeRow{a.ID, ref, string(EdgeRelatedTo)})
			rows = append(rows, edgeRow{ref, a.ID, string(EdgeRelatedTo)})
		}
		for _, ref := range a.Prerequisites {
			rows = append(rows, edgeRow{ref, a.ID, string(EdgePrerequisiteOf)})
		}
		if a.Type == ArtefactFlow && a.Protocol != "" {
			rows = append(rows, edgeRow{a.ID, a.Protocol, string(EdgeProtocolOf)})
			rows = append(rows, edgeRow{a.Protocol, a.ID, string(EdgeProtocolOf)})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].from != rows[j].from {
			return rows[i].from < rows[j].from
		}
		if rows[i].to != rows[j].to {
			return rows[i].to < rows[j].to
		}
		return rows[i].kind < rows[j].kind
	})
	for _, r := range rows {
		if _, err := stmt.Exec(r.from, r.to, r.kind); err != nil {
			return fmt.Errorf("insert edges (%s, %s, %s): %w", r.from, r.to, r.kind, err)
		}
	}
	return nil
}

func insertAliases(tx *sql.Tx, file AliasesFile) error {
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO aliases(alias, canonical, axis) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare aliases: %w", err)
	}
	defer stmt.Close()

	type aliasRow struct {
		alias     string
		canonical string
		axis      string
	}
	var rows []aliasRow
	for _, entry := range file.Aliases {
		alias := strings.ToLower(strings.TrimSpace(entry.Alias))
		for _, c := range entry.Canonical {
			if c.Axis != "" {
				rows = append(rows, aliasRow{alias, c.Value, c.Axis})
			} else {
				rows = append(rows, aliasRow{alias, c.Artefact, ""})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].alias != rows[j].alias {
			return rows[i].alias < rows[j].alias
		}
		if rows[i].axis != rows[j].axis {
			return rows[i].axis < rows[j].axis
		}
		return rows[i].canonical < rows[j].canonical
	})
	for _, r := range rows {
		if _, err := stmt.Exec(r.alias, r.canonical, r.axis); err != nil {
			return fmt.Errorf("insert alias (%s, %s, %s): %w", r.alias, r.canonical, r.axis, err)
		}
	}
	return nil
}

func insertMeta(tx *sql.Tx, taxonomy Taxonomy) error {
	stmt, err := tx.Prepare(`INSERT INTO meta(key, value) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare meta: %w", err)
	}
	defer stmt.Close()

	keys := []struct{ k, v string }{
		{"index_version", IndexVersion},
		{"axes", strings.Join(AllAxes, ",")},
		{"use_cases_count", fmt.Sprintf("%d", len(taxonomy.UseCases))},
		{"actors_count", fmt.Sprintf("%d", len(taxonomy.Actors))},
		{"patterns_count", fmt.Sprintf("%d", len(taxonomy.Patterns))},
		{"problem_domains_count", fmt.Sprintf("%d", len(taxonomy.ProblemDomains))},
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].k < keys[j].k })
	for _, kv := range keys {
		if _, err := stmt.Exec(kv.k, kv.v); err != nil {
			return fmt.Errorf("insert meta (%s): %w", kv.k, err)
		}
	}
	return nil
}

// ArtefactPayload is the JSON shape stored in artefacts.payload. The query
// service reads this column to assemble result rows without rejoining axis
// tables, so the shape is intentionally redundant but stable.
type ArtefactPayload struct {
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	Protocol         string            `json:"protocol,omitempty"`
	Protocols        []string          `json:"protocols,omitempty"`
	UseCases         []string          `json:"use_cases"`
	Actors           []string          `json:"actors"`
	Patterns         []string          `json:"patterns,omitempty"`
	ProblemDomains   []string          `json:"problem_domains"`
	RelatedConcepts  []string          `json:"related_concepts,omitempty"`
	Prerequisites    []string          `json:"prerequisites,omitempty"`
	NormativeAnchors []NormativeAnchor `json:"normative_anchors,omitempty"`
	NormativeLevel   string            `json:"normative_level,omitempty"`
	AssertionText    string            `json:"assertion_text,omitempty"`
	Runnable         bool              `json:"runnable"`
	Status           string            `json:"status"`
	Href             string            `json:"href"`
	Summary          string            `json:"summary,omitempty"`
	BackendID        string            `json:"backend_id,omitempty"`
	Aliases          []string          `json:"aliases,omitempty"`

	// Body holds the full markdown body of the artefact. Kept in the payload
	// so the query service can stream the answer text inline with results
	// without a second fetch — the corpus is small enough that the
	// memory/disk cost is negligible. Use BodyPreview for list summaries.
	Body string `json:"body,omitempty"`

	// BodyPreview is the first paragraph of Body with markdown stripped and
	// truncated for inline display. Always safe to render as plain text.
	BodyPreview string `json:"body_preview,omitempty"`
}

func buildPayload(a Artefact) (string, error) {
	p := ArtefactPayload{
		ID:               a.ID,
		Type:             a.Type,
		Name:             a.Name,
		Protocol:         a.Protocol,
		Protocols:        a.Protocols,
		UseCases:         a.UseCases,
		Actors:           a.Actors,
		Patterns:         a.Patterns,
		ProblemDomains:   a.ProblemDomains,
		RelatedConcepts:  a.RelatedConcepts,
		Prerequisites:    a.Prerequisites,
		NormativeAnchors: a.NormativeAnchors,
		NormativeLevel:   a.NormativeLevel,
		AssertionText:    a.AssertionText,
		Runnable:         a.IsRunnable(),
		Status:           a.EffectiveStatus(),
		Href:             a.DefaultHref(),
		Summary:          a.Summary,
		BackendID:        a.BackendID,
		Aliases:          a.Aliases,
		Body:             a.Body,
		BodyPreview:      a.PlainTextPreview(280),
	}
	buf, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
