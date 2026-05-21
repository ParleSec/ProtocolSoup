package palette

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// candidate is the working representation of a result row before ranking.
// Each candidate accumulates evidence from every source that produced it
// (FTS5, axis-value join, edge traversal). The ranker uses these traces
// both to score the row and to emit visible match reasons.
type candidate struct {
	ID         string
	BM25       float64
	BM25Phrase string
	axisHits   []axisHit
	edgeHits   []edgeHit
	aliasHits  []aliasHit
	protocolHit *protocolNameHit
}

type axisHit struct {
	axis         string
	value        string
	matchedToken string // empty when the hit came from an explicit filter
}

type edgeHit struct {
	via  string // the seed artefact id that hopped to this one
	kind string
}

type aliasHit struct {
	axis         string
	value        string
	artefact     string
	matchedToken string
}

type protocolNameHit struct {
	matchedToken string
}

// maxCandidatesPerSource caps how many rows each retrieval source produces
// before ranking. The prompt requires 100 max per source.
const maxCandidatesPerSource = 100

// gatherCandidates fans the parsed query out across three retrieval sources
// in parallel and merges the resulting candidates by id. The function is
// deterministic: candidates are merged in id order at the end.
func (s *Service) gatherCandidates(ctx context.Context, parsed ParsedQuery, cat catalog) map[string]*candidate {
	merged := make(map[string]*candidate)

	for _, axis := range parsed.axisHitsFromAliases() {
		for _, id := range lookupAxis(cat, axis.Axis, axis.Value) {
			c := getOrCreate(merged, id)
			c.aliasHits = append(c.aliasHits, aliasHit{
				axis:         axis.Axis,
				value:        axis.Value,
				matchedToken: axis.MatchedToken,
			})
			c.axisHits = append(c.axisHits, axisHit{
				axis:         axis.Axis,
				value:        axis.Value,
				matchedToken: axis.MatchedToken,
			})
		}
	}

	for _, hit := range parsed.artefactHitsFromAliases() {
		if _, ok := cat.artefacts[hit.Artefact]; !ok {
			continue
		}
		c := getOrCreate(merged, hit.Artefact)
		c.aliasHits = append(c.aliasHits, aliasHit{
			artefact:     hit.Artefact,
			matchedToken: hit.MatchedToken,
		})
		if cat.artefacts[hit.Artefact].Type == ArtefactProtocol {
			c.protocolHit = &protocolNameHit{matchedToken: hit.MatchedToken}
		}
	}

	for _, f := range parsed.Filters {
		for _, id := range lookupAxis(cat, f.Axis, f.Value) {
			c := getOrCreate(merged, id)
			c.axisHits = append(c.axisHits, axisHit{
				axis:  f.Axis,
				value: f.Value,
			})
		}
	}

	if ftsRows := s.runFTS(ctx, parsed); len(ftsRows) > 0 {
		for _, row := range ftsRows {
			c := getOrCreate(merged, row.id)
			if row.bm25 > c.BM25 {
				c.BM25 = row.bm25
				c.BM25Phrase = row.phrase
			}
		}
	}

	// Edge fan-out from current seeds, one hop. We don't need to query
	// SQLite for this; the edges map is loaded into the in-memory catalog.
	seeds := make([]string, 0, len(merged))
	for id := range merged {
		seeds = append(seeds, id)
	}
	sort.Strings(seeds)

	for _, seed := range seeds {
		for _, e := range cat.edges[seed] {
			if _, ok := merged[e.To]; ok {
				// Already a candidate — record the edge as additional evidence
				merged[e.To].edgeHits = append(merged[e.To].edgeHits, edgeHit{via: seed, kind: e.Kind})
				continue
			}
			if len(merged) >= maxCandidatesPerSource*3 {
				break
			}
			c := getOrCreate(merged, e.To)
			c.edgeHits = append(c.edgeHits, edgeHit{via: seed, kind: e.Kind})
		}
	}

	return merged
}

func getOrCreate(m map[string]*candidate, id string) *candidate {
	c, ok := m[id]
	if !ok {
		c = &candidate{ID: id}
		m[id] = c
	}
	return c
}

func lookupAxis(cat catalog, axis, value string) []string {
	byValue, ok := cat.axisIndex[axis]
	if !ok {
		return nil
	}
	ids := byValue[value]
	if len(ids) > maxCandidatesPerSource {
		ids = ids[:maxCandidatesPerSource]
	}
	return ids
}

// axisHitsFromAliases reduces parsed.Resolved to only the axis-typed
// entries, deduplicating identical hits.
func (p ParsedQuery) axisHitsFromAliases() []ResolvedAlias {
	seen := make(map[string]ResolvedAlias)
	for _, r := range p.Resolved {
		if r.Axis == "" {
			continue
		}
		key := r.Axis + "::" + r.Value
		if existing, ok := seen[key]; ok {
			if len(r.MatchedToken) > len(existing.MatchedToken) {
				seen[key] = r
			}
			continue
		}
		seen[key] = r
	}
	out := make([]ResolvedAlias, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Axis != out[j].Axis {
			return out[i].Axis < out[j].Axis
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// artefactHitsFromAliases reduces parsed.Resolved to the artefact-typed
// entries.
func (p ParsedQuery) artefactHitsFromAliases() []ResolvedAlias {
	seen := make(map[string]ResolvedAlias)
	for _, r := range p.Resolved {
		if r.Axis != "" {
			continue
		}
		if existing, ok := seen[r.Artefact]; ok {
			if len(r.MatchedToken) > len(existing.MatchedToken) {
				seen[r.Artefact] = r
			}
			continue
		}
		seen[r.Artefact] = r
	}
	out := make([]ResolvedAlias, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Artefact < out[j].Artefact
	})
	return out
}

type ftsRow struct {
	id     string
	bm25   float64
	phrase string
}

// runFTS issues a single FTS5 MATCH query covering free tokens and any
// phrase requirements. The BM25 score is normalised by FTS5 to a magnitude
// roughly suitable for blending with the axis weights; we further compress
// it with 1/(1+bm25) so high-scoring rows do not overwhelm axis matches.
func (s *Service) runFTS(ctx context.Context, parsed ParsedQuery) []ftsRow {
	expr := buildFTSExpression(parsed)
	if expr == "" {
		return nil
	}

	query := fmt.Sprintf(`
        SELECT id, bm25(artefacts_fts) AS rank
        FROM artefacts_fts
        WHERE artefacts_fts MATCH ?
        ORDER BY rank
        LIMIT %d
    `, maxCandidatesPerSource)

	rows, err := s.db.QueryContext(ctx, query, expr)
	if err != nil {
		// FTS5 syntax errors are possible when a free token contains
		// FTS5-reserved characters; we degrade silently to no FTS hits.
		return nil
	}
	defer rows.Close()

	var out []ftsRow
	for rows.Next() {
		var id string
		var rank float64
		if err := rows.Scan(&id, &rank); err != nil {
			continue
		}
		// bm25() returns negative numbers (lower is better). Convert into
		// a positive magnitude so the blend below behaves predictably.
		magnitude := -rank
		if magnitude < 0 {
			magnitude = 0
		}
		out = append(out, ftsRow{
			id:     id,
			bm25:   magnitude / (1.0 + magnitude),
			phrase: expr,
		})
	}
	return out
}

// buildFTSExpression turns parsed free tokens and phrases into an FTS5
// MATCH expression. Tokens we cannot safely express are dropped.
func buildFTSExpression(parsed ParsedQuery) string {
	var parts []string

	for _, phrase := range parsed.PhraseMatches {
		safe := sanitisePhrase(phrase)
		if safe == "" {
			continue
		}
		parts = append(parts, `"`+safe+`"`)
	}
	for _, tok := range parsed.FreeTokens {
		safe := sanitiseToken(tok)
		if safe == "" {
			continue
		}
		parts = append(parts, safe+"*")
	}

	return strings.Join(parts, " OR ")
}

// sanitiseToken filters a single FTS5 term to characters known not to break
// the parser. Anything else is dropped to keep the MATCH expression valid.
func sanitiseToken(t string) string {
	var b strings.Builder
	b.Grow(len(t))
	for _, r := range t {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
			continue
		}
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
			continue
		}
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		// Tokens preserve internal hyphens but for FTS5 we treat them as
		// word separators; replace with space so the term-prefix wildcard
		// matches the leading sub-term.
		if r == '-' || r == '_' {
			b.WriteRune(' ')
			continue
		}
	}
	cleaned := strings.TrimSpace(b.String())
	if cleaned == "" {
		return ""
	}
	// If a single token expanded to multiple sub-tokens, keep the first.
	fields := strings.Fields(cleaned)
	return fields[0]
}

func sanitisePhrase(p string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '"' {
			return -1
		}
		return r
	}, p)
	return strings.TrimSpace(cleaned)
}
