package palette

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	_ "modernc.org/sqlite"
)

// Scope values constrain results to one artefact type.
const (
	ScopeFlow     = "flow"
	ScopeProtocol = "protocol"
	ScopeSpec     = "spec"
	ScopeConcept  = "concept"
)

// scopeToType maps a Request.Scope value to an artefact type. Empty scope
// means "no scope filter".
var scopeToType = map[string]string{
	ScopeFlow:     ArtefactFlow,
	ScopeProtocol: ArtefactProtocol,
	ScopeSpec:     ArtefactSpecAssertion,
	ScopeConcept:  ArtefactConcept,
}

// Filter is one (axis, value) constraint applied to the result set. A request
// can carry any number of filters; they are AND-ed.
type Filter struct {
	Axis  string `json:"axis"`
	Value string `json:"value"`
}

// Request is the input to Service.Query. The shape matches what the HTTP
// handler accepts at POST /api/palette/query.
type Request struct {
	Q       string   `json:"q"`
	Scope   string   `json:"scope,omitempty"`
	Filters []Filter `json:"filters,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// MatchReason explains why a row surfaced. Each row carries one or two
// reasons selected by ranker weight. The query service never synthesises
// reasons on the frontend's behalf: every reason references a real row in
// the index.
type MatchReason struct {
	Kind          string  `json:"kind"`                     // axis | alias | fts | edge | runnable | protocol-name
	Axis          string  `json:"axis,omitempty"`           // for kind=axis | alias (when axis-typed)
	Value         string  `json:"value,omitempty"`          // for kind=axis | alias (when axis-typed)
	Artefact      string  `json:"artefact,omitempty"`       // for kind=alias (when artefact-typed) | edge
	MatchedToken  string  `json:"matched_token,omitempty"`  // the query substring that triggered the match
	MatchedPhrase string  `json:"matched_phrase,omitempty"` // for kind=fts: the FTS match snippet
	EdgeKind      string  `json:"edge_kind,omitempty"`      // for kind=edge
	Weight        float64 `json:"weight"`
}

// AxisChip is one labelled axis value rendered next to a result. Chips are
// taken from the artefact's own axis lists and prioritised so the most
// salient (e.g. matched) chips appear first.
type AxisChip struct {
	Axis  string `json:"axis"`
	Value string `json:"value"`
}

// Result is a single returned row. The shape matches the prompt's example
// response so frontend rendering does not need to translate.
type Result struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Name         string        `json:"name"`
	Summary      string        `json:"summary,omitempty"`
	Protocol     string        `json:"protocol,omitempty"`
	AxisChips    []AxisChip    `json:"axis_chips"`
	MatchReasons []MatchReason `json:"match_reasons"`
	Runnable     bool          `json:"runnable"`
	Href         string        `json:"href"`
	RunURL       string        `json:"run_url,omitempty"`
	Score        float64       `json:"score"`
	Status       string        `json:"status,omitempty"`

	// BodyPreview is a plain-text first-paragraph excerpt suitable for an
	// always-visible row summary. Distinct from Summary (which is the
	// frontmatter `summary:` field, written for navigation labels):
	// BodyPreview is the start of the actual answer.
	BodyPreview string `json:"body_preview,omitempty"`

	// Body is the full markdown body of the artefact. Returned on every
	// result so the selected row can render the full answer inline without
	// a second round-trip. The frontend renders it through a small markdown
	// component; no HTML is ever shipped from the backend.
	Body string `json:"body,omitempty"`

	// Snippet is a query-aware excerpt of Body, with the matching tokens
	// emitted as `<mark>` spans. Populated only when one of the free tokens
	// hit a region of Body. Empty otherwise; callers fall back to
	// BodyPreview when Snippet is empty.
	Snippet string `json:"snippet,omitempty"`

	// NormativeAnchors is the artefact's RFC/section list. Mirrored onto
	// the Result so frontends can render anchor chips next to spec-cited
	// concepts without re-reading the payload column.
	NormativeAnchors []NormativeAnchor `json:"normative_anchors,omitempty"`

	// RelatedConcepts is the artefact's `related_concepts:` list. Each
	// entry is an artefact id; the frontend resolves names by looking up
	// the id in the catalog (or by issuing follow-up queries via the chip).
	RelatedConcepts []string `json:"related_concepts,omitempty"`

	// SpecAssertion populates only for artefacts of type spec-assertion. The
	// frontend renders a normative-level pill and the assertion text.
	SpecAssertion *SpecAssertionDetails `json:"spec_assertion,omitempty"`
}

// SpecAssertionDetails carries the fields a spec-assertion result needs to
// render. Kept out of the base Result so other result types stay compact.
type SpecAssertionDetails struct {
	NormativeLevel string            `json:"normative_level"`
	AssertionText  string            `json:"assertion_text"`
	Anchors        []NormativeAnchor `json:"anchors"`
}

// RefinementChip is shown above the result list when intent is ambiguous
// along an axis. Clicking a chip adds it as a Filter in the next request.
type RefinementChip struct {
	Axis  string `json:"axis"`
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Response is the JSON returned from Service.Query.
type Response struct {
	Query            string           `json:"query"`
	Results          []Result         `json:"results"`
	RefinementChips  []RefinementChip `json:"refinement_chips"`
	ResolvedAliases  []ResolvedAlias  `json:"resolved_aliases"`
	TotalCandidates  int              `json:"total_candidates"`
	ElapsedMicros    int64            `json:"elapsed_micros"`
}

// Weights tunes scoring per axis. Use-case matches outrank everything else,
// protocol-name aliases second, patterns and actors third. Adjusted in
// tests; never tuned per-request.
type Weights struct {
	BM25            float64
	UseCase         float64
	ProblemDomain   float64
	Actor           float64
	Pattern         float64
	ProtocolName    float64
	Edge            float64
	RunnableBoost   float64
	AliasArtefact   float64
	StatusLivePref  float64
}

// DefaultWeights returns the production weight schedule.
func DefaultWeights() Weights {
	return Weights{
		BM25:           1.0,
		UseCase:        4.0,
		ProblemDomain:  2.0,
		Actor:          1.5,
		Pattern:        1.5,
		ProtocolName:   3.0,
		Edge:           0.5,
		RunnableBoost:  1.0,
		AliasArtefact:  3.5,
		StatusLivePref: 0.25,
	}
}

// Stats reports whether the palette index is loaded and how large it is.
type Stats struct {
	Loaded        bool   `json:"loaded"`
	ArtefactCount int    `json:"artefact_count"`
	IndexVersion  string `json:"index_version"`
}

// Stats returns a snapshot of palette service state for health checks.
func (s *Service) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		Loaded:        s != nil && !s.closed,
		ArtefactCount: len(s.catalog.artefacts),
		IndexVersion:  IndexVersion,
	}
}

// Service is the in-memory query service. It opens the SQLite palette file
// once at construction time and serves concurrent queries from prepared
// statements. The DB is held in process memory after first access via
// SQLite's mmap, but we additionally cache the artefacts table in a
// catalog so reasoning over results does not require extra round-trips.
type Service struct {
	db      *sql.DB
	weights Weights
	catalog catalog
	closed  bool
	mu      sync.RWMutex
}

// catalog holds the small static tables in memory. Reloading is cheap
// because the index is small (<200 KB for the current corpus).
type catalog struct {
	artefacts map[string]ArtefactPayload
	axisIndex map[string]map[string][]string // axis -> value -> []artefactID
	edges     map[string][]edgeRow           // from -> []edge
	aliases   map[string][]aliasRow          // lower(alias) -> []alias-row
}

type edgeRow struct {
	To   string
	Kind string
}

type aliasRow struct {
	Canonical string
	Axis      string // "" for artefact-typed aliases
}

// NewService opens the palette database at dbPath, primes the catalog, and
// returns a ready-to-serve Service.
func NewService(dbPath string) (*Service, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=mmap_size(67108864)")
	if err != nil {
		return nil, fmt.Errorf("open palette db: %w", err)
	}
	db.SetMaxOpenConns(8)

	svc := &Service{db: db, weights: DefaultWeights()}
	if err := svc.loadCatalog(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return svc, nil
}

// SetWeights overrides the default weights. Mainly used in tests.
func (s *Service) SetWeights(w Weights) {
	s.mu.Lock()
	s.weights = w
	s.mu.Unlock()
}

// Close releases the underlying database handle.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func (s *Service) loadCatalog() error {
	c := catalog{
		artefacts: make(map[string]ArtefactPayload),
		axisIndex: make(map[string]map[string][]string),
		edges:     make(map[string][]edgeRow),
		aliases:   make(map[string][]aliasRow),
	}

	rows, err := s.db.Query(`SELECT id, payload FROM artefacts`)
	if err != nil {
		return fmt.Errorf("load artefacts: %w", err)
	}
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			rows.Close()
			return err
		}
		var p ArtefactPayload
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			rows.Close()
			return fmt.Errorf("decode payload for %s: %w", id, err)
		}
		c.artefacts[id] = p
	}
	rows.Close()

	axisRows, err := s.db.Query(`SELECT artefact_id, axis, value FROM axis_values`)
	if err != nil {
		return fmt.Errorf("load axis_values: %w", err)
	}
	for axisRows.Next() {
		var artefactID, axis, value string
		if err := axisRows.Scan(&artefactID, &axis, &value); err != nil {
			axisRows.Close()
			return err
		}
		byValue, ok := c.axisIndex[axis]
		if !ok {
			byValue = make(map[string][]string)
			c.axisIndex[axis] = byValue
		}
		byValue[value] = append(byValue[value], artefactID)
	}
	axisRows.Close()
	for _, byValue := range c.axisIndex {
		for v := range byValue {
			sort.Strings(byValue[v])
		}
	}

	edgeRows, err := s.db.Query(`SELECT from_id, to_id, kind FROM edges`)
	if err != nil {
		return fmt.Errorf("load edges: %w", err)
	}
	for edgeRows.Next() {
		var from, to, kind string
		if err := edgeRows.Scan(&from, &to, &kind); err != nil {
			edgeRows.Close()
			return err
		}
		c.edges[from] = append(c.edges[from], edgeRow{To: to, Kind: kind})
	}
	edgeRows.Close()

	aliasRows, err := s.db.Query(`SELECT alias, canonical, axis FROM aliases`)
	if err != nil {
		return fmt.Errorf("load aliases: %w", err)
	}
	for aliasRows.Next() {
		var alias, canonical, axis string
		if err := aliasRows.Scan(&alias, &canonical, &axis); err != nil {
			aliasRows.Close()
			return err
		}
		c.aliases[alias] = append(c.aliases[alias], aliasRow{Canonical: canonical, Axis: axis})
	}
	aliasRows.Close()

	s.catalog = c
	return nil
}

// Query runs the full retrieval pipeline against the catalog and the
// underlying FTS5 index. It is concurrency-safe: multiple queries can run
// in parallel against the read-only DB handle.
func (s *Service) Query(ctx context.Context, req Request) (Response, error) {
	s.mu.RLock()
	weights := s.weights
	cat := s.catalog
	s.mu.RUnlock()

	limit := req.Limit
	if limit <= 0 || limit > 50 {
		limit = 20
	}

	parsed := parseQuery(req, cat)

	cands := s.gatherCandidates(ctx, parsed, cat)

	results, refinement := rankCandidates(cands, parsed, cat, weights, limit)

	return Response{
		Query:           parsed.Original,
		Results:         results,
		RefinementChips: refinement,
		ResolvedAliases: parsed.Resolved,
		TotalCandidates: len(cands),
	}, nil
}
