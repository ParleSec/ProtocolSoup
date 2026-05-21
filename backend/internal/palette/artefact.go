// Package palette contains the content substrate, indexer, and query service
// for the ProtocolSoup multi-axis content retrieval surface ("palette"). All
// retrieval is deterministic: no embeddings, no LLM calls, no probabilistic
// ranking. The package is split across files by stage so each stage can be
// tested in isolation.
//
// File map:
//
//	artefact.go   - artefact and frontmatter types + filesystem walking
//	taxonomy.go   - taxonomy.yaml and aliases.yaml types + loading
//	validate.go   - validation rules used by content-validate and the indexer
//	schema.go     - SQLite DDL constants used by the indexer
//	index.go      - palette.db construction (idempotent)
//	parse.go      - query tokenisation and alias resolution
//	candidates.go - FTS5/axis/edge candidate retrieval
//	rank.go       - deterministic ranking and match-reason emission
//	query.go      - Service.Query() entry point
//	api.go        - HTTP handler for POST /api/palette/query
package palette

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// mdLinkPattern matches a markdown link [text](url) and captures the text.
// We use this in stripInlineMarkdown to keep link text in the preview but
// drop the URL.
var mdLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)

// Artefact types recognised by the validator and indexer. The set is closed.
const (
	ArtefactProtocol      = "protocol"
	ArtefactFlow          = "flow"
	ArtefactConcept       = "concept"
	ArtefactWalkthrough   = "walkthrough"
	ArtefactSpecAssertion = "spec-assertion"
)

// Status values recognised on artefact frontmatter.
const (
	StatusLive       = "live"
	StatusPlanned    = "planned"
	StatusDeprecated = "deprecated"
)

// Normative-level values recognised on spec-assertion artefacts.
var NormativeLevels = map[string]struct{}{
	"MUST":       {},
	"SHOULD":     {},
	"MAY":        {},
	"MUST NOT":   {},
	"SHOULD NOT": {},
}

// dirToType maps the directory immediately under content/ to an artefact type.
// Markdown files outside these directories are a validation error so the file
// layout is enforced.
var dirToType = map[string]string{
	"protocols":    ArtefactProtocol,
	"flows":        ArtefactFlow,
	"concepts":     ArtefactConcept,
	"walkthroughs": ArtefactWalkthrough,
	"assertions":   ArtefactSpecAssertion,
}

// NormativeAnchor is one RFC/section reference. Sections is a free-form list
// of section identifiers (e.g. "4.1.3"). The JSON tags lowercase the field
// names so they match the frontend types and the documented response shape;
// without them Go would emit "RFC"/"Sections" which crashes lowercase-aware
// consumers.
type NormativeAnchor struct {
	RFC      string   `yaml:"rfc"      json:"rfc"`
	Sections []string `yaml:"sections" json:"sections"`
}

// Artefact is the parsed frontmatter of a single content file plus the
// markdown body. Type, Path, ProtocolFromDir and Body are filled in by the
// walker and are not represented in the YAML frontmatter directly.
type Artefact struct {
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	Protocol         string            `yaml:"protocol,omitempty"`
	Protocols        []string          `yaml:"protocols,omitempty"`
	UseCases         []string          `yaml:"use_cases,omitempty"`
	Actors           []string          `yaml:"actors,omitempty"`
	Patterns         []string          `yaml:"patterns,omitempty"`
	ProblemDomains   []string          `yaml:"problem_domains,omitempty"`
	RelatedConcepts  []string          `yaml:"related_concepts,omitempty"`
	Prerequisites    []string          `yaml:"prerequisites,omitempty"`
	NormativeAnchors []NormativeAnchor `yaml:"normative_anchors,omitempty"`
	NormativeLevel   string            `yaml:"normative_level,omitempty"`
	Runnable         *bool             `yaml:"runnable,omitempty"`
	Status           string            `yaml:"status,omitempty"`
	Href             string            `yaml:"href,omitempty"`
	Summary          string            `yaml:"summary,omitempty"`
	Aliases          []string          `yaml:"aliases,omitempty"`
	BackendID        string            `yaml:"backend_id,omitempty"`
	AssertionText    string            `yaml:"assertion_text,omitempty"`

	Type            string `yaml:"-"`
	Path            string `yaml:"-"`
	ProtocolFromDir string `yaml:"-"`
	Body            string `yaml:"-"`
}

// allowedFrontmatterFields is the closed set of frontmatter keys. Unknown keys
// are a validation error so frontmatter stays under positive control.
var allowedFrontmatterFields = map[string]struct{}{
	"id":                {},
	"name":              {},
	"protocol":          {},
	"protocols":         {},
	"use_cases":         {},
	"actors":            {},
	"patterns":          {},
	"problem_domains":   {},
	"related_concepts":  {},
	"prerequisites":     {},
	"normative_anchors": {},
	"normative_level":   {},
	"runnable":          {},
	"status":            {},
	"href":              {},
	"summary":           {},
	"aliases":           {},
	"backend_id":        {},
	"assertion_text":    {},
}

// IsRunnable reports whether the artefact is runnable, applying the type
// defaults. Flows default to true, everything else defaults to false.
func (a Artefact) IsRunnable() bool {
	if a.Runnable != nil {
		return *a.Runnable
	}
	return a.Type == ArtefactFlow
}

// EffectiveStatus returns the explicit status or the default ("live") when
// none is set on the artefact.
func (a Artefact) EffectiveStatus() string {
	if a.Status == "" {
		return StatusLive
	}
	return a.Status
}

// DefaultHref returns the canonical site URL for an artefact, or the empty
// string for artefact types that are inline-only.
//
// Concepts, walkthroughs, and spec-assertions are inline-only by design:
// their canonical surface is the palette's expanded row (full markdown body,
// normative anchors, related-concept chips). No /concept/{id},
// /walkthrough/{id}, or /assertion/{id} route exists in the Next.js app, so
// returning an empty href is the explicit signal to the frontend to skip
// router.push and hide "Open page" affordances for those types.
//
// An empty href is returned for these types even when the frontmatter sets
// `href` explicitly — earlier content baked `/concept/{id}` into the
// frontmatter, and we never want to ship a link that 404s. If/when a
// canonical concept page route is added, this rule moves and the explicit
// `href` field starts to be honoured again.
func (a Artefact) DefaultHref() string {
	switch a.Type {
	case ArtefactConcept, ArtefactWalkthrough, ArtefactSpecAssertion:
		return ""
	}
	if a.Href != "" {
		return a.Href
	}
	switch a.Type {
	case ArtefactProtocol:
		return "/protocol/" + a.ID
	case ArtefactFlow:
		if a.Protocol != "" {
			return "/protocol/" + a.Protocol + "/flow/" + a.ID
		}
		return "/looking-glass"
	}
	return "/"
}

// PlainTextPreview returns the first paragraph of the artefact body with
// markdown stripped, truncated to maxChars on a word boundary. Used by the
// indexer to bake an always-displayable preview into the payload, so the
// frontend can show "search-result snippets" without re-parsing the body.
// A paragraph break is two consecutive newlines (the convention every
// artefact body in content/ follows).
func (a Artefact) PlainTextPreview(maxChars int) string {
	if a.Body == "" {
		return ""
	}
	// First paragraph: everything up to the first blank line.
	end := strings.Index(a.Body, "\n\n")
	first := a.Body
	if end >= 0 {
		first = a.Body[:end]
	}
	first = strings.TrimSpace(first)

	// Strip a leading heading marker if the first paragraph happens to be a
	// single `# Heading` line (kept short and human-readable that way).
	if strings.HasPrefix(first, "#") {
		first = strings.TrimLeft(first, "# ")
	}

	plain := stripInlineMarkdown(first)
	plain = collapseWhitespace(plain)
	if maxChars <= 0 || len(plain) <= maxChars {
		return plain
	}
	// Truncate on a word boundary when possible, append a unicode ellipsis.
	cut := plain[:maxChars]
	if sp := strings.LastIndex(cut, " "); sp > maxChars/2 {
		cut = cut[:sp]
	}
	return strings.TrimRight(cut, " ,.;:") + "..."
}

// stripInlineMarkdown removes the inline markdown syntax used in the
// content corpus: backticks for code, **bold**, *italic*, and link syntax
// `[text](url)` → `text`. The full body keeps the markdown; this is for the
// preview field only.
func stripInlineMarkdown(s string) string {
	// Links: [text](url) → text
	s = mdLinkPattern.ReplaceAllString(s, "$1")
	// Bold/italic: leave inner text, drop the markers.
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "__", "")
	// Backticks → keep the content, drop the marker.
	s = strings.ReplaceAll(s, "`", "")
	return s
}

func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastWasSpace := false
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		if r == ' ' {
			if lastWasSpace {
				continue
			}
			lastWasSpace = true
		} else {
			lastWasSpace = false
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// ProtocolList returns the set of protocols an artefact relates to, drawn
// from Protocol (single-protocol) or Protocols (cross-cutting) or the
// directory-inferred protocol for flows.
func (a Artefact) ProtocolList() []string {
	if len(a.Protocols) > 0 {
		out := make([]string, len(a.Protocols))
		copy(out, a.Protocols)
		return out
	}
	if a.Protocol != "" {
		return []string{a.Protocol}
	}
	if a.Type == ArtefactProtocol {
		return []string{a.ID}
	}
	if a.ProtocolFromDir != "" {
		return []string{a.ProtocolFromDir}
	}
	return nil
}

// ContentReader walks a content directory and parses every markdown file into
// an Artefact. It returns artefacts sorted by Path so downstream output is
// stable (which the indexer relies on for byte-identical builds).
type ContentReader struct {
	Root string
}

// Read parses every artefact under Root. It does not validate cross-artefact
// references; that is the validator's job. Returns artefacts sorted by Path.
func (r ContentReader) Read() ([]Artefact, error) {
	var artefacts []Artefact

	err := filepath.WalkDir(r.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		base := filepath.Base(path)
		if base == "SCHEMA.md" || strings.HasPrefix(base, ".") {
			return nil
		}

		rel, err := filepath.Rel(r.Root, path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		artefact, err := parseArtefactFile(path, rel)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		artefacts = append(artefacts, artefact)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(artefacts, func(i, j int) bool {
		return artefacts[i].Path < artefacts[j].Path
	})
	return artefacts, nil
}

// parseArtefactFile reads a single content file and parses the YAML
// frontmatter delimited by `---`. The first `---` must be on line 1.
func parseArtefactFile(absPath, relPath string) (Artefact, error) {
	parts := strings.SplitN(relPath, "/", 3)
	if len(parts) < 2 {
		return Artefact{}, fmt.Errorf("markdown file outside recognised directory: %s", relPath)
	}
	topDir := parts[0]
	artefactType, ok := dirToType[topDir]
	if !ok {
		return Artefact{}, fmt.Errorf("markdown file under unknown directory %q (expected one of protocols/, flows/, concepts/, walkthroughs/, assertions/)", topDir)
	}

	frontmatter, body, err := readFrontmatter(absPath)
	if err != nil {
		return Artefact{}, err
	}

	if err := assertNoUnknownFields(frontmatter); err != nil {
		return Artefact{}, err
	}

	var a Artefact
	if err := yaml.Unmarshal(frontmatter, &a); err != nil {
		return Artefact{}, fmt.Errorf("invalid frontmatter YAML: %w", err)
	}
	a.Type = artefactType
	a.Path = relPath
	a.Body = body

	if artefactType == ArtefactFlow && len(parts) >= 3 {
		a.ProtocolFromDir = parts[1]
	}

	return a, nil
}

func readFrontmatter(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	if !scanner.Scan() {
		return nil, "", fmt.Errorf("empty file")
	}
	if strings.TrimRight(scanner.Text(), "\r") != "---" {
		return nil, "", fmt.Errorf("missing frontmatter: file must start with ---")
	}

	var fm strings.Builder
	closed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimRight(line, "\r") == "---" {
			closed = true
			break
		}
		fm.WriteString(line)
		fm.WriteByte('\n')
	}
	if !closed {
		return nil, "", fmt.Errorf("unterminated frontmatter: missing closing ---")
	}

	var body strings.Builder
	for scanner.Scan() {
		body.WriteString(scanner.Text())
		body.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return []byte(fm.String()), strings.TrimSpace(body.String()), nil
}

// assertNoUnknownFields walks the frontmatter as a generic YAML map and
// rejects any unknown top-level keys. We do this in a separate pass instead
// of using yaml.Unmarshal strict mode so that the error message can name the
// offending key without aborting on the first unknown field encountered by
// the Decoder.
func assertNoUnknownFields(raw []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return fmt.Errorf("invalid frontmatter YAML: %w", err)
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return nil
	}
	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("frontmatter must be a YAML mapping at the top level")
	}
	var unknown []string
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i].Value
		if _, ok := allowedFrontmatterFields[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown frontmatter fields: %s", strings.Join(unknown, ", "))
	}
	return nil
}
