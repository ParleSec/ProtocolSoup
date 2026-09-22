package conformance

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// SourceRepository is the GitHub repository that hosts the code the verdicts
// describe. Source links are pinned to the report commit so they always show
// the exact lines that produced a verdict.
const SourceRepository = "https://github.com/ParleSec/ProtocolSoup"

// cacheControl matches the revalidation window the frontend uses for these
// responses.
const cacheControl = "public, max-age=300"

// SpecsResponse is the body of GET /api/conformance/specs.
type SpecsResponse struct {
	ReportValid    bool          `json:"report_valid"`
	LaunchGateOpen bool          `json:"launch_gate_open"`
	Commit         string        `json:"commit,omitempty"`
	GeneratedAt    string        `json:"generated_at,omitempty"`
	Specs          []SpecSummary `json:"specs"`
}

// SpecSummary describes one specification in listings.
type SpecSummary struct {
	ID               string          `json:"id"`
	ShortTitle       string          `json:"short_title"`
	Title            string          `json:"title"`
	Version          string          `json:"version"`
	URL              string          `json:"url"`
	RequirementCount int             `json:"requirement_count"`
	Verdicts         map[Verdict]int `json:"verdicts,omitempty"`
	Indexable        bool            `json:"indexable"`
}

// SpecResponse is the body of GET /api/conformance/specs/{specId}.
type SpecResponse struct {
	SpecSummary
	ReportValid    bool             `json:"report_valid"`
	LaunchGateOpen bool             `json:"launch_gate_open"`
	Commit         string           `json:"commit,omitempty"`
	GeneratedAt    string           `json:"generated_at,omitempty"`
	Requirements   []RequirementRow `json:"requirements"`
}

// RequirementRow is a requirement as listed on a specification index.
type RequirementRow struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Section   string   `json:"section"`
	Level     string   `json:"level"`
	Roles     []string `json:"roles"`
	Verdict   Verdict  `json:"verdict,omitempty"`
	Indexable bool     `json:"indexable"`
}

// RequirementLink identifies a related requirement.
type RequirementLink struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// TestEvidence is a registry test with its verdict for this build. Test
// output is never included.
type TestEvidence struct {
	Package string  `json:"package"`
	Name    string  `json:"name"`
	File    string  `json:"file"`
	Line    int     `json:"line,omitempty"`
	Verdict Verdict `json:"verdict,omitempty"`
}

// RequirementResponse is the body of GET /api/conformance/requirements/{id}.
type RequirementResponse struct {
	ID                string            `json:"id"`
	Specification     SpecSummary       `json:"specification"`
	Section           string            `json:"section"`
	SectionURL        string            `json:"section_url"`
	Level             string            `json:"level"`
	Title             string            `json:"title"`
	Statement         string            `json:"statement"`
	Roles             []string          `json:"roles"`
	Applicability     string            `json:"applicability"`
	Verdict           Verdict           `json:"verdict,omitempty"`
	Commit            string            `json:"commit,omitempty"`
	GeneratedAt       string            `json:"generated_at,omitempty"`
	SourceBaseURL     string            `json:"source_base_url,omitempty"`
	Tests             []TestEvidence    `json:"tests"`
	Implementation    []string          `json:"implementation"`
	ADR               string            `json:"adr,omitempty"`
	Notes             string            `json:"notes,omitempty"`
	ExplainerMarkdown string            `json:"explainer_markdown,omitempty"`
	Indexable         bool              `json:"indexable"`
	Siblings          []RequirementLink `json:"siblings"`
	Previous          *RequirementLink  `json:"previous,omitempty"`
	Next              *RequirementLink  `json:"next,omitempty"`
}

// SitemapEntry is one indexable page for the frontend sitemap.
type SitemapEntry struct {
	Path    string `json:"path"`
	LastMod string `json:"lastmod"`
}

// Routes returns the handlers mounted under /api/conformance.
func (c *Catalogue) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/specs", c.handleSpecs)
	r.Get("/specs/{specId}", c.handleSpec)
	r.Get("/requirements/{id}", c.handleRequirement)
	r.Get("/sitemap", c.handleSitemap)
	return r
}

func (c *Catalogue) specSummary(spec Specification) SpecSummary {
	return SpecSummary{
		ID:               spec.ID,
		ShortTitle:       spec.ShortTitle,
		Title:            spec.Title,
		Version:          spec.Version,
		URL:              spec.URL,
		RequirementCount: len(c.bySpec[spec.ID]),
		Verdicts:         c.VerdictSummary(spec.ID),
		Indexable:        c.SpecIndexable(spec.ID),
	}
}

func (c *Catalogue) provenance() (commit, generatedAt string) {
	if !c.ReportValid() {
		return "", ""
	}
	return c.report.Commit, c.report.GeneratedAt
}

func (c *Catalogue) handleSpecs(w http.ResponseWriter, _ *http.Request) {
	commit, generatedAt := c.provenance()
	response := SpecsResponse{
		ReportValid:    c.ReportValid(),
		LaunchGateOpen: c.LaunchGateOpen(),
		Commit:         commit,
		GeneratedAt:    generatedAt,
		Specs:          make([]SpecSummary, 0, len(c.specs)),
	}
	for _, spec := range c.specs {
		response.Specs = append(response.Specs, c.specSummary(spec))
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Catalogue) handleSpec(w http.ResponseWriter, r *http.Request) {
	spec, ok := c.Specification(chi.URLParam(r, "specId"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "specification not found"})
		return
	}
	commit, generatedAt := c.provenance()
	response := SpecResponse{
		SpecSummary:    c.specSummary(spec),
		ReportValid:    c.ReportValid(),
		LaunchGateOpen: c.LaunchGateOpen(),
		Commit:         commit,
		GeneratedAt:    generatedAt,
		Requirements:   make([]RequirementRow, 0, len(c.bySpec[spec.ID])),
	}
	for _, req := range c.bySpec[spec.ID] {
		row := RequirementRow{
			ID:        req.ID,
			Title:     req.Title,
			Section:   req.Section,
			Level:     req.Level,
			Roles:     req.Roles,
			Indexable: c.Indexable(req.ID),
		}
		if result, ok := c.Result(req.ID); ok {
			row.Verdict = result.Verdict
		}
		response.Requirements = append(response.Requirements, row)
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Catalogue) handleRequirement(w http.ResponseWriter, r *http.Request) {
	req, ok := c.Requirement(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "requirement not found"})
		return
	}
	spec, _ := c.Specification(req.Specification)
	commit, generatedAt := c.provenance()

	response := RequirementResponse{
		ID:             req.ID,
		Specification:  c.specSummary(spec),
		Section:        req.Section,
		SectionURL:     c.registry.SectionURL(req),
		Level:          req.Level,
		Title:          req.Title,
		Statement:      req.Statement,
		Roles:          req.Roles,
		Applicability:  req.Applicability,
		Commit:         commit,
		GeneratedAt:    generatedAt,
		Tests:          make([]TestEvidence, 0, len(req.Tests)),
		Implementation: req.Implementation,
		ADR:            req.ADR,
		Notes:          req.Notes,
		Indexable:      c.Indexable(req.ID),
		Siblings:       []RequirementLink{},
	}

	result, hasResult := c.Result(req.ID)
	if hasResult {
		response.Verdict = result.Verdict
		response.SourceBaseURL = SourceRepository + "/blob/" + commit + "/"
	}
	for _, test := range req.Tests {
		evidence := TestEvidence{Package: test.Package, Name: test.Name, File: test.File}
		if hasResult {
			for _, tr := range result.Tests {
				if tr.Package == test.Package && tr.Name == test.Name {
					evidence.Line = tr.Line
					evidence.Verdict = tr.Verdict
					break
				}
			}
		}
		response.Tests = append(response.Tests, evidence)
	}
	if markdown, ok := c.Explainer(req.ID); ok {
		response.ExplainerMarkdown = markdown
	}

	siblings, previous, next := c.Neighbours(req.ID)
	for _, sibling := range siblings {
		response.Siblings = append(response.Siblings, RequirementLink{ID: sibling.ID, Title: sibling.Title})
	}
	if previous != nil {
		response.Previous = &RequirementLink{ID: previous.ID, Title: previous.Title}
	}
	if next != nil {
		response.Next = &RequirementLink{ID: next.ID, Title: next.Title}
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Catalogue) handleSitemap(w http.ResponseWriter, _ *http.Request) {
	entries := c.Sitemap()
	writeJSON(w, http.StatusOK, entries)
}

// Sitemap lists indexable specification and requirement pages. lastmod is
// the report generation time (sitemaps.org 0.9 W3C Datetime). It returns an
// empty, non-nil slice when nothing is indexable.
func (c *Catalogue) Sitemap() []SitemapEntry {
	entries := []SitemapEntry{}
	if !c.LaunchGateOpen() {
		return entries
	}
	lastmod := c.report.GeneratedAt
	for _, spec := range c.specs {
		if !c.SpecIndexable(spec.ID) {
			continue
		}
		entries = append(entries, SitemapEntry{Path: "/spec/" + spec.ID, LastMod: lastmod})
		for _, req := range c.bySpec[spec.ID] {
			if c.Indexable(req.ID) {
				entries = append(entries, SitemapEntry{Path: RequirementPath(spec.ID, req.ID), LastMod: lastmod})
			}
		}
	}
	return entries
}

// RequirementPath is the canonical frontend path for a requirement page.
func RequirementPath(specID, requirementID string) string {
	return "/spec/" + specID + "/" + strings.ToLower(requirementID)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", cacheControl)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
