package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ExplainerSource supplies human-authored explainer markdown for a
// requirement ID. The palette service implements it from spec-assertion
// artefacts; a nil source means no requirement has an explainer.
type ExplainerSource interface {
	Explainer(id string) (markdown string, ok bool)
}

// Catalogue joins the embedded registry with an optional conformance report
// and the serving build's commit. It is the single source for everything a
// requirement page may assert: a verdict is only exposed when the report
// provably describes the running build.
type Catalogue struct {
	registry    Registry
	report      *Report
	buildCommit string
	explainers  ExplainerSource

	specs      []Specification              // specs with at least one requirement, registry order
	specByID   map[string]Specification     // canonical spec ID
	bySpec     map[string][]Requirement     // canonical spec ID -> requirements in spec order
	byLowerID  map[string]Requirement       // lowercase requirement ID -> requirement
	resultByID map[string]RequirementResult // canonical requirement ID -> report result
}

// LoadReport reads a conformance report written by cmd/conformance-report.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode conformance report %s: %w", path, err)
	}
	return &report, nil
}

// NewCatalogue builds a catalogue. report and explainers may be nil.
func NewCatalogue(registry Registry, report *Report, buildCommit string, explainers ExplainerSource) *Catalogue {
	c := &Catalogue{
		registry:    registry,
		report:      report,
		buildCommit: strings.TrimSpace(buildCommit),
		explainers:  explainers,
		specByID:    make(map[string]Specification, len(registry.Specifications)),
		bySpec:      make(map[string][]Requirement),
		byLowerID:   make(map[string]Requirement, len(registry.Requirements)),
		resultByID:  make(map[string]RequirementResult),
	}
	for _, req := range registry.Requirements {
		c.byLowerID[strings.ToLower(req.ID)] = req
		c.bySpec[req.Specification] = append(c.bySpec[req.Specification], req)
	}
	for _, spec := range registry.Specifications {
		reqs := c.bySpec[spec.ID]
		if len(reqs) == 0 {
			continue
		}
		sort.SliceStable(reqs, func(i, j int) bool {
			if cmp := CompareSections(reqs[i].Section, reqs[j].Section); cmp != 0 {
				return cmp < 0
			}
			return reqs[i].ID < reqs[j].ID
		})
		c.bySpec[spec.ID] = reqs
		c.specs = append(c.specs, spec)
		c.specByID[spec.ID] = spec
	}
	if report != nil {
		for _, result := range report.Requirements {
			c.resultByID[result.ID] = result
		}
	}
	return c
}

// Registry returns the underlying registry.
func (c *Catalogue) Registry() Registry { return c.registry }

// BuildCommit returns the serving build's commit, possibly empty.
func (c *Catalogue) BuildCommit() string { return c.buildCommit }

// Report returns the loaded report, or nil. Callers must check ReportValid
// before presenting any verdict from it.
func (c *Catalogue) Report() *Report { return c.report }

// ReportValid reports whether the loaded report describes the running build:
// it exists, was generated from a clean tree, and its commit equals the
// build commit with both non-empty.
func (c *Catalogue) ReportValid() bool {
	if c.report == nil || c.report.Dirty {
		return false
	}
	commit := strings.TrimSpace(c.report.Commit)
	return commit != "" && c.buildCommit != "" && commit == c.buildCommit
}

// LaunchGateOpen is true when the report is valid and no MUST-family
// requirement has a verdict of FAIL, MISSING_TEST or CHECK.
func (c *Catalogue) LaunchGateOpen() bool {
	if !c.ReportValid() {
		return false
	}
	for _, req := range c.registry.Requirements {
		if !IsMustFamily(req.Level) {
			continue
		}
		result, ok := c.resultByID[req.ID]
		if !ok {
			return false
		}
		switch result.Verdict {
		case VerdictFail, VerdictMissingTest, VerdictCheck:
			return false
		}
	}
	return true
}

// Requirement resolves a requirement ID case-insensitively and returns the
// canonical registry entry.
func (c *Catalogue) Requirement(id string) (Requirement, bool) {
	req, ok := c.byLowerID[strings.ToLower(strings.TrimSpace(id))]
	return req, ok
}

// Result returns the report result for a requirement. It is only populated
// when ReportValid is true, which implements the no-fabricated-verdicts rule.
func (c *Catalogue) Result(id string) (RequirementResult, bool) {
	if !c.ReportValid() {
		return RequirementResult{}, false
	}
	req, ok := c.Requirement(id)
	if !ok {
		return RequirementResult{}, false
	}
	result, ok := c.resultByID[req.ID]
	return result, ok
}

// Explainer returns the human-authored explainer for a requirement, if any.
func (c *Catalogue) Explainer(id string) (string, bool) {
	if c.explainers == nil {
		return "", false
	}
	req, ok := c.Requirement(id)
	if !ok {
		return "", false
	}
	return c.explainers.Explainer(strings.ToLower(req.ID))
}

// Indexable reports whether a requirement page may be indexed: the launch
// gate is open, its verdict is PASS, DEVIATION or N/A, and an explainer
// exists. Indexability is derived from evidence, never configured.
func (c *Catalogue) Indexable(id string) bool {
	if !c.LaunchGateOpen() {
		return false
	}
	result, ok := c.Result(id)
	if !ok {
		return false
	}
	switch result.Verdict {
	case VerdictPass, VerdictDeviation, VerdictNotApply:
	default:
		return false
	}
	_, hasExplainer := c.Explainer(id)
	return hasExplainer
}

// Specifications returns the specifications that have at least one
// requirement, in registry order.
func (c *Catalogue) Specifications() []Specification {
	return append([]Specification(nil), c.specs...)
}

// Specification resolves a spec ID case-insensitively. Specifications with
// zero requirements are not found.
func (c *Catalogue) Specification(id string) (Specification, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, spec := range c.specs {
		if strings.ToLower(spec.ID) == id {
			return spec, true
		}
	}
	return Specification{}, false
}

// Requirements returns a specification's requirements ordered by
// CompareSections, then by ID.
func (c *Catalogue) Requirements(specID string) []Requirement {
	spec, ok := c.Specification(specID)
	if !ok {
		return nil
	}
	return append([]Requirement(nil), c.bySpec[spec.ID]...)
}

// SpecIndexable reports whether a specification index page may be indexed:
// the launch gate is open and at least one of its requirements is indexable.
func (c *Catalogue) SpecIndexable(specID string) bool {
	if !c.LaunchGateOpen() {
		return false
	}
	for _, req := range c.Requirements(specID) {
		if c.Indexable(req.ID) {
			return true
		}
	}
	return false
}

// Neighbours returns the same-section siblings of a requirement (excluding
// itself) and its previous and next requirement in specification order.
func (c *Catalogue) Neighbours(id string) (siblings []Requirement, previous, next *Requirement) {
	req, ok := c.Requirement(id)
	if !ok {
		return nil, nil, nil
	}
	ordered := c.bySpec[req.Specification]
	for i := range ordered {
		other := ordered[i]
		if other.ID == req.ID {
			if i > 0 {
				prev := ordered[i-1]
				previous = &prev
			}
			if i+1 < len(ordered) {
				nxt := ordered[i+1]
				next = &nxt
			}
			continue
		}
		if other.Section == req.Section {
			siblings = append(siblings, other)
		}
	}
	return siblings, previous, next
}

// VerdictSummary counts verdicts across a specification's requirements. It
// returns nil when the report is not valid for this build.
func (c *Catalogue) VerdictSummary(specID string) map[Verdict]int {
	if !c.ReportValid() {
		return nil
	}
	summary := make(map[Verdict]int)
	for _, req := range c.Requirements(specID) {
		if result, ok := c.resultByID[req.ID]; ok {
			summary[result.Verdict]++
		}
	}
	return summary
}
