package palette

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Issue is a single validation finding. Path is the artefact-relative path
// (or "taxonomy.yaml"/"aliases.yaml" for catalog-level findings). Message is
// a short, user-readable description with no terminating punctuation.
type Issue struct {
	Path    string
	Message string
}

// Format renders an issue as "path: message" for CLI output.
func (i Issue) Format() string {
	if i.Path == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

// ValidateContent runs every validation rule against the supplied tree and
// returns the full list of issues sorted by (path, message). An empty slice
// means the tree is clean. The function never returns a partial result: all
// checks are run even when earlier checks fail, so a single CI run lists
// every authoring problem at once.
func ValidateContent(contentRoot string) ([]Artefact, Taxonomy, AliasesFile, []Issue, error) {
	taxonomy, err := LoadTaxonomy(contentRoot)
	if err != nil {
		return nil, Taxonomy{}, AliasesFile{}, nil, err
	}
	aliases, err := LoadAliases(contentRoot)
	if err != nil {
		return nil, taxonomy, AliasesFile{}, nil, err
	}

	artefacts, err := ContentReader{Root: contentRoot}.Read()
	if err != nil {
		return nil, taxonomy, aliases, nil, err
	}

	var issues []Issue

	known := make(map[string]Artefact, len(artefacts))
	for i, a := range artefacts {
		if existing, dup := known[a.ID]; dup {
			issues = append(issues, Issue{
				Path:    a.Path,
				Message: fmt.Sprintf("duplicate artefact id %q (first defined in %s)", a.ID, existing.Path),
			})
			continue
		}
		known[a.ID] = artefacts[i]
	}

	for _, a := range artefacts {
		issues = append(issues, validateArtefact(a, taxonomy, known)...)
	}

	issues = append(issues, validateAliasesAgainstCatalog(aliases, taxonomy, known)...)

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Message < issues[j].Message
	})
	return artefacts, taxonomy, aliases, issues, nil
}

// validateArtefact runs all per-artefact validation rules.
func validateArtefact(a Artefact, t Taxonomy, known map[string]Artefact) []Issue {
	var issues []Issue
	add := func(format string, args ...any) {
		issues = append(issues, Issue{Path: a.Path, Message: fmt.Sprintf(format, args...)})
	}

	expectedID := strings.TrimSuffix(filepath.Base(a.Path), ".md")
	if a.ID == "" {
		add("missing required field id")
	} else if a.ID != expectedID {
		add("id %q does not match filename stem %q", a.ID, expectedID)
	}

	if strings.TrimSpace(a.Name) == "" {
		add("missing required field name")
	}

	if len(a.UseCases) == 0 {
		add("missing required field use_cases (must list at least one)")
	}
	if len(a.Actors) == 0 {
		add("missing required field actors (must list at least one)")
	}
	if len(a.ProblemDomains) == 0 {
		add("missing required field problem_domains (must list at least one)")
	}

	checkAxisList := func(axis string, values []string) {
		for _, v := range values {
			if v == "" {
				add("%s contains an empty value", axis)
				continue
			}
			if !t.Has(axis, v) {
				add("%s contains unknown value %q (not declared in taxonomy.yaml)", axis, v)
			}
		}
		if dup := firstDuplicate(values); dup != "" {
			add("%s contains duplicate value %q", axis, dup)
		}
	}
	checkAxisList(AxisUseCases, a.UseCases)
	checkAxisList(AxisActors, a.Actors)
	checkAxisList(AxisPatterns, a.Patterns)
	checkAxisList(AxisProblemDomains, a.ProblemDomains)

	if a.Status != "" && a.Status != StatusLive && a.Status != StatusPlanned && a.Status != StatusDeprecated {
		add("status %q is not one of live, planned, deprecated", a.Status)
	}

	if a.Protocol != "" && len(a.Protocols) > 0 {
		add("protocol and protocols are mutually exclusive; set one only")
	}

	checkEdges := func(field string, ids []string) {
		for _, ref := range ids {
			if ref == "" {
				add("%s contains an empty reference", field)
				continue
			}
			if _, ok := known[ref]; !ok {
				add("%s references unknown artefact id %q", field, ref)
			}
		}
		if dup := firstDuplicate(ids); dup != "" {
			add("%s contains duplicate reference %q", field, dup)
		}
	}
	checkEdges("related_concepts", a.RelatedConcepts)
	checkEdges("prerequisites", a.Prerequisites)

	switch a.Type {
	case ArtefactProtocol:
		if a.Protocol != "" {
			add("protocol artefacts must omit the protocol field (it is implied by id)")
		}
		if a.Runnable != nil && *a.Runnable {
			add("protocol artefacts cannot be runnable")
		}

	case ArtefactFlow:
		if a.Protocol == "" {
			add("flow artefacts require a protocol field")
		} else if a.ProtocolFromDir != "" && a.Protocol != a.ProtocolFromDir {
			add("flow protocol %q does not match parent directory %q", a.Protocol, a.ProtocolFromDir)
		}
		if a.Protocol != "" {
			if _, ok := known[a.Protocol]; !ok {
				add("flow references unknown protocol %q (expected content/protocols/%s.md)", a.Protocol, a.Protocol)
			}
		}

	case ArtefactConcept:
		if a.Runnable != nil && *a.Runnable {
			add("concept artefacts cannot be runnable")
		}

	case ArtefactWalkthrough:
		if len(a.RelatedConcepts) == 0 && len(a.Prerequisites) == 0 {
			add("walkthrough must reference at least one flow or concept via related_concepts or prerequisites")
		}

	case ArtefactSpecAssertion:
		if len(a.NormativeAnchors) == 0 {
			add("spec-assertion requires at least one normative_anchors entry")
		}
		if a.NormativeLevel == "" {
			add("spec-assertion requires normative_level (MUST, SHOULD, MAY, MUST NOT, SHOULD NOT)")
		} else if _, ok := NormativeLevels[a.NormativeLevel]; !ok {
			add("normative_level %q is not one of MUST, SHOULD, MAY, MUST NOT, SHOULD NOT", a.NormativeLevel)
		}
		if strings.TrimSpace(a.AssertionText) == "" {
			add("spec-assertion requires assertion_text describing the normative statement")
		}
	}

	for _, ref := range a.Protocols {
		if _, ok := known[ref]; !ok {
			add("protocols references unknown artefact id %q", ref)
		}
	}

	for _, anchor := range a.NormativeAnchors {
		if strings.TrimSpace(anchor.RFC) == "" {
			add("normative_anchors entry missing rfc")
		}
		if len(anchor.Sections) == 0 {
			add("normative_anchors entry for %q has no sections", anchor.RFC)
		}
	}

	return issues
}

// validateAliasesAgainstCatalog ensures every alias canonical target resolves
// against the taxonomy and known artefact set.
func validateAliasesAgainstCatalog(f AliasesFile, t Taxonomy, known map[string]Artefact) []Issue {
	var issues []Issue
	for _, entry := range f.Aliases {
		for _, c := range entry.Canonical {
			if c.Axis != "" {
				if !axisAllowed(c.Axis) {
					issues = append(issues, Issue{
						Path:    "aliases.yaml",
						Message: fmt.Sprintf("alias %q references unknown axis %q", entry.Alias, c.Axis),
					})
					continue
				}
				if !t.Has(c.Axis, c.Value) {
					issues = append(issues, Issue{
						Path:    "aliases.yaml",
						Message: fmt.Sprintf("alias %q references unknown value %q on axis %s", entry.Alias, c.Value, c.Axis),
					})
				}
				continue
			}
			if _, ok := known[c.Artefact]; !ok {
				issues = append(issues, Issue{
					Path:    "aliases.yaml",
					Message: fmt.Sprintf("alias %q references unknown artefact %q", entry.Alias, c.Artefact),
				})
			}
		}
	}
	return issues
}

func axisAllowed(axis string) bool {
	for _, a := range AllAxes {
		if a == axis {
			return true
		}
	}
	return false
}

func firstDuplicate(values []string) string {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			return v
		}
		seen[v] = struct{}{}
	}
	return ""
}
