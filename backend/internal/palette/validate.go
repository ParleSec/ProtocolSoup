package palette

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
)

// ExplainerHeadings are the `##` headings every spec-assertion body must
// contain, in this order and with no others. The fixed shape is what lets a
// requirement page render the explainer under predictable sections and lets
// the validator catch a half-written file before it reaches the index.
var ExplainerHeadings = []string{
	"What this requires",
	"Why it exists",
	"What non-compliance looks like",
	"How ProtocolSoup tests it",
}

var (
	h2Pattern    = regexp.MustCompile(`(?m)^##[ \t]+(.+?)[ \t]*$`)
	fencePattern = regexp.MustCompile("(?m)^[ \t]*(```|~~~)")
	// A tag opener followed by a letter, "/" or "!" (comments, doctypes).
	// Bare "<" in prose, such as "a < b", does not match.
	htmlPattern = regexp.MustCompile(`<[A-Za-z/!]`)
)

// RequirementRef is the registry row a spec-assertion explains. Spec is the
// registry specification ID, which becomes the first path segment of the
// artefact's href.
type RequirementRef struct {
	ID   string
	Spec string
}

// RequirementIndex maps lowercase registry requirement IDs to their
// registry row. A nil index means no registry was loaded, in which case
// every spec-assertion is a validation issue: an explainer that cannot be
// tied to a requirement has no page to live on.
type RequirementIndex map[string]RequirementRef

// LoadRequirementIndex reads the conformance registry at path. An empty
// path uses the registry compiled into the binary.
func LoadRequirementIndex(path string) (RequirementIndex, error) {
	var (
		registry conformance.Registry
		err      error
	)
	if path == "" {
		registry, err = conformance.Embedded()
	} else {
		registry, err = conformance.Load(path)
	}
	if err != nil {
		return nil, fmt.Errorf("load requirement registry: %w", err)
	}
	return NewRequirementIndex(registry), nil
}

// NewRequirementIndex builds the lookup from a decoded registry.
func NewRequirementIndex(registry conformance.Registry) RequirementIndex {
	index := make(RequirementIndex, len(registry.Requirements))
	for _, req := range registry.Requirements {
		index[strings.ToLower(req.ID)] = RequirementRef{ID: req.ID, Spec: req.Specification}
	}
	return index
}

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
//
// requirements resolves spec-assertion IDs against the conformance registry
// and fills Artefact.Spec on the returned artefacts. It may be nil when the
// tree contains no spec-assertions.
func ValidateContent(contentRoot string, requirements RequirementIndex) ([]Artefact, Taxonomy, AliasesFile, []Issue, error) {
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

	for i := range artefacts {
		if artefacts[i].Type != ArtefactSpecAssertion {
			continue
		}
		if ref, ok := requirements[strings.ToLower(artefacts[i].ID)]; ok {
			artefacts[i].Spec = ref.Spec
		}
	}

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
		if a.Type == ArtefactSpecAssertion {
			issues = append(issues, validateExplainer(a, requirements)...)
		}
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
		if a.RunDefaults != nil {
			if a.Runnable != nil && !*a.Runnable {
				add("run_defaults is set but the flow is not runnable")
			}
			if a.RunDefaults.ClientAuth == "" && a.RunDefaults.TokenMode == "" {
				add("run_defaults is present but sets neither client_auth nor token_mode")
			}
			if v := a.RunDefaults.ClientAuth; v != "" {
				if _, ok := RunDefaultClientAuthValues[v]; !ok {
					add("run_defaults.client_auth %q is not one of client_secret_basic, private_key_jwt", v)
				}
			}
			if v := a.RunDefaults.TokenMode; v != "" {
				if _, ok := RunDefaultTokenModeValues[v]; !ok {
					add("run_defaults.token_mode %q is not one of bearer, dpop", v)
				}
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

	if a.Type != ArtefactFlow && a.RunDefaults != nil {
		add("run_defaults is only valid on flow artefacts")
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

// validateExplainer applies the rules specific to spec-assertion bodies: the
// ID must name a registry requirement, the body must carry exactly the
// ExplainerHeadings in order, and the body must be plain markdown with no
// fenced code or raw HTML (the requirement page renders it with MarkdownLite,
// which refuses both).
func validateExplainer(a Artefact, requirements RequirementIndex) []Issue {
	var issues []Issue
	add := func(format string, args ...any) {
		issues = append(issues, Issue{Path: a.Path, Message: fmt.Sprintf(format, args...)})
	}

	if a.ID != "" {
		if a.ID != strings.ToLower(a.ID) {
			add("spec-assertion id %q must be the lowercase registry requirement id", a.ID)
		}
		if requirements == nil {
			add("spec-assertion %q cannot be checked: no requirement registry loaded (pass -registry)", a.ID)
		} else if _, ok := requirements[strings.ToLower(a.ID)]; !ok {
			add("spec-assertion id %q is not a requirement in the conformance registry", a.ID)
		}
	}

	var headings []string
	for _, m := range h2Pattern.FindAllStringSubmatch(a.Body, -1) {
		headings = append(headings, m[1])
	}
	if !equalStrings(headings, ExplainerHeadings) {
		add("spec-assertion body must contain exactly these ## headings in order: %s (found: %s)",
			strings.Join(ExplainerHeadings, "; "), joinOrNone(headings))
	}

	if fencePattern.MatchString(a.Body) {
		add("spec-assertion body must not contain fenced code blocks")
	}
	if htmlPattern.MatchString(a.Body) {
		add("spec-assertion body must not contain raw HTML")
	}

	return issues
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "; ")
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
