package palette

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// TaxonomyEntry is one controlled-vocabulary value. The note is human-readable
// guidance for authors and is surfaced in result chips for self-explanation.
type TaxonomyEntry struct {
	Note string `yaml:"note"`
}

// Taxonomy is the parsed taxonomy.yaml file. Each map is keyed by canonical
// value; values are taxonomy entries.
type Taxonomy struct {
	UseCases       map[string]TaxonomyEntry `yaml:"use_cases"`
	Actors         map[string]TaxonomyEntry `yaml:"actors"`
	Patterns       map[string]TaxonomyEntry `yaml:"patterns"`
	ProblemDomains map[string]TaxonomyEntry `yaml:"problem_domains"`
}

// Has reports whether the given (axis, value) pair is in the taxonomy.
func (t Taxonomy) Has(axis, value string) bool {
	switch axis {
	case AxisUseCases:
		_, ok := t.UseCases[value]
		return ok
	case AxisActors:
		_, ok := t.Actors[value]
		return ok
	case AxisPatterns:
		_, ok := t.Patterns[value]
		return ok
	case AxisProblemDomains:
		_, ok := t.ProblemDomains[value]
		return ok
	}
	return false
}

// Axis names. Kept in one place so taxonomy, aliases, and the query API all
// agree on the spelling.
const (
	AxisUseCases       = "use_cases"
	AxisActors         = "actors"
	AxisPatterns       = "patterns"
	AxisProblemDomains = "problem_domains"
)

// AllAxes is the closed set of retrieval axes.
var AllAxes = []string{AxisUseCases, AxisActors, AxisPatterns, AxisProblemDomains}

// LoadTaxonomy parses taxonomy.yaml from the given content root and validates
// the file shape. It does not validate that the values are referenced; the
// validator does that against the artefact set.
func LoadTaxonomy(contentRoot string) (Taxonomy, error) {
	raw, err := os.ReadFile(filepath.Join(contentRoot, "taxonomy.yaml"))
	if err != nil {
		return Taxonomy{}, fmt.Errorf("read taxonomy.yaml: %w", err)
	}
	var t Taxonomy
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return Taxonomy{}, fmt.Errorf("parse taxonomy.yaml: %w", err)
	}
	if len(t.UseCases) == 0 {
		return Taxonomy{}, fmt.Errorf("taxonomy.yaml: use_cases must not be empty")
	}
	if len(t.Actors) == 0 {
		return Taxonomy{}, fmt.Errorf("taxonomy.yaml: actors must not be empty")
	}
	if len(t.Patterns) == 0 {
		return Taxonomy{}, fmt.Errorf("taxonomy.yaml: patterns must not be empty")
	}
	if len(t.ProblemDomains) == 0 {
		return Taxonomy{}, fmt.Errorf("taxonomy.yaml: problem_domains must not be empty")
	}
	for axis, m := range map[string]map[string]TaxonomyEntry{
		AxisUseCases:       t.UseCases,
		AxisActors:         t.Actors,
		AxisPatterns:       t.Patterns,
		AxisProblemDomains: t.ProblemDomains,
	} {
		for value, entry := range m {
			if strings.TrimSpace(entry.Note) == "" {
				return Taxonomy{}, fmt.Errorf("taxonomy.yaml: %s/%s missing a semantic note", axis, value)
			}
		}
	}
	return t, nil
}

// AliasCanonical is one canonical target referenced by an alias. Exactly one
// of (Axis+Value) or (Artefact) must be set.
type AliasCanonical struct {
	Axis     string `yaml:"axis,omitempty"`
	Value    string `yaml:"value,omitempty"`
	Artefact string `yaml:"artefact,omitempty"`
}

// AliasEntry pairs a free-form alias with its canonical targets.
type AliasEntry struct {
	Alias     string           `yaml:"alias"`
	Canonical []AliasCanonical `yaml:"canonical"`
}

// AliasesFile is the parsed aliases.yaml document.
type AliasesFile struct {
	Aliases []AliasEntry `yaml:"aliases"`
}

// LoadAliases parses aliases.yaml from the content root. Duplicate alias keys
// are reported here so the indexer never has to deal with collisions.
func LoadAliases(contentRoot string) (AliasesFile, error) {
	raw, err := os.ReadFile(filepath.Join(contentRoot, "aliases.yaml"))
	if err != nil {
		return AliasesFile{}, fmt.Errorf("read aliases.yaml: %w", err)
	}
	var f AliasesFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return AliasesFile{}, fmt.Errorf("parse aliases.yaml: %w", err)
	}

	seen := make(map[string]int)
	var dups []string
	for _, entry := range f.Aliases {
		if strings.TrimSpace(entry.Alias) == "" {
			return AliasesFile{}, fmt.Errorf("aliases.yaml: entry missing alias field")
		}
		if len(entry.Canonical) == 0 {
			return AliasesFile{}, fmt.Errorf("aliases.yaml: alias %q has no canonical targets", entry.Alias)
		}
		key := strings.ToLower(strings.TrimSpace(entry.Alias))
		seen[key]++
		if seen[key] == 2 {
			dups = append(dups, key)
		}
		for _, c := range entry.Canonical {
			hasAxis := c.Axis != ""
			hasArtefact := c.Artefact != ""
			if hasAxis == hasArtefact {
				return AliasesFile{}, fmt.Errorf("aliases.yaml: alias %q canonical entries must set exactly one of axis/value or artefact", entry.Alias)
			}
			if hasAxis && c.Value == "" {
				return AliasesFile{}, fmt.Errorf("aliases.yaml: alias %q axis %q has no value", entry.Alias, c.Axis)
			}
		}
	}
	if len(dups) > 0 {
		sort.Strings(dups)
		return AliasesFile{}, fmt.Errorf("aliases.yaml: duplicate alias keys: %s", strings.Join(dups, ", "))
	}
	return f, nil
}

// Sorted returns the alias entries sorted by lower-cased alias. The indexer
// relies on this ordering for byte-identical output across runs.
func (f AliasesFile) Sorted() []AliasEntry {
	out := make([]AliasEntry, len(f.Aliases))
	copy(out, f.Aliases)
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Alias) < strings.ToLower(out[j].Alias)
	})
	return out
}
