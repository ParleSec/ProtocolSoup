// Package conformance loads and validates the canonical VC requirement
// registry. The registry owns requirement metadata; executable Go tests own
// verdicts.
package conformance

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1

var allowedLevels = map[string]struct{}{
	"MUST": {}, "MUST NOT": {}, "REQUIRED": {}, "SHALL": {}, "SHALL NOT": {},
	"SHOULD": {}, "SHOULD NOT": {}, "RECOMMENDED": {}, "NOT RECOMMENDED": {},
	"MAY": {}, "OPTIONAL": {},
}

type Registry struct {
	SchemaVersion  int             `yaml:"schema_version" json:"schema_version"`
	Suite          SuiteBaseline   `yaml:"suite" json:"suite"`
	Specifications []Specification `yaml:"specifications" json:"specifications"`
	Requirements   []Requirement   `yaml:"requirements" json:"requirements"`
}

type SuiteBaseline struct {
	Release string `yaml:"release" json:"release"`
	Commit  string `yaml:"commit" json:"commit"`
	URL     string `yaml:"url" json:"url"`
}

type Specification struct {
	ID      string `yaml:"id" json:"id"`
	Title   string `yaml:"title" json:"title"`
	Version string `yaml:"version" json:"version"`
	URL     string `yaml:"url" json:"url"`
}

type Requirement struct {
	ID             string    `yaml:"id" json:"id"`
	Specification  string    `yaml:"specification" json:"specification"`
	Section        string    `yaml:"section" json:"section"`
	Level          string    `yaml:"level" json:"level"`
	Statement      string    `yaml:"statement" json:"statement"`
	Roles          []string  `yaml:"roles" json:"roles"`
	Applicability  string    `yaml:"applicability" json:"applicability"`
	Implementation []string  `yaml:"implementation" json:"implementation"`
	Tests          []TestRef `yaml:"tests" json:"tests,omitempty"`
	ADR            string    `yaml:"adr,omitempty" json:"adr,omitempty"`
	Notes          string    `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type TestRef struct {
	Package string `yaml:"package" json:"package"`
	File    string `yaml:"file" json:"file"`
	Name    string `yaml:"name" json:"name"`
}

func Load(path string) (Registry, error) {
	f, err := os.Open(path)
	if err != nil {
		return Registry{}, err
	}
	defer f.Close()
	return Decode(f)
}

func Decode(r io.Reader) (Registry, error) {
	var registry Registry
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&registry); err != nil {
		return Registry{}, fmt.Errorf("decode registry: %w", err)
	}
	return registry, nil
}

func Validate(registry Registry, repoRoot string) error {
	var issues []string
	if registry.SchemaVersion != SchemaVersion {
		issues = append(issues, fmt.Sprintf("schema_version is %d, want %d", registry.SchemaVersion, SchemaVersion))
	}
	if strings.TrimSpace(registry.Suite.Release) == "" ||
		strings.TrimSpace(registry.Suite.Commit) == "" ||
		strings.TrimSpace(registry.Suite.URL) == "" {
		issues = append(issues, "suite release, commit, and URL are required")
	}

	specIDs := make(map[string]struct{}, len(registry.Specifications))
	for i, spec := range registry.Specifications {
		prefix := fmt.Sprintf("specifications[%d]", i)
		if strings.TrimSpace(spec.ID) == "" {
			issues = append(issues, prefix+": id is required")
		} else if _, exists := specIDs[spec.ID]; exists {
			issues = append(issues, prefix+": duplicate id "+spec.ID)
		} else {
			specIDs[spec.ID] = struct{}{}
		}
		if strings.TrimSpace(spec.Title) == "" || strings.TrimSpace(spec.Version) == "" || strings.TrimSpace(spec.URL) == "" {
			issues = append(issues, prefix+": title, version, and URL are required")
		}
	}

	requirementIDs := make(map[string]struct{}, len(registry.Requirements))
	for i, requirement := range registry.Requirements {
		prefix := fmt.Sprintf("requirements[%d]", i)
		if requirement.ID != "" {
			prefix = requirement.ID
		}
		if strings.TrimSpace(requirement.ID) == "" {
			issues = append(issues, prefix+": id is required")
		} else if _, exists := requirementIDs[requirement.ID]; exists {
			issues = append(issues, prefix+": duplicate requirement id")
		} else {
			requirementIDs[requirement.ID] = struct{}{}
		}
		if _, exists := specIDs[requirement.Specification]; !exists {
			issues = append(issues, prefix+": unknown specification "+requirement.Specification)
		}
		if strings.TrimSpace(requirement.Section) == "" ||
			strings.TrimSpace(requirement.Level) == "" ||
			strings.TrimSpace(requirement.Statement) == "" {
			issues = append(issues, prefix+": section, level, and statement are required")
		}
		if _, ok := allowedLevels[requirement.Level]; !ok {
			issues = append(issues, prefix+": level is not a supported BCP 14 value")
		}
		if len(requirement.Roles) == 0 {
			issues = append(issues, prefix+": at least one role is required")
		}
		switch requirement.Applicability {
		case "applicable":
		case "not_applicable", "deviation":
			if strings.TrimSpace(requirement.ADR) == "" {
				issues = append(issues, prefix+": "+requirement.Applicability+" requires an ADR")
			}
		default:
			issues = append(issues, prefix+": applicability must be applicable, not_applicable, or deviation")
		}
		if len(requirement.Implementation) == 0 {
			issues = append(issues, prefix+": at least one implementation path is required")
		}
		for _, path := range requirement.Implementation {
			if err := validateRepoPath(repoRoot, path); err != nil {
				issues = append(issues, prefix+": implementation "+err.Error())
			}
		}
		if requirement.ADR != "" {
			if err := validateRepoPath(repoRoot, requirement.ADR); err != nil {
				issues = append(issues, prefix+": ADR "+err.Error())
			}
		}
		if len(requirement.Tests) == 0 {
			issues = append(issues, prefix+": at least one executable test is required")
		}
		for testIndex, test := range requirement.Tests {
			testPrefix := fmt.Sprintf("%s: tests[%d]", prefix, testIndex)
			if !strings.HasPrefix(test.Package, "./") || strings.TrimSpace(test.Name) == "" {
				issues = append(issues, testPrefix+": package must start with ./ and name is required")
			}
			if err := validateRepoPath(repoRoot, test.File); err != nil {
				issues = append(issues, testPrefix+": file "+err.Error())
			}
		}
	}

	if len(issues) == 0 {
		return nil
	}
	sort.Strings(issues)
	return errors.New(strings.Join(issues, "\n"))
}

func validateRepoPath(repoRoot, path string) error {
	clean := filepath.Clean(filepath.FromSlash(strings.TrimSpace(path)))
	if path == "" || filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q must be repository-relative", path)
	}
	info, err := os.Stat(filepath.Join(repoRoot, clean))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path %q does not exist", path)
		}
		return fmt.Errorf("stat path %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path %q must name a file", path)
	}
	return nil
}
