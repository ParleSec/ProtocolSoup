// Package conformance loads and validates the canonical VC requirement
// registry. The registry owns requirement metadata; executable Go tests own
// verdicts.
package conformance

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1

// MaxTitleLength bounds requirement titles so they fit page headings and
// search result titles without truncation.
const MaxTitleLength = 70

// SectionPlaceholder is substituted with the requirement section when a
// specification declares a section_anchor template.
const SectionPlaceholder = "{section}"

var allowedLevels = map[string]struct{}{
	"MUST": {}, "MUST NOT": {}, "REQUIRED": {}, "SHALL": {}, "SHALL NOT": {},
	"SHOULD": {}, "SHOULD NOT": {}, "RECOMMENDED": {}, "NOT RECOMMENDED": {},
	"MAY": {}, "OPTIONAL": {},
}

// mustFamily is the set of BCP 14 keywords that express an absolute
// requirement (RFC 2119 Sections 1 and 2; RFC 8174 Section 2).
var mustFamily = map[string]struct{}{
	"MUST": {}, "MUST NOT": {}, "REQUIRED": {}, "SHALL": {}, "SHALL NOT": {},
}

// IsMustFamily reports whether a BCP 14 level expresses an absolute
// requirement rather than a recommendation or option.
func IsMustFamily(level string) bool {
	_, ok := mustFamily[level]
	return ok
}

// dottedSection matches sections that public specification anchors can
// address directly, such as "5", "5.9.1" or "11.1". Compound sections like
// "6.3 and 8.2" or "Appendix F.1" have no single anchor.
var dottedSection = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

//go:embed vc-requirements.yaml
var embeddedRegistry []byte

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
	ID         string `yaml:"id" json:"id"`
	Title      string `yaml:"title" json:"title"`
	ShortTitle string `yaml:"short_title" json:"short_title"`
	Version    string `yaml:"version" json:"version"`
	URL        string `yaml:"url" json:"url"`
	// SectionAnchor is an optional URL fragment template containing
	// SectionPlaceholder exactly once, for example "#section-{section}".
	// Specifications without public anchors leave it unset.
	SectionAnchor string `yaml:"section_anchor,omitempty" json:"section_anchor,omitempty"`
}

type Requirement struct {
	ID            string `yaml:"id" json:"id"`
	Specification string `yaml:"specification" json:"specification"`
	Section       string `yaml:"section" json:"section"`
	Level         string `yaml:"level" json:"level"`
	// Title is a descriptive noun phrase drawn from the statement, at most
	// MaxTitleLength characters, with no trailing full stop.
	Title          string    `yaml:"title" json:"title"`
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

// Embedded returns the registry compiled into the binary. Servers use it so
// requirement pages never depend on a working-tree file; cmd/conformance-report
// keeps loading from disk so it validates the checked-out registry.
func Embedded() (Registry, error) {
	return Decode(bytes.NewReader(embeddedRegistry))
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

// SectionURL returns the specification URL for a requirement, with the
// section anchor filled in when the specification declares one and the
// section is a single dotted number that the anchor template can address.
// Otherwise it returns the bare specification URL.
func (r Registry) SectionURL(req Requirement) string {
	for _, spec := range r.Specifications {
		if spec.ID != req.Specification {
			continue
		}
		if spec.SectionAnchor == "" || !dottedSection.MatchString(req.Section) {
			return spec.URL
		}
		return spec.URL + strings.Replace(spec.SectionAnchor, SectionPlaceholder, req.Section, 1)
	}
	return ""
}

// CompareSections orders specification sections naturally: dot-separated
// segments are compared pairwise, numerically when both are integers and
// lexically otherwise, so "5" < "5.9" < "5.9.1" < "5.10". It returns -1, 0
// or 1 like strings.Compare.
func CompareSections(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		var c int
		if aErr == nil && bErr == nil {
			switch {
			case an < bn:
				c = -1
			case an > bn:
				c = 1
			}
		} else {
			c = strings.Compare(as[i], bs[i])
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
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
		if strings.TrimSpace(spec.ShortTitle) == "" {
			issues = append(issues, prefix+": short_title is required")
		}
		if spec.SectionAnchor != "" && strings.Count(spec.SectionAnchor, SectionPlaceholder) != 1 {
			issues = append(issues, prefix+": section_anchor must contain "+SectionPlaceholder+" exactly once")
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
		title := strings.TrimSpace(requirement.Title)
		switch {
		case title == "":
			issues = append(issues, prefix+": title is required")
		case len([]rune(title)) > MaxTitleLength:
			issues = append(issues, fmt.Sprintf("%s: title exceeds %d characters", prefix, MaxTitleLength))
		case strings.HasSuffix(title, "."):
			issues = append(issues, prefix+": title must not end with a full stop")
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
