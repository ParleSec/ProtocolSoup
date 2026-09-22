package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Verdict string

const (
	VerdictPass        Verdict = "PASS"
	VerdictFail        Verdict = "FAIL"
	VerdictCheck       Verdict = "CHECK"
	VerdictMissingTest Verdict = "MISSING_TEST"
	VerdictNotApply    Verdict = "N/A"
	VerdictDeviation   Verdict = "DEVIATION"
)

type Report struct {
	SchemaVersion int `json:"schema_version"`
	// Commit is the ProtocolSoup source revision the tests ran against. It is
	// distinct from Suite.Commit, which pins the external OIDF conformance
	// suite baseline. Requirement pages only show a verdict when Commit equals
	// the serving build's BUILD_COMMIT.
	Commit string `json:"commit"`
	// GeneratedAt is the RFC 3339 UTC time the report was produced.
	GeneratedAt string `json:"generated_at"`
	// Dirty is true when the working tree had uncommitted changes, so the
	// report cannot be attributed to Commit alone and is never treated as
	// valid evidence for a build.
	Dirty          bool                `json:"dirty"`
	Suite          SuiteBaseline       `json:"suite"`
	Specifications []Specification     `json:"specifications"`
	Summary        map[Verdict]int     `json:"summary"`
	Requirements   []RequirementResult `json:"requirements"`
}

type RequirementResult struct {
	Requirement
	Verdict Verdict      `json:"verdict"`
	Tests   []TestResult `json:"test_results"`
}

type TestResult struct {
	Package string `json:"package"`
	Name    string `json:"name"`
	// File is the repository-relative test file from the registry.
	File string `json:"file"`
	// Line is the 1-based line of the test function declaration, or 0 when
	// the declaration was not found.
	Line    int     `json:"line"`
	Verdict Verdict `json:"verdict"`
	Output  string  `json:"output,omitempty"`
}

// Provenance identifies the source tree a report was generated from.
type Provenance struct {
	Commit      string
	Dirty       bool
	GeneratedAt time.Time
}

// ResolveProvenance determines the commit and dirty state of repoRoot. The
// commit comes from GITHUB_SHA when getenv returns one, and from
// `git rev-parse HEAD` otherwise. Dirty is true when `git status --porcelain`
// reports any change.
func ResolveProvenance(ctx context.Context, repoRoot string, getenv func(string) string) (Provenance, error) {
	provenance := Provenance{GeneratedAt: time.Now().UTC()}
	if sha := strings.TrimSpace(getenv("GITHUB_SHA")); sha != "" {
		provenance.Commit = sha
	} else {
		out, err := gitOutput(ctx, repoRoot, "rev-parse", "HEAD")
		if err != nil {
			return provenance, fmt.Errorf("resolve commit: %w", err)
		}
		provenance.Commit = out
	}
	status, err := gitOutput(ctx, repoRoot, "status", "--porcelain")
	if err != nil {
		return provenance, fmt.Errorf("resolve dirty state: %w", err)
	}
	provenance.Dirty = status != ""
	return provenance, nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = dir
	out, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// TestLine returns the 1-based line of `func <name>(` in the Go test file at
// repoRoot/file, or 0 when the file cannot be parsed or has no such function.
func TestLine(repoRoot, file, name string) int {
	path := filepath.Join(repoRoot, filepath.FromSlash(file))
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return 0
	}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || fn.Name.Name != name {
			continue
		}
		return fset.Position(fn.Pos()).Line
	}
	return 0
}

type goTestEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

// GenerateReport runs every registry test in backendDir and records the
// result against repoRoot's provenance. A test-execution failure still
// returns the populated report alongside the error so callers can persist
// the true verdicts.
func GenerateReport(ctx context.Context, registry Registry, repoRoot, backendDir string) (Report, error) {
	provenance, err := ResolveProvenance(ctx, repoRoot, os.Getenv)
	if err != nil {
		return Report{}, err
	}

	packageTests := make(map[string]map[string]struct{})
	for _, requirement := range registry.Requirements {
		for _, test := range requirement.Tests {
			if packageTests[test.Package] == nil {
				packageTests[test.Package] = make(map[string]struct{})
			}
			packageTests[test.Package][test.Name] = struct{}{}
		}
	}

	results := make(map[string]map[string]TestResult, len(packageTests))
	var packageErrors []string
	packages := make([]string, 0, len(packageTests))
	for packageName := range packageTests {
		packages = append(packages, packageName)
	}
	sort.Strings(packages)
	for _, packageName := range packages {
		packageResult, err := runPackageTests(ctx, backendDir, packageName, packageTests[packageName])
		results[packageName] = packageResult
		if err != nil {
			packageErrors = append(packageErrors, fmt.Sprintf("%s: %v", packageName, err))
		}
	}

	report := Report{
		SchemaVersion:  registry.SchemaVersion,
		Commit:         provenance.Commit,
		GeneratedAt:    provenance.GeneratedAt.Format(time.RFC3339),
		Dirty:          provenance.Dirty,
		Suite:          registry.Suite,
		Specifications: append([]Specification(nil), registry.Specifications...),
		Summary:        make(map[Verdict]int),
		Requirements:   make([]RequirementResult, 0, len(registry.Requirements)),
	}
	for _, requirement := range registry.Requirements {
		result := RequirementResult{Requirement: requirement}
		// Do not duplicate registry test metadata in generated JSON.
		result.Requirement.Tests = nil
		for _, test := range requirement.Tests {
			testResult, ok := results[test.Package][test.Name]
			if !ok {
				testResult = TestResult{
					Package: test.Package,
					Name:    test.Name,
					Verdict: VerdictMissingTest,
				}
			}
			testResult.File = test.File
			testResult.Line = TestLine(repoRoot, test.File, test.Name)
			result.Tests = append(result.Tests, testResult)
		}
		result.Verdict = requirementVerdict(requirement, result.Tests)
		report.Summary[result.Verdict]++
		report.Requirements = append(report.Requirements, result)
	}

	if len(packageErrors) > 0 {
		return report, fmt.Errorf("one or more test packages failed: %s", strings.Join(packageErrors, "; "))
	}
	return report, nil
}

func runPackageTests(
	ctx context.Context,
	backendDir string,
	packageName string,
	wanted map[string]struct{},
) (map[string]TestResult, error) {
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Strings(names)
	pattern := "^(" + strings.Join(names, "|") + ")$"

	command := exec.CommandContext(ctx, "go", "test", "-json", "-count=1", "-run", pattern, packageName)
	command.Dir = backendDir
	output, commandErr := command.CombinedOutput()

	results := make(map[string]TestResult, len(wanted))
	testOutput := make(map[string]*strings.Builder, len(wanted))
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var event goTestEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if _, ok := wanted[event.Test]; !ok {
			continue
		}
		if event.Output != "" {
			if testOutput[event.Test] == nil {
				testOutput[event.Test] = &strings.Builder{}
			}
			testOutput[event.Test].WriteString(event.Output)
		}
		var verdict Verdict
		switch event.Action {
		case "pass":
			verdict = VerdictPass
		case "fail":
			verdict = VerdictFail
		case "skip":
			verdict = VerdictCheck
		default:
			continue
		}
		result := TestResult{Package: packageName, Name: event.Test, Verdict: verdict}
		if verdict != VerdictPass && testOutput[event.Test] != nil {
			result.Output = strings.TrimSpace(testOutput[event.Test].String())
		}
		results[event.Test] = result
	}
	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("parse go test output: %w", err)
	}
	if commandErr != nil {
		return results, fmt.Errorf("%w", commandErr)
	}
	return results, nil
}

func requirementVerdict(requirement Requirement, tests []TestResult) Verdict {
	for _, test := range tests {
		if test.Verdict == VerdictFail {
			return VerdictFail
		}
	}
	for _, test := range tests {
		if test.Verdict == VerdictMissingTest {
			return VerdictMissingTest
		}
	}
	for _, test := range tests {
		if test.Verdict == VerdictCheck {
			return VerdictCheck
		}
	}
	switch requirement.Applicability {
	case "not_applicable":
		return VerdictNotApply
	case "deviation":
		return VerdictDeviation
	default:
		return VerdictPass
	}
}
