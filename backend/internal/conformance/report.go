package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
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
	SchemaVersion  int                 `json:"schema_version"`
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
	Package string  `json:"package"`
	Name    string  `json:"name"`
	Verdict Verdict `json:"verdict"`
	Output  string  `json:"output,omitempty"`
}

type goTestEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

func GenerateReport(ctx context.Context, registry Registry, backendDir string) (Report, error) {
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
