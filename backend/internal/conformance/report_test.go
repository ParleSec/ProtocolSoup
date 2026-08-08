package conformance

import "testing"

func TestRequirementVerdict(t *testing.T) {
	tests := []struct {
		name          string
		applicability string
		results       []TestResult
		want          Verdict
	}{
		{name: "pass", applicability: "applicable", results: []TestResult{{Verdict: VerdictPass}}, want: VerdictPass},
		{name: "failure blocks", applicability: "applicable", results: []TestResult{{Verdict: VerdictPass}, {Verdict: VerdictFail}}, want: VerdictFail},
		{name: "missing test blocks", applicability: "applicable", results: []TestResult{{Verdict: VerdictMissingTest}}, want: VerdictMissingTest},
		{name: "skip remains check", applicability: "applicable", results: []TestResult{{Verdict: VerdictCheck}}, want: VerdictCheck},
		{name: "tested not applicable", applicability: "not_applicable", results: []TestResult{{Verdict: VerdictPass}}, want: VerdictNotApply},
		{name: "tested deviation", applicability: "deviation", results: []TestResult{{Verdict: VerdictPass}}, want: VerdictDeviation},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requirement := Requirement{Applicability: test.applicability}
			if got := requirementVerdict(requirement, test.results); got != test.want {
				t.Fatalf("requirementVerdict() = %s, want %s", got, test.want)
			}
		})
	}
}
