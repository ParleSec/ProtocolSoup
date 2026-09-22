package conformance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResolveProvenancePrefersGitHubSHA(t *testing.T) {
	root := initGitRepo(t)
	getenv := func(key string) string {
		if key == "GITHUB_SHA" {
			return "abc123"
		}
		return ""
	}
	provenance, err := ResolveProvenance(context.Background(), root, getenv)
	if err != nil {
		t.Fatalf("ResolveProvenance: %v", err)
	}
	if provenance.Commit != "abc123" {
		t.Fatalf("Commit = %q, want GITHUB_SHA value", provenance.Commit)
	}
	if provenance.Dirty {
		t.Fatal("Dirty = true for a clean tree")
	}
	if provenance.GeneratedAt.IsZero() || provenance.GeneratedAt.Location().String() != "UTC" {
		t.Fatalf("GeneratedAt = %v, want non-zero UTC time", provenance.GeneratedAt)
	}
}

func TestResolveProvenanceFallsBackToGitAndDetectsDirtyTree(t *testing.T) {
	root := initGitRepo(t)
	noEnv := func(string) string { return "" }

	provenance, err := ResolveProvenance(context.Background(), root, noEnv)
	if err != nil {
		t.Fatalf("ResolveProvenance: %v", err)
	}
	want := gitStdout(t, root, "rev-parse", "HEAD")
	if provenance.Commit != want {
		t.Fatalf("Commit = %q, want HEAD %q", provenance.Commit, want)
	}
	if provenance.Dirty {
		t.Fatal("Dirty = true for a clean tree")
	}

	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	provenance, err = ResolveProvenance(context.Background(), root, noEnv)
	if err != nil {
		t.Fatalf("ResolveProvenance(dirty): %v", err)
	}
	if !provenance.Dirty {
		t.Fatal("Dirty = false after adding an untracked file")
	}
}

func TestTestLineResolvesFunctionDeclaration(t *testing.T) {
	root := t.TempDir()
	source := "package example\n\nimport \"testing\"\n\n// TestFirst is documented.\nfunc TestFirst(t *testing.T) {}\n\nfunc helper() {}\n\nfunc TestSecond(t *testing.T) {\n}\n"
	if err := os.MkdirAll(filepath.Join(root, "backend", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "backend", "pkg", "example_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := TestLine(root, "backend/pkg/example_test.go", "TestFirst"); got != 6 {
		t.Fatalf("TestLine(TestFirst) = %d, want 6", got)
	}
	if got := TestLine(root, "backend/pkg/example_test.go", "TestSecond"); got != 10 {
		t.Fatalf("TestLine(TestSecond) = %d, want 10", got)
	}
	if got := TestLine(root, "backend/pkg/example_test.go", "TestMissing"); got != 0 {
		t.Fatalf("TestLine(TestMissing) = %d, want 0", got)
	}
	if got := TestLine(root, "backend/pkg/absent_test.go", "TestFirst"); got != 0 {
		t.Fatalf("TestLine(absent file) = %d, want 0", got)
	}
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	run := func(args ...string) {
		command := exec.Command("git", args...)
		command.Dir = root
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.test")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "tracked.txt")
	run("commit", "-q", "-m", "init")
	return root
}

func gitStdout(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitOutput(context.Background(), dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return out
}

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
