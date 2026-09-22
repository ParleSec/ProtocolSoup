package conformance

import "testing"

const testBuildCommit = "0123456789abcdef0123456789abcdef01234567"

type mapExplainers map[string]string

func (m mapExplainers) Explainer(id string) (string, bool) {
	markdown, ok := m[id]
	return markdown, ok
}

// catalogueFixture returns a registry with two specs (one empty) and a
// matching report where every requirement passes unless overridden.
func catalogueRegistry() Registry {
	return Registry{
		SchemaVersion: SchemaVersion,
		Specifications: []Specification{
			{ID: "alpha", Title: "Alpha Spec", ShortTitle: "Alpha 1.0", Version: "1.0", URL: "https://example.test/alpha", SectionAnchor: "#section-{section}"},
			{ID: "empty", Title: "Empty Spec", ShortTitle: "Empty", Version: "1", URL: "https://example.test/empty"},
			{ID: "beta", Title: "Beta Spec", ShortTitle: "Beta", Version: "2", URL: "https://example.test/beta"},
		},
		Requirements: []Requirement{
			{ID: "AL-010", Specification: "alpha", Section: "5.10", Level: "MUST", Title: "Ten", Statement: "s", Roles: []string{"wallet"}, Applicability: "applicable",
				Implementation: []string{"backend/a.go"}, Tests: []TestRef{{Package: "./a", File: "backend/a_test.go", Name: "TestTen"}}},
			{ID: "AL-002", Specification: "alpha", Section: "5.9.1", Level: "SHOULD", Title: "Two", Statement: "s", Roles: []string{"wallet"}, Applicability: "applicable",
				Implementation: []string{"backend/a.go"}, Tests: []TestRef{{Package: "./a", File: "backend/a_test.go", Name: "TestTwo"}}},
			{ID: "AL-001", Specification: "alpha", Section: "5.9", Level: "MUST NOT", Title: "One", Statement: "s", Roles: []string{"wallet"}, Applicability: "applicable",
				Implementation: []string{"backend/a.go"}, Tests: []TestRef{{Package: "./a", File: "backend/a_test.go", Name: "TestOne"}}},
			{ID: "AL-003", Specification: "alpha", Section: "5.9.1", Level: "MAY", Title: "Three", Statement: "s", Roles: []string{"wallet"}, Applicability: "applicable",
				Implementation: []string{"backend/a.go"}, Tests: []TestRef{{Package: "./a", File: "backend/a_test.go", Name: "TestThree"}}},
			{ID: "BE-001", Specification: "beta", Section: "2", Level: "SHOULD", Title: "Beta one", Statement: "s", Roles: []string{"issuer"}, Applicability: "deviation", ADR: "docs/adr.md",
				Implementation: []string{"backend/b.go"}, Tests: []TestRef{{Package: "./b", File: "backend/b_test.go", Name: "TestBeta"}}},
		},
	}
}

func catalogueReport(registry Registry, overrides map[string]Verdict) *Report {
	report := &Report{
		SchemaVersion: SchemaVersion,
		Commit:        testBuildCommit,
		GeneratedAt:   "2026-09-22T00:00:00Z",
		Summary:       map[Verdict]int{},
	}
	for _, req := range registry.Requirements {
		verdict := VerdictPass
		if req.Applicability == "deviation" {
			verdict = VerdictDeviation
		}
		if v, ok := overrides[req.ID]; ok {
			verdict = v
		}
		result := RequirementResult{Requirement: req, Verdict: verdict}
		result.Requirement.Tests = nil
		for _, test := range req.Tests {
			result.Tests = append(result.Tests, TestResult{
				Package: test.Package, Name: test.Name, File: test.File, Line: 42, Verdict: verdict, Output: "secret test output",
			})
		}
		report.Requirements = append(report.Requirements, result)
		report.Summary[verdict]++
	}
	return report
}

func TestReportValidBranches(t *testing.T) {
	registry := catalogueRegistry()
	cases := []struct {
		name        string
		report      *Report
		buildCommit string
		want        bool
	}{
		{name: "valid", report: catalogueReport(registry, nil), buildCommit: testBuildCommit, want: true},
		{name: "no report", report: nil, buildCommit: testBuildCommit, want: false},
		{name: "dirty report", report: func() *Report { r := catalogueReport(registry, nil); r.Dirty = true; return r }(), buildCommit: testBuildCommit, want: false},
		{name: "commit mismatch", report: catalogueReport(registry, nil), buildCommit: "ffffffff", want: false},
		{name: "empty build commit", report: catalogueReport(registry, nil), buildCommit: "", want: false},
		{name: "empty report commit", report: func() *Report { r := catalogueReport(registry, nil); r.Commit = ""; return r }(), buildCommit: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalogue(registry, tc.report, tc.buildCommit, nil)
			if got := c.ReportValid(); got != tc.want {
				t.Fatalf("ReportValid() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestLaunchGateOpenBranches(t *testing.T) {
	registry := catalogueRegistry()
	cases := []struct {
		name      string
		overrides map[string]Verdict
		valid     bool
		want      bool
	}{
		{name: "all pass", valid: true, want: true},
		{name: "report invalid", valid: false, want: false},
		{name: "MUST fails", overrides: map[string]Verdict{"AL-010": VerdictFail}, valid: true, want: false},
		{name: "MUST NOT missing test", overrides: map[string]Verdict{"AL-001": VerdictMissingTest}, valid: true, want: false},
		{name: "MUST check", overrides: map[string]Verdict{"AL-010": VerdictCheck}, valid: true, want: false},
		{name: "SHOULD fails does not close gate", overrides: map[string]Verdict{"AL-002": VerdictFail}, valid: true, want: true},
		{name: "MAY check does not close gate", overrides: map[string]Verdict{"AL-003": VerdictCheck}, valid: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buildCommit := testBuildCommit
			if !tc.valid {
				buildCommit = "other"
			}
			c := NewCatalogue(registry, catalogueReport(registry, tc.overrides), buildCommit, nil)
			if got := c.LaunchGateOpen(); got != tc.want {
				t.Fatalf("LaunchGateOpen() = %t, want %t", got, tc.want)
			}
		})
	}

	t.Run("MUST requirement absent from report", func(t *testing.T) {
		report := catalogueReport(registry, nil)
		report.Requirements = report.Requirements[1:]
		c := NewCatalogue(registry, report, testBuildCommit, nil)
		if c.LaunchGateOpen() {
			t.Fatal("LaunchGateOpen() = true with a MUST requirement missing from the report")
		}
	})
}

func TestIndexableBranches(t *testing.T) {
	registry := catalogueRegistry()
	explainers := mapExplainers{"al-010": "# x", "al-002": "# y", "be-001": "# z", "al-003": "# w"}

	t.Run("pass with explainer", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, explainers)
		if !c.Indexable("AL-010") || !c.Indexable("al-010") {
			t.Fatal("PASS requirement with explainer should be indexable, case-insensitively")
		}
		if !c.Indexable("BE-001") {
			t.Fatal("DEVIATION requirement with explainer should be indexable")
		}
	})
	t.Run("N/A with explainer", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, map[string]Verdict{"AL-003": VerdictNotApply}), testBuildCommit, explainers)
		if !c.Indexable("AL-003") {
			t.Fatal("N/A requirement with explainer should be indexable")
		}
	})
	t.Run("no explainer", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, explainers)
		if c.Indexable("AL-001") {
			t.Fatal("requirement without explainer must not be indexable")
		}
	})
	t.Run("nil explainer source", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, nil)
		if c.Indexable("AL-010") {
			t.Fatal("no explainer source means nothing is indexable")
		}
	})
	t.Run("gate closed", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, map[string]Verdict{"AL-001": VerdictFail}), testBuildCommit, explainers)
		if c.Indexable("AL-010") {
			t.Fatal("closed launch gate must make every page non-indexable")
		}
		if c.SpecIndexable("alpha") {
			t.Fatal("closed launch gate must make spec pages non-indexable")
		}
	})
	t.Run("non-passing verdict", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, map[string]Verdict{"AL-002": VerdictFail}), testBuildCommit, explainers)
		if c.Indexable("AL-002") {
			t.Fatal("FAIL requirement must not be indexable")
		}
		if !c.Indexable("AL-010") {
			t.Fatal("a SHOULD failure must not affect other requirements")
		}
	})
	t.Run("report invalid", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), "other", explainers)
		if c.Indexable("AL-010") {
			t.Fatal("invalid report must make every page non-indexable")
		}
	})
	t.Run("spec indexable when any requirement is", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, mapExplainers{"al-010": "# x"})
		if !c.SpecIndexable("alpha") {
			t.Fatal("alpha has an indexable requirement")
		}
		if c.SpecIndexable("beta") {
			t.Fatal("beta has no indexable requirement")
		}
	})
	t.Run("unknown requirement", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, explainers)
		if c.Indexable("ZZ-999") {
			t.Fatal("unknown requirement must not be indexable")
		}
	})
}

func TestCatalogueOrderingAndNeighbours(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, nil, "", nil)

	specs := c.Specifications()
	if len(specs) != 2 || specs[0].ID != "alpha" || specs[1].ID != "beta" {
		t.Fatalf("Specifications() = %+v, want alpha and beta only", specs)
	}
	if _, ok := c.Specification("empty"); ok {
		t.Fatal("specification with zero requirements must not resolve")
	}
	if _, ok := c.Specification("ALPHA"); !ok {
		t.Fatal("specification lookup should be case-insensitive")
	}

	reqs := c.Requirements("alpha")
	gotOrder := []string{reqs[0].ID, reqs[1].ID, reqs[2].ID, reqs[3].ID}
	wantOrder := []string{"AL-001", "AL-002", "AL-003", "AL-010"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("Requirements(alpha) order = %v, want %v", gotOrder, wantOrder)
		}
	}

	siblings, previous, next := c.Neighbours("al-002")
	if len(siblings) != 1 || siblings[0].ID != "AL-003" {
		t.Fatalf("siblings of AL-002 = %+v, want AL-003", siblings)
	}
	if previous == nil || previous.ID != "AL-001" || next == nil || next.ID != "AL-003" {
		t.Fatalf("previous/next of AL-002 = %v/%v, want AL-001/AL-003", previous, next)
	}
	_, first, _ := c.Neighbours("AL-001")
	if first != nil {
		t.Fatal("first requirement must have no previous")
	}
	_, _, last := c.Neighbours("AL-010")
	if last != nil {
		t.Fatal("last requirement must have no next")
	}

	if req, ok := c.Requirement("al-010"); !ok || req.ID != "AL-010" {
		t.Fatalf("Requirement(al-010) = %+v, %t; want canonical AL-010", req, ok)
	}
}

func TestResultHiddenWhenReportInvalid(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), "other", nil)
	if _, ok := c.Result("AL-010"); ok {
		t.Fatal("Result must be hidden when the report does not match the build")
	}
	if c.VerdictSummary("alpha") != nil {
		t.Fatal("VerdictSummary must be nil when the report does not match the build")
	}
	if entries := c.Sitemap(); len(entries) != 0 {
		t.Fatalf("Sitemap() = %+v, want empty", entries)
	}
}
