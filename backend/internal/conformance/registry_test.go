package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryRejectsUnknownFields(t *testing.T) {
	_, err := Decode(strings.NewReader(`
schema_version: 1
unknown: true
`))
	if err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

// validRegistryFixture returns a registry that passes Validate against a
// temp repo root containing the referenced files.
func validRegistryFixture(t *testing.T) (Registry, string) {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "backend/internal/example/example.go")
	writeTestFile(t, root, "backend/internal/example/example_test.go")
	writeTestFile(t, root, "docs/decisions/0001-example.md")

	registry := Registry{
		SchemaVersion: SchemaVersion,
		Suite: SuiteBaseline{
			Release: "release-v1",
			Commit:  "0123456789",
			URL:     "https://example.test/release-v1",
		},
		Specifications: []Specification{{
			ID:            "example",
			Title:         "Example Specification",
			ShortTitle:    "Example 1.0",
			Version:       "1",
			URL:           "https://example.test/spec",
			SectionAnchor: "#section-{section}",
		}},
		Requirements: []Requirement{{
			ID:             "EX-001",
			Specification:  "example",
			Section:        "1",
			Level:          "MUST",
			Title:          "Executable evidence for the implementation",
			Statement:      "The implementation MUST have executable evidence.",
			Roles:          []string{"server"},
			Applicability:  "applicable",
			Implementation: []string{"backend/internal/example/example.go"},
			Tests: []TestRef{{
				Package: "./internal/example",
				File:    "backend/internal/example/example_test.go",
				Name:    "TestExample",
			}},
		}},
	}
	return registry, root
}

func TestRegistryValidationRequiresExecutableEvidence(t *testing.T) {
	registry, root := validRegistryFixture(t)

	if err := Validate(registry, root); err != nil {
		t.Fatalf("Validate(valid registry): %v", err)
	}

	registry.Requirements[0].Tests = nil
	if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "executable test") {
		t.Fatalf("Validate(missing test) = %v, want executable-test error", err)
	}
}

func TestRegistryDeviationRequiresExistingADR(t *testing.T) {
	registry, root := validRegistryFixture(t)
	registry.Requirements[0].Level = "SHOULD"
	registry.Requirements[0].Statement = "The implementation SHOULD explain deviations."
	registry.Requirements[0].Applicability = "deviation"

	if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "requires an ADR") {
		t.Fatalf("Validate(deviation without ADR) = %v, want ADR error", err)
	}
}

func TestRegistryValidationRequiresShortTitle(t *testing.T) {
	registry, root := validRegistryFixture(t)
	registry.Specifications[0].ShortTitle = " "
	if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "short_title is required") {
		t.Fatalf("Validate(missing short_title) = %v, want short_title error", err)
	}
}

func TestRegistryValidationSectionAnchorPlaceholder(t *testing.T) {
	for _, anchor := range []string{"#section-", "#{section}-{section}"} {
		registry, root := validRegistryFixture(t)
		registry.Specifications[0].SectionAnchor = anchor
		if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "exactly once") {
			t.Fatalf("Validate(section_anchor %q) = %v, want placeholder error", anchor, err)
		}
	}

	registry, root := validRegistryFixture(t)
	registry.Specifications[0].SectionAnchor = ""
	if err := Validate(registry, root); err != nil {
		t.Fatalf("Validate(unset section_anchor): %v", err)
	}
}

func TestRegistryValidationTitleRules(t *testing.T) {
	cases := []struct {
		name  string
		title string
		want  string
	}{
		{name: "missing", title: "", want: "title is required"},
		{name: "too long", title: strings.Repeat("a", MaxTitleLength+1), want: "exceeds 70 characters"},
		{name: "trailing full stop", title: "Executable evidence.", want: "must not end with a full stop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, root := validRegistryFixture(t)
			registry.Requirements[0].Title = tc.title
			if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate(title %q) = %v, want %q", tc.title, err, tc.want)
			}
		})
	}

	registry, root := validRegistryFixture(t)
	registry.Requirements[0].Title = strings.Repeat("a", MaxTitleLength)
	if err := Validate(registry, root); err != nil {
		t.Fatalf("Validate(title at limit): %v", err)
	}
}

func TestSectionURL(t *testing.T) {
	registry, _ := validRegistryFixture(t)
	registry.Specifications = append(registry.Specifications, Specification{
		ID: "noanchor", Title: "No Anchor", ShortTitle: "NA", Version: "1", URL: "https://example.test/noanchor",
	})

	cases := []struct {
		name string
		req  Requirement
		want string
	}{
		{name: "dotted section", req: Requirement{Specification: "example", Section: "5.9.1"}, want: "https://example.test/spec#section-5.9.1"},
		{name: "compound section falls back", req: Requirement{Specification: "example", Section: "6.3 and 8.2"}, want: "https://example.test/spec"},
		{name: "appendix falls back", req: Requirement{Specification: "example", Section: "Appendix F.1"}, want: "https://example.test/spec"},
		{name: "no anchor template", req: Requirement{Specification: "noanchor", Section: "9.1.2"}, want: "https://example.test/noanchor"},
		{name: "unknown spec", req: Requirement{Specification: "missing", Section: "1"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := registry.SectionURL(tc.req); got != tc.want {
				t.Fatalf("SectionURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompareSections(t *testing.T) {
	ordered := []string{"5", "5.9", "5.9.1", "5.10", "11.1", "Appendix F.1", "B.1"}
	for i := 0; i < len(ordered); i++ {
		if got := CompareSections(ordered[i], ordered[i]); got != 0 {
			t.Fatalf("CompareSections(%q, %q) = %d, want 0", ordered[i], ordered[i], got)
		}
		for j := i + 1; j < len(ordered); j++ {
			if got := CompareSections(ordered[i], ordered[j]); got != -1 {
				t.Fatalf("CompareSections(%q, %q) = %d, want -1", ordered[i], ordered[j], got)
			}
			if got := CompareSections(ordered[j], ordered[i]); got != 1 {
				t.Fatalf("CompareSections(%q, %q) = %d, want 1", ordered[j], ordered[i], got)
			}
		}
	}
}

func TestIsMustFamily(t *testing.T) {
	for _, level := range []string{"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT"} {
		if !IsMustFamily(level) {
			t.Fatalf("IsMustFamily(%q) = false, want true", level)
		}
	}
	for _, level := range []string{"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", "OPTIONAL", ""} {
		if IsMustFamily(level) {
			t.Fatalf("IsMustFamily(%q) = true, want false", level)
		}
	}
}

func TestEmbeddedRegistryMatchesDiskAndValidates(t *testing.T) {
	embedded, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded(): %v", err)
	}
	disk, err := Load("vc-requirements.yaml")
	if err != nil {
		t.Fatalf("Load(disk): %v", err)
	}
	if len(embedded.Requirements) != len(disk.Requirements) || len(embedded.Specifications) != len(disk.Specifications) {
		t.Fatalf("embedded registry (%d specs, %d requirements) differs from disk (%d specs, %d requirements)",
			len(embedded.Specifications), len(embedded.Requirements), len(disk.Specifications), len(disk.Requirements))
	}
	repoRoot := filepath.Join("..", "..", "..")
	if err := Validate(embedded, repoRoot); err != nil {
		t.Fatalf("Validate(embedded): %v", err)
	}
}

func writeTestFile(t *testing.T, root, path string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
}
