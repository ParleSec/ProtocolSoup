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

func TestRegistryValidationRequiresExecutableEvidence(t *testing.T) {
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
			ID:      "example",
			Title:   "Example",
			Version: "1",
			URL:     "https://example.test/spec",
		}},
		Requirements: []Requirement{{
			ID:             "EX-001",
			Specification:  "example",
			Section:        "1",
			Level:          "MUST",
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

	if err := Validate(registry, root); err != nil {
		t.Fatalf("Validate(valid registry): %v", err)
	}

	registry.Requirements[0].Tests = nil
	if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "executable test") {
		t.Fatalf("Validate(missing test) = %v, want executable-test error", err)
	}
}

func TestRegistryDeviationRequiresExistingADR(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "backend/internal/example/example.go")
	writeTestFile(t, root, "backend/internal/example/example_test.go")

	registry := Registry{
		SchemaVersion: SchemaVersion,
		Suite: SuiteBaseline{
			Release: "release-v1",
			Commit:  "0123456789",
			URL:     "https://example.test/release-v1",
		},
		Specifications: []Specification{{
			ID:      "example",
			Title:   "Example",
			Version: "1",
			URL:     "https://example.test/spec",
		}},
		Requirements: []Requirement{{
			ID:             "EX-001",
			Specification:  "example",
			Section:        "1",
			Level:          "SHOULD",
			Statement:      "The implementation SHOULD explain deviations.",
			Roles:          []string{"server"},
			Applicability:  "deviation",
			Implementation: []string{"backend/internal/example/example.go"},
			Tests: []TestRef{{
				Package: "./internal/example",
				File:    "backend/internal/example/example_test.go",
				Name:    "TestExample",
			}},
		}},
	}

	if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "requires an ADR") {
		t.Fatalf("Validate(deviation without ADR) = %v, want ADR error", err)
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
