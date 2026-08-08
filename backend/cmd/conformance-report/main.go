// Command conformance-report validates the canonical VC requirement registry,
// executes its mapped Go tests, and emits the deterministic public evidence
// document consumed by the Starlight site.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "conformance-report:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("conformance-report", flag.ContinueOnError)
	verify := flags.Bool("verify", false, "fail if the output differs from the tracked file")
	validateOnly := flags.Bool("validate-only", false, "validate registry metadata without running tests")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	backendDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve backend directory: %w", err)
	}
	repoRoot := filepath.Dir(backendDir)
	registryPath := filepath.Join(backendDir, "internal", "conformance", "vc-requirements.yaml")
	outputPath := filepath.Join(repoRoot, "artifacts", "vc-conformance", "report.json")

	registry, err := conformance.Load(registryPath)
	if err != nil {
		return err
	}
	if err := conformance.Validate(registry, repoRoot); err != nil {
		return fmt.Errorf("invalid registry:\n%w", err)
	}
	if *validateOnly {
		fmt.Printf("conformance-report: %d requirements valid\n", len(registry.Requirements))
		return nil
	}

	report, testErr := conformance.GenerateReport(ctx, registry, backendDir)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	if *verify {
		tracked, err := os.ReadFile(outputPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(tracked, encoded) {
			return errors.New("generated conformance report differs from tracked output; run conformance-report and commit the result")
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
			return err
		}
		fmt.Printf("conformance-report: wrote %s\n", outputPath)
	}
	return testErr
}
