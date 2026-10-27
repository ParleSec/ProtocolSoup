// Command conformance-capture sends each conformance requirement's passing
// and failing scenario to a deployed ProtocolSoup and writes the recorded
// exchanges to artifacts/vc-conformance/artefacts.json, which the next image
// of the same commit serves on the requirement pages. Run it from backend/.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "conformance-capture:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("conformance-capture", flag.ContinueOnError)
	base := flags.String("base", "", "main app origin, e.g. https://protocolsoup.com (required)")
	wallet := flags.String("wallet", "", "hosted wallet origin, e.g. https://wallet.protocolsoup.com")
	counterparty := flags.String("counterparty", "", "conformance counterparty origin, when deployed")
	commit := flags.String("commit", "", "commit the deployed apps must report on /health; defaults to what the main app reports")
	only := flags.String("only", "", "comma-separated requirement IDs to capture; all registered when empty")
	out := flags.String("out", "", "output path; defaults to <repo>/artifacts/vc-conformance/artefacts.json")
	rpm := flags.Int("rpm", capture.DefaultRequestsPerMinute, "requests per minute against the deployed apps")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if strings.TrimSpace(*base) == "" {
		return fmt.Errorf("-base is required")
	}

	outputPath := *out
	if outputPath == "" {
		backendDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve backend directory: %w", err)
		}
		outputPath = filepath.Join(filepath.Dir(backendDir), "artifacts", "vc-conformance", "artefacts.json")
	}

	// Artefacts are only meaningful for the build that produced them, so the
	// run refuses to start unless every app it talks to serves that build.
	deployed, err := healthCommit(ctx, *base)
	if err != nil {
		return err
	}
	expected := strings.TrimSpace(*commit)
	if expected == "" {
		expected = deployed
	}
	if expected == "" {
		return fmt.Errorf("%s/health reports no commit; set BUILD_COMMIT on the server or pass -commit", *base)
	}
	if deployed != expected {
		return fmt.Errorf("%s/health reports commit %q, want %q", *base, deployed, expected)
	}
	if strings.TrimSpace(*wallet) != "" {
		walletCommit, err := healthCommit(ctx, *wallet)
		if err != nil {
			return err
		}
		if walletCommit != expected {
			return fmt.Errorf("%s/health reports commit %q, want %q", *wallet, walletCommit, expected)
		}
	}

	var ids []string
	if strings.TrimSpace(*only) != "" {
		ids = strings.Split(*only, ",")
	}
	recorder := capture.NewRecorder(nil)
	env := capture.NewEnv(*base, *wallet, *counterparty, recorder, *rpm)
	set, mismatches, err := capture.Run(ctx, env, recorder, expected, ids)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("conformance-capture: wrote %d requirements for commit %s to %s (publish after %s)\n",
		len(set.Requirements), expected, outputPath, set.PublishAfter.Format(time.RFC3339))

	if len(mismatches) > 0 {
		for _, mismatch := range mismatches {
			fmt.Fprintln(os.Stderr, "conformance-capture: mismatch:", mismatch)
		}
		return fmt.Errorf("%d scenario(s) did not behave as a conformant server would", len(mismatches))
	}
	return nil
}

// healthCommit reads the commit an app reports on /health.
func healthCommit(ctx context.Context, origin string) (string, error) {
	target := strings.TrimRight(origin, "/") + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", capture.UserAgent)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s answered %d", target, resp.StatusCode)
	}
	var health struct {
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return "", fmt.Errorf("parse %s: %w", target, err)
	}
	return strings.TrimSpace(health.Commit), nil
}
