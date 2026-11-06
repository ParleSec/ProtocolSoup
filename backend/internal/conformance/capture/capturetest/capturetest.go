// Package capturetest runs a scenario package's captures against a live
// server from that package's tests.
package capturetest

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// RunLive captures every scenario registered in the calling test binary
// against the local server on CAPTURE_PORT (plus the wallet on
// CAPTURE_WALLET_PORT and the counterparty on CAPTURE_COUNTERPARTY_PORT, or
// the deployed counterparty with CAPTURE_PRODUCTION_COUNTERPARTY=true, when
// set), optionally limited by CAPTURE_ONLY, and fails the test on any
// mismatch. Like the conformance-capture command, it reaches only localhost
// ports and ProtocolSoup's own deployed apps. Without CAPTURE_PORT it skips,
// so ordinary test runs never reach a network server. A scenario package calls it from a TestLive, which runs
// only that package's scenarios because only they are registered in its test
// binary.
func RunLive(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("CAPTURE_PORT")) == "" {
		t.Skip("set CAPTURE_PORT to the port of a local server to capture live")
	}
	origins, err := capture.LocalOrigins(
		portFromEnv(t, "CAPTURE_PORT"),
		portFromEnv(t, "CAPTURE_WALLET_PORT"),
		portFromEnv(t, "CAPTURE_COUNTERPARTY_PORT"),
		strings.EqualFold(strings.TrimSpace(os.Getenv("CAPTURE_PRODUCTION_COUNTERPARTY")), "true"),
	)
	if err != nil {
		t.Fatalf("capture origins: %v", err)
	}
	recorder := capture.NewRecorder(nil)
	env := capture.NewEnv(origins.Base, origins.Wallet, origins.Counterparty, recorder, 90)
	var only []string
	if raw := strings.TrimSpace(os.Getenv("CAPTURE_ONLY")); raw != "" {
		only = strings.Split(raw, ",")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	set, mismatches, err := capture.Run(ctx, env, recorder, "live", only)
	if err != nil {
		t.Fatalf("capture run: %v", err)
	}
	for _, req := range set.Requirements {
		logArtefact(t, req.ID, conformance.KindPassing, req.Passing)
		logArtefact(t, req.ID, conformance.KindFailing, req.Failing)
		for kind, reason := range req.Unavailable {
			t.Logf("%s %s: unavailable: %s", req.ID, kind, reason)
		}
	}
	for _, mismatch := range mismatches {
		t.Errorf("mismatch: %s", mismatch)
	}
}

// portFromEnv reads a port number from name, 0 when it is unset.
func portFromEnv(t *testing.T, name string) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s must be a port number, got %q", name, raw)
	}
	return port
}

func logArtefact(t *testing.T, id string, kind conformance.ArtefactKind, artefact *conformance.Artefact) {
	t.Helper()
	if artefact == nil {
		return
	}
	t.Logf("%s %s: %s outcome=%s expected=%s", id, kind, artefact.Scenario, artefact.Outcome, artefact.Expected)
	for _, exchange := range artefact.Exchanges {
		body := ""
		if exchange.Response.Body != nil {
			body = exchange.Response.Body.Data
			if len(body) > 160 {
				body = body[:160] + "..."
			}
		}
		t.Logf("    %s %s -> %d %s", exchange.Request.Method, exchange.Request.URL, exchange.Response.Status, body)
	}
}
