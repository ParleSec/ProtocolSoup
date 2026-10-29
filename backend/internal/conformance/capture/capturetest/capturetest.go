// Package capturetest runs a scenario package's captures against a live
// server from that package's tests.
package capturetest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// RunLive captures every scenario registered in the calling test binary
// against the server named by CAPTURE_BASE (plus CAPTURE_WALLET and
// CAPTURE_COUNTERPARTY when set), optionally limited by CAPTURE_ONLY, and
// fails the test on any mismatch. Without CAPTURE_BASE it skips, so ordinary
// test runs never reach a network server. A scenario package calls it from a
// TestLive, which runs only that package's scenarios because only they are
// registered in its test binary.
func RunLive(t *testing.T) {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("CAPTURE_BASE"))
	if base == "" {
		t.Skip("set CAPTURE_BASE to a running server to capture live")
	}
	recorder := capture.NewRecorder(nil)
	env := capture.NewEnv(base, os.Getenv("CAPTURE_WALLET"), os.Getenv("CAPTURE_COUNTERPARTY"), recorder, 90)
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
