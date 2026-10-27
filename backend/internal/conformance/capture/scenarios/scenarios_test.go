package scenarios

import (
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// TestEveryRequirementHasAnEntry keeps the scenario catalogue and the
// registry in step: every requirement is demonstrated, explained as
// unavailable, or listed in pending, never two of those and never silently
// missing; and nothing is registered for a requirement the registry lacks.
func TestEveryRequirementHasAnEntry(t *testing.T) {
	registry, err := conformance.Embedded()
	if err != nil {
		t.Fatalf("embedded registry: %v", err)
	}
	entries := capture.Entries()
	isPending := map[string]bool{}
	for _, id := range pending {
		if isPending[id] {
			t.Errorf("%s is listed twice in pending", id)
		}
		isPending[id] = true
	}
	known := map[string]bool{}
	for _, req := range registry.Requirements {
		known[req.ID] = true
		entry, registered := entries[req.ID]
		switch {
		case registered && isPending[req.ID]:
			t.Errorf("%s is registered and still listed in pending; remove it from pending", req.ID)
			continue
		case !registered && !isPending[req.ID]:
			t.Errorf("%s has no capture entry; register scenarios or an unavailable reason, or list it in pending", req.ID)
			continue
		case !registered:
			continue
		}
		for _, kind := range []conformance.ArtefactKind{conformance.KindPassing, conformance.KindFailing} {
			scenario := entry.Passing
			want := conformance.OutcomeAccepted
			if kind == conformance.KindFailing {
				scenario = entry.Failing
				want = conformance.OutcomeRejected
			}
			reason := strings.TrimSpace(entry.Unavailable[kind])
			switch {
			case scenario == nil && reason == "":
				t.Errorf("%s %s has neither a scenario nor an unavailable reason", req.ID, kind)
			case scenario != nil && reason != "":
				t.Errorf("%s %s has both a scenario and an unavailable reason", req.ID, kind)
			case scenario != nil && scenario.Expected != want:
				t.Errorf("%s %s scenario %q expects %s; a %s scenario expects %s", req.ID, kind, scenario.Name, scenario.Expected, kind, want)
			case scenario != nil && (scenario.Name == "" || scenario.Description == "" || scenario.Actor == "" || scenario.Run == nil):
				t.Errorf("%s %s scenario is missing a name, description, actor or Run", req.ID, kind)
			}
		}
	}
	for id := range entries {
		if !known[id] {
			t.Errorf("capture entry %s is not a registry requirement", id)
		}
	}
	for id := range isPending {
		if !known[id] {
			t.Errorf("pending lists %s, which is not a registry requirement", id)
		}
	}
}
