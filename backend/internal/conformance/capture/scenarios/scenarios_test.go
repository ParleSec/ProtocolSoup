package scenarios

import (
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// TestEveryRequirementHasAnEntry keeps the scenario catalogue and the
// registry in step: every requirement is demonstrated or explained as
// unavailable, never both and never silently missing; and nothing is
// registered for a requirement the registry lacks.
func TestEveryRequirementHasAnEntry(t *testing.T) {
	registry, err := conformance.Embedded()
	if err != nil {
		t.Fatalf("embedded registry: %v", err)
	}
	entries := capture.Entries()
	known := map[string]bool{}
	for _, req := range registry.Requirements {
		known[req.ID] = true
		entry, registered := entries[req.ID]
		if !registered {
			t.Errorf("%s has no capture entry; register scenarios or an unavailable reason", req.ID)
			continue
		}
		for _, kind := range []conformance.ArtefactKind{conformance.KindPassing, conformance.KindFailing} {
			scenarios := entry.Scenarios(kind)
			want := conformance.OutcomeAccepted
			if kind == conformance.KindFailing {
				want = conformance.OutcomeRejected
			}
			reason := strings.TrimSpace(entry.Unavailable[kind])
			switch {
			case len(scenarios) == 0 && reason == "":
				t.Errorf("%s %s has neither a scenario nor an unavailable reason", req.ID, kind)
			case len(scenarios) > 0 && reason != "":
				t.Errorf("%s %s has both a scenario and an unavailable reason", req.ID, kind)
			}
			names := map[string]bool{}
			for _, scenario := range scenarios {
				switch {
				case scenario == nil:
					t.Errorf("%s %s registers a nil scenario", req.ID, kind)
				case scenario.Expected != want:
					t.Errorf("%s %s scenario %q expects %s; a %s scenario expects %s", req.ID, kind, scenario.Name, scenario.Expected, kind, want)
				case scenario.Name == "" || scenario.Description == "" || scenario.Actor == "" || scenario.Run == nil:
					t.Errorf("%s %s scenario is missing a name, description, actor or Run", req.ID, kind)
				case names[scenario.Name]:
					t.Errorf("%s %s registers scenario %q twice", req.ID, kind, scenario.Name)
				}
				if scenario != nil {
					names[scenario.Name] = true
				}
			}
		}
	}
	for id := range entries {
		if !known[id] {
			t.Errorf("capture entry %s is not a registry requirement", id)
		}
	}
}

// TestEveryExampleHasAScenario keeps the example scenarios and the registry
// in step: every registry example has a scenario that captures its value,
// and nothing is registered for an example the registry lacks.
func TestEveryExampleHasAScenario(t *testing.T) {
	registry, err := conformance.Embedded()
	if err != nil {
		t.Fatalf("embedded registry: %v", err)
	}
	scenarios := capture.ExampleScenarios()
	known := map[string]bool{}
	for _, example := range registry.Examples {
		known[example.ID] = true
		scenario, registered := scenarios[example.ID]
		switch {
		case !registered:
			t.Errorf("example %s has no capture scenario", example.ID)
		case strings.TrimSpace(scenario.Description) == "" || scenario.Actor == "" || scenario.Run == nil:
			t.Errorf("example %s scenario is missing a description, actor or Run", example.ID)
		}
	}
	for id := range scenarios {
		if !known[id] {
			t.Errorf("example scenario %s is not a registry example", id)
		}
	}
}
