package haipwallet

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// TestEveryRowHasExactlyOneSourcePerKind proves each row this package
// registers has a scenario or an unavailable reason for each kind, never
// both or neither, and that each scenario expects the outcome of its kind.
func TestEveryRowHasExactlyOneSourcePerKind(t *testing.T) {
	ids := []string{"CW-044", "CW-072", "CW-089", "CW-101", "CW-H003", "CW-H004", "CW-H010", "CW-H013", "CW-H014"}
	entries := capture.Entries()
	for _, id := range ids {
		entry, ok := entries[id]
		if !ok {
			t.Errorf("%s is not registered", id)
			continue
		}
		for _, kind := range []conformance.ArtefactKind{conformance.KindPassing, conformance.KindFailing} {
			scenarios := entry.Scenarios(kind)
			_, unavailable := entry.Unavailable[kind]
			if (len(scenarios) == 0) == !unavailable {
				t.Errorf("%s %s: want exactly one of a scenario or an unavailable reason", id, kind)
			}
			for _, scenario := range scenarios {
				if kind == conformance.KindPassing && scenario.Expected != conformance.OutcomeAccepted {
					t.Errorf("%s passing expects %s", id, scenario.Expected)
				}
				if kind == conformance.KindFailing && scenario.Expected != conformance.OutcomeRejected {
					t.Errorf("%s failing expects %s", id, scenario.Expected)
				}
			}
		}
	}
}
