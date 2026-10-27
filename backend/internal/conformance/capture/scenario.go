package capture

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
)

// Scenario is one capture: it sends real requests and reports what the
// server did with them.
type Scenario struct {
	Name        string
	Description string
	Actor       conformance.ArtefactActor
	// Expected is what a conformant server does: accept a passing scenario,
	// reject a failing one.
	Expected conformance.ArtefactOutcome
	// Run performs the scenario and returns the server's outcome. An error
	// means the exchange went somewhere neither outcome describes (a 5xx, an
	// unexpected error code), which the runner reports rather than records.
	Run func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error)
}

// Entry says how a requirement is demonstrated. Each kind is either a
// scenario or an unavailable reason.
type Entry struct {
	Passing     *Scenario
	Failing     *Scenario
	Unavailable map[conformance.ArtefactKind]string
}

// entries maps a registry requirement ID to how it is demonstrated. The
// scenario packages fill it from init; package scenarios imports them all
// and checks every registry row is covered.
var entries = map[string]Entry{}

// Register records how requirement id is demonstrated. Scenario packages
// call it from init; registering an ID twice is a programming error.
func Register(id string, entry Entry) {
	if _, exists := entries[id]; exists {
		panic("capture: duplicate entry for " + id)
	}
	entries[id] = entry
}

// Entries returns a copy of the registered entries.
func Entries() map[string]Entry {
	out := make(map[string]Entry, len(entries))
	for id, entry := range entries {
		out[id] = entry
	}
	return out
}

// Mismatch is a scenario whose outcome was not the conformant one, or that
// could not be completed.
type Mismatch struct {
	ID       string
	Kind     conformance.ArtefactKind
	Scenario string
	Reason   string
}

func (m Mismatch) String() string {
	return fmt.Sprintf("%s %s (%s): %s", m.ID, m.Kind, m.Scenario, m.Reason)
}

// Run captures every registered requirement, or only those in only when it
// is non-empty, and returns the artefact set. Mismatches are recorded
// truthfully in the set as well as returned, so the caller can fail loudly.
func Run(ctx context.Context, env *Env, recorder *Recorder, commit string, only []string) (*conformance.ArtefactSet, []Mismatch, error) {
	wanted := map[string]bool{}
	for _, id := range only {
		wanted[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		if len(wanted) > 0 && !wanted[id] {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	set := &conformance.ArtefactSet{
		SchemaVersion: conformance.ArtefactSchemaVersion,
		Commit:        commit,
		CapturedAt:    time.Now().UTC(),
		BaseURLs: map[string]string{
			"base":         env.BaseURL,
			"wallet":       env.WalletURL,
			"counterparty": env.CounterpartyURL,
		},
	}
	var mismatches []Mismatch
	for _, id := range ids {
		entry := entries[id]
		result := conformance.RequirementArtefacts{ID: id}
		if len(entry.Unavailable) > 0 {
			result.Unavailable = map[conformance.ArtefactKind]string{}
			for kind, reason := range entry.Unavailable {
				result.Unavailable[kind] = reason
			}
		}
		for _, kind := range []conformance.ArtefactKind{conformance.KindPassing, conformance.KindFailing} {
			scenario := entry.Passing
			if kind == conformance.KindFailing {
				scenario = entry.Failing
			}
			if scenario == nil {
				continue
			}
			_ = recorder.Take()
			outcome, err := scenario.Run(ctx, env)
			exchanges := recorder.Take()
			if ctx.Err() != nil {
				return nil, mismatches, ctx.Err()
			}
			if err != nil {
				mismatches = append(mismatches, Mismatch{ID: id, Kind: kind, Scenario: scenario.Name, Reason: err.Error()})
				continue
			}
			if outcome != scenario.Expected {
				mismatches = append(mismatches, Mismatch{ID: id, Kind: kind, Scenario: scenario.Name,
					Reason: fmt.Sprintf("production %s it; a conformant server %s it", outcome, scenario.Expected)})
			}
			artefact := &conformance.Artefact{
				Scenario:    scenario.Name,
				Actor:       scenario.Actor,
				Description: scenario.Description,
				Expected:    scenario.Expected,
				Outcome:     outcome,
				Exchanges:   exchanges,
			}
			if kind == conformance.KindPassing {
				result.Passing = artefact
			} else {
				result.Failing = artefact
			}
		}
		set.Requirements = append(set.Requirements, result)
	}
	set.PublishAfter = env.PublishAfter().UTC()
	if set.PublishAfter.Before(set.CapturedAt) {
		set.PublishAfter = set.CapturedAt
	}
	return set, mismatches, nil
}
