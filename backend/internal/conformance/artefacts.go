package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// ArtefactSchemaVersion is the artefacts.json format this build reads.
const ArtefactSchemaVersion = 1

// ArtefactActor names who sent the requests in an artefact. The hosted wallet
// only ever behaves as a conformant wallet; malformed requests come from the
// conformance client, and deliberately broken servers are the counterparty.
type ArtefactActor string

const (
	ActorConformanceClient ArtefactActor = "conformance_client"
	ActorHostedWallet      ArtefactActor = "hosted_wallet"
	ActorCounterparty      ArtefactActor = "counterparty"
)

// ArtefactOutcome is what production did with the scenario's requests.
type ArtefactOutcome string

const (
	OutcomeAccepted ArtefactOutcome = "accepted"
	OutcomeRejected ArtefactOutcome = "rejected"
)

// ArtefactKind is the role an artefact plays on its requirement page.
type ArtefactKind string

const (
	KindPassing ArtefactKind = "passing"
	KindFailing ArtefactKind = "failing"
)

// Artefact is one captured scenario: the exchanges a real client had with
// the deployed server, recorded in full.
type Artefact struct {
	Scenario    string                          `json:"scenario"`
	Actor       ArtefactActor                   `json:"actor"`
	Description string                          `json:"description"`
	Expected    ArtefactOutcome                 `json:"expected_outcome"`
	Outcome     ArtefactOutcome                 `json:"outcome"`
	Exchanges   []lookingglass.CapturedExchange `json:"exchanges"`
}

// RequirementArtefacts holds a requirement's passing and failing artefacts.
// Unavailable gives the reason, per kind, that one could not be captured from
// production; a kind is never silently missing.
type RequirementArtefacts struct {
	ID          string                  `json:"id"`
	Passing     *Artefact               `json:"passing,omitempty"`
	Failing     *Artefact               `json:"failing,omitempty"`
	Unavailable map[ArtefactKind]string `json:"unavailable,omitempty"`
}

// ArtefactSet is the output of cmd/conformance-capture for one deployed build.
type ArtefactSet struct {
	SchemaVersion int                    `json:"schema_version"`
	Commit        string                 `json:"commit"`
	CapturedAt    time.Time              `json:"captured_at"`
	PublishAfter  time.Time              `json:"publish_after"`
	BaseURLs      map[string]string      `json:"base_urls"`
	Requirements  []RequirementArtefacts `json:"requirements"`
}

// LoadArtefacts reads an artefacts.json file.
func LoadArtefacts(path string) (*ArtefactSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set ArtefactSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse artefacts: %w", err)
	}
	if set.SchemaVersion != ArtefactSchemaVersion {
		return nil, fmt.Errorf("artefacts schema_version %d is not %d", set.SchemaVersion, ArtefactSchemaVersion)
	}
	return &set, nil
}

// SetArtefacts attaches captured artefacts to the catalogue.
func (c *Catalogue) SetArtefacts(set *ArtefactSet) {
	c.artefacts = set
	c.artefactsByID = make(map[string]RequirementArtefacts)
	if set == nil {
		return
	}
	for _, entry := range set.Requirements {
		c.artefactsByID[strings.ToUpper(entry.ID)] = entry
	}
}

// ArtefactsValid reports whether the attached artefacts were captured from
// the build this server is running, the same rule ReportValid applies to the
// conformance report.
func (c *Catalogue) ArtefactsValid() bool {
	if c.artefacts == nil {
		return false
	}
	commit := strings.TrimSpace(c.artefacts.Commit)
	return commit != "" && commit == strings.TrimSpace(c.buildCommit)
}

// ArtefactStatus is the state of a requirement's artefacts in a response.
type ArtefactStatus string

const (
	// ArtefactsPublished means the exchanges are included.
	ArtefactsPublished ArtefactStatus = "published"
	// ArtefactsPending means they were captured but some token or code in
	// them is still usable, so they are withheld until publish_after.
	ArtefactsPending ArtefactStatus = "pending"
	// ArtefactsNotCaptured means no valid set covers this build.
	ArtefactsNotCaptured ArtefactStatus = "not_captured"
)

// RequirementArtefactsResponse is the body of
// GET /requirements/{id}/artefacts.
type RequirementArtefactsResponse struct {
	ID            string                  `json:"id"`
	Status        ArtefactStatus          `json:"status"`
	Commit        string                  `json:"commit,omitempty"`
	CapturedAt    string                  `json:"captured_at,omitempty"`
	PublishAfter  string                  `json:"publish_after,omitempty"`
	SourceBaseURL string                  `json:"source_base_url,omitempty"`
	Passing       *Artefact               `json:"passing,omitempty"`
	Failing       *Artefact               `json:"failing,omitempty"`
	Unavailable   map[ArtefactKind]string `json:"unavailable,omitempty"`
}

// requirementArtefacts builds the response for one requirement at now.
func (c *Catalogue) requirementArtefacts(req Requirement, now time.Time) RequirementArtefactsResponse {
	response := RequirementArtefactsResponse{ID: req.ID, Status: ArtefactsNotCaptured}
	if !c.ArtefactsValid() {
		return response
	}
	entry, ok := c.artefactsByID[strings.ToUpper(req.ID)]
	if !ok {
		return response
	}
	set := c.artefacts
	response.Commit = set.Commit
	response.CapturedAt = set.CapturedAt.UTC().Format(time.RFC3339)
	response.PublishAfter = set.PublishAfter.UTC().Format(time.RFC3339)
	response.SourceBaseURL = SourceRepository + "/blob/" + set.Commit + "/"
	response.Unavailable = entry.Unavailable
	if now.Before(set.PublishAfter) {
		response.Status = ArtefactsPending
		return response
	}
	response.Status = ArtefactsPublished
	response.Passing = entry.Passing
	response.Failing = entry.Failing
	return response
}
