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
// Version 2 made failing a list, one artefact per way a requirement was
// broken and refused. Version 3 added examples. Version 4 gave an example
// its own publish time.
const ArtefactSchemaVersion = 4

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

// RequirementArtefacts holds a requirement's passing artefact and its failing
// artefacts, one per way the requirement was broken and refused. Unavailable
// gives the reason, per kind, that none could be captured from production; a
// kind is never silently missing.
type RequirementArtefacts struct {
	ID          string                  `json:"id"`
	Passing     *Artefact               `json:"passing,omitempty"`
	Failing     []Artefact              `json:"failing,omitempty"`
	Unavailable map[ArtefactKind]string `json:"unavailable,omitempty"`
}

// Where an example value sat in the exchange that carried it.
const (
	ExampleInRequest  = "request"
	ExampleInResponse = "response"
)

// ExampleSource says where an example value was on the wire.
type ExampleSource struct {
	// Exchange indexes the example's Exchanges.
	Exchange int `json:"exchange"`
	// Message is ExampleInRequest or ExampleInResponse.
	Message string `json:"message"`
	// Location names the place in that message, such as "the DPoP header".
	Location string `json:"location"`
	// FormField is set when the value is a control of an
	// application/x-www-form-urlencoded body, which carries it
	// percent-encoded. It names the control.
	FormField string `json:"form_field,omitempty"`
}

// How an example was checked when it was captured.
const (
	// VerifiedByXMLSignature is for a SAML message: its enveloped XML
	// Signature, and that of each Assertion in it, verified with the signing
	// certificate in the issuer's SAML metadata, which one of the example's
	// exchanges fetched and whose entityID equals the message's Issuer.
	VerifiedByXMLSignature = "xml_signature"
	// VerifiedByIssuerMetadata is for an SD-JWT VC: the signature verified
	// under the key, selected by kid, in the JWT VC Issuer Metadata one of
	// the example's exchanges fetched, whose issuer equals the credential's
	// iss. The end-entity certificate in x5c carries the same key, and each
	// Disclosure's digest appears once in _sd.
	VerifiedByIssuerMetadata = "jwt_vc_issuer_metadata"
	// VerifiedByIssuer is for a metadata document, which carries no
	// signature: the member that names its issuer equals the issuer
	// identifier the request URL was built from.
	VerifiedByIssuer = "issuer"
	// VerifiedByLocation is for a SCIM resource, which carries no signature:
	// the value is the whole body of the response to a GET of the URI its
	// own meta.location names; that response's Content-Location and ETag
	// headers equal meta.location and meta.version (RFC 7643 Section 3.1);
	// and the 201 response that created the resource, in one of the
	// example's exchanges, named the same URI in its Location header and the
	// same id in its body (RFC 7644 Section 3.3).
	VerifiedByLocation = "location"
	// VerifiedByEmbeddedJWK means the signature verified under the public
	// key in the value's own jwk header parameter.
	VerifiedByEmbeddedJWK = "embedded_jwk"
	// VerifiedByJWKS means the signature verified under the key, selected by
	// kid, in the JWK Set one of the example's exchanges fetched.
	VerifiedByJWKS = "jwks"
)

// ExampleVerification records the check the capture run made on an example
// value. The run fails rather than record a value that does not pass it.
type ExampleVerification struct {
	Method string `json:"method"`
	// Algorithm is the JWS alg of a signed value.
	Algorithm string `json:"algorithm,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	// JWKSExchange indexes the exchange that fetched the keys: the JWK Set
	// for VerifiedByJWKS, the JWT VC Issuer Metadata for
	// VerifiedByIssuerMetadata, the SAML metadata for VerifiedByXMLSignature.
	JWKSExchange *int `json:"jwks_exchange,omitempty"`
	// IssuerMember names the member that carries the issuer, and Issuer is
	// its value, for VerifiedByIssuer.
	IssuerMember string `json:"issuer_member,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	// Location is the resource's meta.location, and CreatedExchange indexes
	// the exchange that created the resource, for VerifiedByLocation.
	Location        string `json:"location,omitempty"`
	CreatedExchange *int   `json:"created_exchange,omitempty"`
}

// CapturedExample is one example value with the exchanges that carried and
// verified it, recorded in full.
type CapturedExample struct {
	ID           string                          `json:"id"`
	Actor        ArtefactActor                   `json:"actor"`
	Description  string                          `json:"description"`
	Value        string                          `json:"value"`
	Source       ExampleSource                   `json:"source"`
	Verification ExampleVerification             `json:"verification"`
	Exchanges    []lookingglass.CapturedExchange `json:"exchanges"`
	// PublishAfter is when the value itself stops being acceptable, for a
	// value that cannot be revoked. The example is published at the later of
	// this and the set's PublishAfter. It is zero when the value was revoked
	// or is good for one use only.
	PublishAfter time.Time `json:"publish_after,omitzero"`
}

// ArtefactSet is the output of cmd/conformance-capture for one deployed build.
type ArtefactSet struct {
	SchemaVersion int                    `json:"schema_version"`
	Commit        string                 `json:"commit"`
	CapturedAt    time.Time              `json:"captured_at"`
	PublishAfter  time.Time              `json:"publish_after"`
	BaseURLs      map[string]string      `json:"base_urls"`
	Requirements  []RequirementArtefacts `json:"requirements"`
	Examples      []CapturedExample      `json:"examples,omitempty"`
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
	Failing       []Artefact              `json:"failing,omitempty"`
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
