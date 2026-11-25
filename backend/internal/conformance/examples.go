package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/go-chi/chi/v5"
)

// An example is one protocol message type, shown on its own page as the
// deployed sandbox really produced it. The registry owns what the message is
// and what each of its fields means; cmd/conformance-capture owns the value,
// which is always a message a real exchange carried.

// ExampleFormatJWT is a compact JWS whose payload is a JWT Claims Set. Its
// parts are the decoded JOSE Header ("header") and Claims Set ("payload").
const ExampleFormatJWT = "jwt"

// ExampleFormatJSON is a JSON object sent as the body of an HTTP message,
// such as a metadata document. Its one part is the object itself
// ("document").
const ExampleFormatJSON = "json"

// ExampleFormatSDJWT is an SD-JWT as an Issuer sends it (RFC 9901 Section
// 4): an Issuer-signed JWT and its Disclosures, each followed by "~". Its
// parts are the JOSE Header ("header"), the JWT Claims Set ("payload") and
// one "disclosure" per Disclosure, whose members are the three elements of
// the Disclosure's array: "salt", "name" and "value".
const ExampleFormatSDJWT = "sd-jwt"

// exampleDisclosurePart names the part each Disclosure of an SD-JWT becomes.
const exampleDisclosurePart = "disclosure"

// exampleParts lists, per format, the decoded parts a field path may start
// with.
var exampleParts = map[string][]string{
	ExampleFormatJWT:   {"header", "payload"},
	ExampleFormatJSON:  {"document"},
	ExampleFormatSDJWT: {"header", "payload", exampleDisclosurePart},
}

var exampleIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Example is a registry entry for one protocol message type.
type Example struct {
	// ID is the page's URL segment: lowercase words joined by hyphens.
	ID string `yaml:"id" json:"id"`
	// Title names the message, as a noun phrase with no trailing full stop.
	Title string `yaml:"title" json:"title"`
	// Question is the page's title and H1.
	Question string `yaml:"question" json:"question"`
	// Summary says what the message is. It is the first sentence on the page.
	Summary string `yaml:"summary" json:"summary"`
	Format  string `yaml:"format" json:"format"`
	// LookingGlass names the flow that produces this message live.
	LookingGlass ExampleFlow `yaml:"looking_glass" json:"looking_glass"`
	// Fields annotates every member of the message's decoded parts.
	Fields []ExampleField `yaml:"fields" json:"fields"`
}

// ExampleFlow identifies a Looking Glass flow by backend plugin and flow ID.
type ExampleFlow struct {
	Protocol string `yaml:"protocol" json:"protocol"`
	Flow     string `yaml:"flow" json:"flow"`
	// TokenMode preselects the flow's access-token protection, "bearer" or
	// "dpop", when the message only appears under one of them.
	TokenMode string `yaml:"token_mode,omitempty" json:"token_mode,omitempty"`
}

// RunURL is the Looking Glass deep link that opens the flow, in the shape
// the palette's run_url has (frontend parseFlowDeepLink reads both).
func (f ExampleFlow) RunURL() string {
	if f.Protocol == "" {
		return ""
	}
	url := "/looking-glass?protocol=" + f.Protocol + "&flow=" + f.Flow
	if f.TokenMode != "" {
		url += "&token_mode=" + f.TokenMode
	}
	return url
}

// ExampleField ties one member of the message to the specification text
// that defines it.
type ExampleField struct {
	// Path is the decoded part and the member within it, such as
	// "header.typ" or "payload.cnf.jkt".
	Path string `yaml:"path" json:"path"`
	// Reference names the specification section, such as
	// "RFC 9449 Section 4.2".
	Reference string `yaml:"reference" json:"reference"`
	URL       string `yaml:"url" json:"url"`
	// Statement is the specification's own text for the member, verbatim.
	Statement string `yaml:"statement" json:"statement"`
	// Note says what ProtocolSoup puts in the member where the specification
	// leaves that to the deployment.
	Note string `yaml:"note,omitempty" json:"note,omitempty"`
	// Requirements lists the registry requirements this member satisfies.
	Requirements []string `yaml:"requirements,omitempty" json:"requirements,omitempty"`
}

// validateExamples returns the registry issues in the examples section.
func validateExamples(registry Registry, requirementIDs map[string]struct{}) []string {
	var issues []string
	seen := make(map[string]struct{}, len(registry.Examples))
	for i, example := range registry.Examples {
		prefix := fmt.Sprintf("examples[%d]", i)
		if example.ID != "" {
			prefix = "example " + example.ID
		}
		switch {
		case !exampleIDPattern.MatchString(example.ID):
			issues = append(issues, prefix+": id must be lowercase words joined by hyphens")
		default:
			if _, exists := seen[example.ID]; exists {
				issues = append(issues, prefix+": duplicate example id")
			}
			seen[example.ID] = struct{}{}
		}
		title := strings.TrimSpace(example.Title)
		switch {
		case title == "":
			issues = append(issues, prefix+": title is required")
		case len([]rune(title)) > MaxTitleLength:
			issues = append(issues, fmt.Sprintf("%s: title exceeds %d characters", prefix, MaxTitleLength))
		case strings.HasSuffix(title, "."):
			issues = append(issues, prefix+": title must not end with a full stop")
		}
		question := strings.TrimSpace(example.Question)
		switch {
		case question == "":
			issues = append(issues, prefix+": question is required")
		case len([]rune(question)) > MaxQuestionLength:
			issues = append(issues, fmt.Sprintf("%s: question exceeds %d characters", prefix, MaxQuestionLength))
		case !strings.HasSuffix(question, "?"):
			issues = append(issues, prefix+": question must end with a question mark")
		}
		if strings.TrimSpace(example.Summary) == "" {
			issues = append(issues, prefix+": summary is required")
		}
		parts, knownFormat := exampleParts[example.Format]
		if !knownFormat {
			issues = append(issues, prefix+": format is not supported")
		}
		// A message no Looking Glass flow produces names none, and its page
		// offers no flow to run.
		if (strings.TrimSpace(example.LookingGlass.Protocol) == "") != (strings.TrimSpace(example.LookingGlass.Flow) == "") {
			issues = append(issues, prefix+": looking_glass needs both protocol and flow, or neither")
		}
		switch example.LookingGlass.TokenMode {
		case "":
		case "bearer", "dpop":
			if strings.TrimSpace(example.LookingGlass.Flow) == "" {
				issues = append(issues, prefix+": looking_glass token_mode needs a flow")
			}
		default:
			issues = append(issues, prefix+": looking_glass token_mode must be bearer or dpop")
		}
		if len(example.Fields) == 0 {
			issues = append(issues, prefix+": at least one field is required")
		}
		paths := make(map[string]struct{}, len(example.Fields))
		for fieldIndex, field := range example.Fields {
			fieldPrefix := fmt.Sprintf("%s: fields[%d]", prefix, fieldIndex)
			if field.Path != "" {
				fieldPrefix = prefix + ": field " + field.Path
			}
			part, member, _ := strings.Cut(field.Path, ".")
			if member == "" || (knownFormat && !containsString(parts, part)) {
				issues = append(issues, fieldPrefix+": path must be a part of the format and a member, joined by a dot")
			}
			if _, exists := paths[field.Path]; exists {
				issues = append(issues, fieldPrefix+": duplicate path")
			}
			paths[field.Path] = struct{}{}
			if strings.TrimSpace(field.Reference) == "" || strings.TrimSpace(field.Statement) == "" {
				issues = append(issues, fieldPrefix+": reference and statement are required")
			}
			if !strings.HasPrefix(field.URL, "https://") {
				issues = append(issues, fieldPrefix+": url must be an https URL")
			}
			for _, id := range field.Requirements {
				if _, exists := requirementIDs[id]; !exists {
					issues = append(issues, fieldPrefix+": unknown requirement "+id)
				}
			}
		}
	}
	return issues
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// ExamplePart is one decoded part of an example value.
type ExamplePart struct {
	Name string `json:"name"`
	// JSON is the part exactly as it was decoded from the value: the same
	// bytes, in the same member order.
	JSON string `json:"json"`
	// Indented is JSON with line breaks and indentation added between its
	// tokens. No token is changed or moved.
	Indented string `json:"indented"`
	// Members are the part's members in the order they appear, each nested
	// member a field annotates following its parent.
	Members []ExampleMember `json:"members"`
	// Digest is set for a Disclosure: the base64url SHA-256 digest of the
	// Disclosure as it was sent, which is the value the Issuer-signed JWT
	// carries for it in _sd (RFC 9901 Section 4.2.3).
	Digest string `json:"digest,omitempty"`
}

// ExampleMember is one member of a decoded part. Value is the member's JSON
// text as the sender wrote it, carried as a string so that no JSON parser
// between here and the page can reformat a number or reorder an object.
type ExampleMember struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

// DecodeExample splits an example value into its decoded parts. It never
// re-serialises a part, so member order and number formatting are the
// sender's.
func (e Example) DecodeExample(value string) ([]ExamplePart, error) {
	annotated := make(map[string]struct{}, len(e.Fields))
	for _, field := range e.Fields {
		annotated[field.Path] = struct{}{}
	}
	switch e.Format {
	case ExampleFormatJWT:
		return jwsParts(value, annotated)
	case ExampleFormatSDJWT:
		// RFC 9901 Section 4: an SD-JWT with no Key Binding JWT is the
		// Issuer-signed JWT and each Disclosure, every one followed by "~".
		segments := strings.Split(value, "~")
		if len(segments) < 2 || segments[len(segments)-1] != "" {
			return nil, fmt.Errorf("value is not an SD-JWT without a Key Binding JWT: it does not end with ~")
		}
		parts, err := jwsParts(segments[0], annotated)
		if err != nil {
			return nil, err
		}
		for _, disclosure := range segments[1 : len(segments)-1] {
			part, err := disclosurePart(disclosure)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
		}
		return parts, nil
	case ExampleFormatJSON:
		part, err := examplePart(exampleParts[ExampleFormatJSON][0], []byte(value), annotated)
		if err != nil {
			return nil, err
		}
		return []ExamplePart{part}, nil
	default:
		return nil, fmt.Errorf("example format %q is not supported", e.Format)
	}
}

// jwsParts decodes the JOSE Header and the payload of a compact JWS.
func jwsParts(compact string, annotated map[string]struct{}) ([]ExamplePart, error) {
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("value is not a compact JWS: %d segments", len(segments))
	}
	parts := make([]ExamplePart, 0, 2)
	for i, name := range exampleParts[ExampleFormatJWT] {
		decoded, err := base64.RawURLEncoding.DecodeString(segments[i])
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		part, err := examplePart(name, decoded, annotated)
		if err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	return parts, nil
}

// disclosureElements names the elements of a Disclosure for an object
// property, in the order RFC 9901 Section 4.2.1 gives them: "Create a JSON
// array of three elements".
var disclosureElements = []string{"salt", "name", "value"}

// disclosurePart decodes one Disclosure. Its members are the array's
// elements, each as the Issuer wrote it. A Disclosure for an array element
// has two elements (Section 4.2.2) and is not supported: no registered
// example carries one.
func disclosurePart(encoded string) (ExamplePart, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ExamplePart{}, fmt.Errorf("decode disclosure: %w", err)
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(decoded, &elements); err != nil {
		return ExamplePart{}, fmt.Errorf("decode disclosure: %w", err)
	}
	if len(elements) != len(disclosureElements) {
		return ExamplePart{}, fmt.Errorf("disclosure has %d elements, want the %d of an object property", len(elements), len(disclosureElements))
	}
	members := make([]ExampleMember, 0, len(elements))
	for i, element := range elements {
		members = append(members, ExampleMember{Path: exampleDisclosurePart + "." + disclosureElements[i], Value: string(element)})
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, decoded, "", "  "); err != nil {
		return ExamplePart{}, fmt.Errorf("decode disclosure: %w", err)
	}
	// RFC 9901 Section 4.2.3: "The digest MUST be computed over the US-ASCII
	// bytes of the base64url-encoded value that is the Disclosure."
	digest := sha256.Sum256([]byte(encoded))
	return ExamplePart{
		Name:     exampleDisclosurePart,
		JSON:     string(decoded),
		Indented: indented.String(),
		Members:  members,
		Digest:   base64.RawURLEncoding.EncodeToString(digest[:]),
	}, nil
}

// examplePart lists the members of one decoded part and indents it.
func examplePart(name string, decoded []byte, annotated map[string]struct{}) (ExamplePart, error) {
	members, err := exampleMembers(name, decoded, annotated)
	if err != nil {
		return ExamplePart{}, fmt.Errorf("decode %s: %w", name, err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, decoded, "", "  "); err != nil {
		return ExamplePart{}, fmt.Errorf("decode %s: %w", name, err)
	}
	return ExamplePart{Name: name, JSON: string(decoded), Indented: indented.String(), Members: members}, nil
}

// exampleMembers lists the members of the JSON object raw under prefix, in
// document order. A nested member is listed when a field annotates it or
// something inside it.
func exampleMembers(prefix string, raw []byte, annotated map[string]struct{}) ([]ExampleMember, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("%s is not a JSON object", prefix)
	}
	var members []ExampleMember
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("%s has a member name that is not a string", prefix)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		path := prefix + "." + name
		members = append(members, ExampleMember{Path: path, Value: string(value)})
		if !annotatesInside(annotated, path) || len(value) == 0 || value[0] != '{' {
			continue
		}
		nested, err := exampleMembers(path, []byte(value), annotated)
		if err != nil {
			return nil, err
		}
		for _, member := range nested {
			if _, ok := annotated[member.Path]; ok || annotatesInside(annotated, member.Path) {
				members = append(members, member)
			}
		}
	}
	return members, nil
}

// annotatesInside reports whether any annotated path lies inside path.
func annotatesInside(annotated map[string]struct{}, path string) bool {
	for candidate := range annotated {
		if strings.HasPrefix(candidate, path+".") {
			return true
		}
	}
	return false
}

// CheckExample reports how value and the example's fields disagree: a
// top-level member no field annotates, or a field whose member the value
// does not carry. A page built from a value that passes shows every member
// with its specification text and describes nothing that is not there.
func (e Example) CheckExample(value string) error {
	parts, err := e.DecodeExample(value)
	if err != nil {
		return err
	}
	annotated := make(map[string]struct{}, len(e.Fields))
	for _, field := range e.Fields {
		annotated[field.Path] = struct{}{}
	}
	present := map[string]struct{}{}
	var gaps []string
	for _, part := range parts {
		for _, member := range part.Members {
			present[member.Path] = struct{}{}
			topLevel := strings.Count(member.Path, ".") == 1
			if _, ok := annotated[member.Path]; !ok && topLevel {
				gaps = append(gaps, "no field annotates "+member.Path)
			}
		}
	}
	for _, field := range e.Fields {
		if _, ok := present[field.Path]; !ok {
			gaps = append(gaps, "the value has no "+field.Path)
		}
	}
	if len(gaps) > 0 {
		return fmt.Errorf("example %s: %s", e.ID, strings.Join(gaps, "; "))
	}
	return nil
}

// ExamplePath is the canonical frontend path for an example page.
func ExamplePath(id string) string {
	return "/example/" + id
}

// Example resolves an example ID case-insensitively.
func (c *Catalogue) Example(id string) (Example, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, example := range c.registry.Examples {
		if example.ID == id {
			return example, true
		}
	}
	return Example{}, false
}

// capturedExample returns the captured value for an example when the loaded
// artefact set describes the running build.
func (c *Catalogue) capturedExample(id string) (CapturedExample, bool) {
	if !c.ArtefactsValid() {
		return CapturedExample{}, false
	}
	for _, captured := range c.artefacts.Examples {
		if captured.ID == id {
			return captured, true
		}
	}
	return CapturedExample{}, false
}

// ExampleIndexable reports whether an example page may be indexed: the
// launch gate is open and the build's artefact set holds its value. The
// value is the page, so a page without one is never indexed.
func (c *Catalogue) ExampleIndexable(id string) bool {
	if !c.LaunchGateOpen() {
		return false
	}
	_, ok := c.capturedExample(id)
	return ok
}

// examplesCiting lists the examples with a field that cites requirement id.
func (c *Catalogue) examplesCiting(id string) []ExampleLink {
	links := []ExampleLink{}
	for _, example := range c.registry.Examples {
		if exampleCites(example, id) {
			links = append(links, ExampleLink{ID: example.ID, Title: example.Title, Question: example.Question})
		}
	}
	return links
}

func exampleCites(example Example, id string) bool {
	for _, field := range example.Fields {
		if containsString(field.Requirements, id) {
			return true
		}
	}
	return false
}

// ExampleLink identifies an example page.
type ExampleLink struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Question string `json:"question"`
}

// ExampleSummary describes one example in listings.
type ExampleSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Question  string `json:"question"`
	Summary   string `json:"summary"`
	Format    string `json:"format"`
	Indexable bool   `json:"indexable"`
}

// ExamplesResponse is the body of GET /api/conformance/examples.
type ExamplesResponse struct {
	Examples []ExampleSummary `json:"examples"`
}

// ExampleRequirementLink is a requirement a field satisfies, with the path
// of its page. The verdict lives on that page, beside the statement that it
// is a self-test.
type ExampleRequirementLink struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Question string `json:"question"`
	Path     string `json:"path"`
}

// ExampleFieldResponse is a field annotation with its requirements resolved.
type ExampleFieldResponse struct {
	Path         string                   `json:"path"`
	Reference    string                   `json:"reference"`
	URL          string                   `json:"url"`
	Statement    string                   `json:"statement"`
	Note         string                   `json:"note,omitempty"`
	Requirements []ExampleRequirementLink `json:"requirements"`
}

// ExampleResponse is the body of GET /api/conformance/examples/{id}. The
// definition is always present. The value, its decoded parts, the exchanges
// that carried it and how it was verified are present only when status is
// published.
type ExampleResponse struct {
	ExampleSummary
	// RunURL opens the Looking Glass flow that produces this message live.
	// It is absent for a message no flow produces.
	RunURL string                 `json:"run_url,omitempty"`
	Fields []ExampleFieldResponse `json:"fields"`

	Status       ArtefactStatus `json:"status"`
	Commit       string         `json:"commit,omitempty"`
	CapturedAt   string         `json:"captured_at,omitempty"`
	PublishAfter string         `json:"publish_after,omitempty"`

	Actor       ArtefactActor `json:"actor,omitempty"`
	Description string        `json:"description,omitempty"`
	// Value is the message exactly as the source exchange carried it.
	Value string `json:"value,omitempty"`
	// IssuedAt is when the source exchange began.
	IssuedAt     string                          `json:"issued_at,omitempty"`
	Parts        []ExamplePart                   `json:"parts,omitempty"`
	Source       *ExampleSource                  `json:"source,omitempty"`
	Verification *ExampleVerification            `json:"verification,omitempty"`
	Exchanges    []lookingglass.CapturedExchange `json:"exchanges,omitempty"`
}

func (c *Catalogue) exampleSummary(example Example) ExampleSummary {
	return ExampleSummary{
		ID:        example.ID,
		Title:     example.Title,
		Question:  example.Question,
		Summary:   example.Summary,
		Format:    example.Format,
		Indexable: c.ExampleIndexable(example.ID),
	}
}

// exampleResponse builds the response for one example at now.
func (c *Catalogue) exampleResponse(example Example, now time.Time) (ExampleResponse, error) {
	response := ExampleResponse{
		ExampleSummary: c.exampleSummary(example),
		RunURL:         example.LookingGlass.RunURL(),
		Fields:         make([]ExampleFieldResponse, 0, len(example.Fields)),
		Status:         ArtefactsNotCaptured,
	}
	for _, field := range example.Fields {
		entry := ExampleFieldResponse{
			Path:         field.Path,
			Reference:    field.Reference,
			URL:          field.URL,
			Statement:    field.Statement,
			Note:         field.Note,
			Requirements: make([]ExampleRequirementLink, 0, len(field.Requirements)),
		}
		for _, id := range field.Requirements {
			req, ok := c.Requirement(id)
			if !ok {
				continue
			}
			entry.Requirements = append(entry.Requirements, ExampleRequirementLink{
				ID:       req.ID,
				Title:    req.Title,
				Question: req.Question,
				Path:     RequirementPath(req.Specification, req.ID),
			})
		}
		response.Fields = append(response.Fields, entry)
	}

	captured, ok := c.capturedExample(example.ID)
	if !ok {
		return response, nil
	}
	set := c.artefacts
	// A value that cannot be revoked is published only once it has expired,
	// which can be later than the rest of the set.
	publishAfter := set.PublishAfter
	if captured.PublishAfter.After(publishAfter) {
		publishAfter = captured.PublishAfter
	}
	response.Commit = set.Commit
	response.CapturedAt = set.CapturedAt.UTC().Format(time.RFC3339)
	response.PublishAfter = publishAfter.UTC().Format(time.RFC3339)
	if now.Before(publishAfter) {
		response.Status = ArtefactsPending
		return response, nil
	}
	parts, err := example.DecodeExample(captured.Value)
	if err != nil {
		return response, err
	}
	if captured.Source.Exchange < 0 || captured.Source.Exchange >= len(captured.Exchanges) {
		return response, fmt.Errorf("example %s: source exchange %d is not one of its %d exchanges",
			example.ID, captured.Source.Exchange, len(captured.Exchanges))
	}
	issued := captured.Exchanges[captured.Source.Exchange].Timing.StartUnixMicro
	source, verification := captured.Source, captured.Verification
	response.Status = ArtefactsPublished
	response.Actor = captured.Actor
	response.Description = captured.Description
	response.Value = captured.Value
	response.IssuedAt = time.UnixMicro(issued).UTC().Format(time.RFC3339)
	response.Parts = parts
	response.Source = &source
	response.Verification = &verification
	response.Exchanges = captured.Exchanges
	return response, nil
}

func (c *Catalogue) handleExamples(w http.ResponseWriter, _ *http.Request) {
	response := ExamplesResponse{Examples: make([]ExampleSummary, 0, len(c.registry.Examples))}
	for _, example := range c.registry.Examples {
		response.Examples = append(response.Examples, c.exampleSummary(example))
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Catalogue) handleExample(w http.ResponseWriter, r *http.Request) {
	example, ok := c.Example(chi.URLParam(r, "id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "example not found"})
		return
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	response, err := c.exampleResponse(example, now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response)
}
