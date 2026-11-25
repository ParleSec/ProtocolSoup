package conformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// exampleJWS is a compact JWS over the exact header and payload bytes
// given. The signature segment is not a signature: these tests are about
// decoding, which never looks at it.
func exampleJWS(header, payload string) string {
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(header)) + "." + encode([]byte(payload)) + "." + encode([]byte("signature"))
}

const (
	exampleHeaderJSON  = `{"typ":"dpop+jwt","alg":"ES256"}`
	examplePayloadJSON = `{"zeta":1.0,"cnf":{"other":2,"jkt":"thumb"},"iat":1795319017}`
)

func exampleFixture() Example {
	field := func(path string, requirements ...string) ExampleField {
		return ExampleField{
			Path: path, Reference: "Alpha Section 5.10", URL: "https://example.test/alpha#section-5.10",
			Statement: "The member MUST be present.", Requirements: requirements,
		}
	}
	return Example{
		ID:           "sample-proof",
		Title:        "Sample proof",
		Question:     "What does a sample proof look like?",
		Summary:      "A sample proof is a JWT a client signs.",
		Format:       ExampleFormatJWT,
		LookingGlass: ExampleFlow{Protocol: "oauth2", Flow: "client_credentials", TokenMode: "dpop"},
		Fields: []ExampleField{
			field("header.typ", "AL-010"),
			field("header.alg"),
			field("payload.zeta"),
			field("payload.cnf"),
			field("payload.cnf.jkt", "AL-010", "AL-002"),
			field("payload.iat"),
		},
	}
}

func TestRegistryValidationExampleRules(t *testing.T) {
	valid := func(t *testing.T) (Registry, string) {
		registry, root := validRegistryFixture(t)
		example := exampleFixture()
		for i := range example.Fields {
			if len(example.Fields[i].Requirements) > 0 {
				example.Fields[i].Requirements = []string{"EX-001"}
			}
		}
		registry.Examples = []Example{example}
		return registry, root
	}

	registry, root := valid(t)
	registry.Examples[0].LookingGlass = ExampleFlow{}
	if err := Validate(registry, root); err != nil {
		t.Fatalf("an example no Looking Glass flow produces must validate: %v", err)
	}

	registry, root = valid(t)
	if err := Validate(registry, root); err != nil {
		t.Fatalf("a well-formed example must validate: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(example *Example)
		want   string
	}{
		{"id with capitals", func(e *Example) { e.ID = "Sample_Proof" }, "id must be lowercase words joined by hyphens"},
		{"no title", func(e *Example) { e.Title = "" }, "title is required"},
		{"question without question mark", func(e *Example) { e.Question = "A sample proof" }, "question must end with a question mark"},
		{"no summary", func(e *Example) { e.Summary = " " }, "summary is required"},
		{"unsupported format", func(e *Example) { e.Format = "xml" }, "format is not supported"},
		{"a protocol without a flow", func(e *Example) { e.LookingGlass.Flow = "" }, "looking_glass needs both protocol and flow, or neither"},
		{"a token mode without a flow", func(e *Example) { e.LookingGlass = ExampleFlow{TokenMode: "dpop"} }, "looking_glass token_mode needs a flow"},
		{"unknown token mode", func(e *Example) { e.LookingGlass.TokenMode = "mtls" }, "token_mode must be bearer or dpop"},
		{"no fields", func(e *Example) { e.Fields = nil }, "at least one field is required"},
		{"path outside the format's parts", func(e *Example) { e.Fields[0].Path = "body.typ" }, "path must be a part of the format and a member"},
		{"path without a member", func(e *Example) { e.Fields[0].Path = "header" }, "path must be a part of the format and a member"},
		{"duplicate path", func(e *Example) { e.Fields[1].Path = e.Fields[0].Path }, "duplicate path"},
		{"no statement", func(e *Example) { e.Fields[0].Statement = "" }, "reference and statement are required"},
		{"url without https", func(e *Example) { e.Fields[0].URL = "http://example.test" }, "url must be an https URL"},
		{"unknown requirement", func(e *Example) { e.Fields[0].Requirements = []string{"ZZ-404"} }, "unknown requirement ZZ-404"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, root := valid(t)
			tc.mutate(&registry.Examples[0])
			err := Validate(registry, root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an issue containing %q", err, tc.want)
			}
		})
	}

	t.Run("duplicate id", func(t *testing.T) {
		registry, root := valid(t)
		registry.Examples = append(registry.Examples, registry.Examples[0])
		if err := Validate(registry, root); err == nil || !strings.Contains(err.Error(), "duplicate example id") {
			t.Fatalf("Validate = %v", err)
		}
	})
}

func TestDecodeExampleKeepsTheSendersBytesAndMemberOrder(t *testing.T) {
	example := exampleFixture()
	parts, err := example.DecodeExample(exampleJWS(exampleHeaderJSON, examplePayloadJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || parts[0].Name != "header" || parts[1].Name != "payload" {
		t.Fatalf("parts = %+v", parts)
	}
	if parts[0].JSON != exampleHeaderJSON || parts[1].JSON != examplePayloadJSON {
		t.Fatalf("decoded parts must be the sender's bytes: %q, %q", parts[0].JSON, parts[1].JSON)
	}
	// Indenting adds only whitespace between tokens.
	if stripped := strings.NewReplacer(" ", "", "\n", "").Replace(parts[1].Indented); stripped != examplePayloadJSON {
		t.Fatalf("indented payload changed a token: %q", parts[1].Indented)
	}
	if !strings.HasPrefix(parts[1].Indented, "{\n  \"zeta\": 1.0,\n") {
		t.Fatalf("indented payload = %q", parts[1].Indented)
	}

	var got []string
	for _, member := range parts[1].Members {
		got = append(got, member.Path+"="+member.Value)
	}
	// zeta precedes cnf and iat because the sender wrote it first, 1.0 is
	// not rewritten as 1, and cnf.jkt is listed because a field annotates
	// it while cnf.other, which nothing annotates, is not.
	want := []string{
		`payload.zeta=1.0`,
		`payload.cnf={"other":2,"jkt":"thumb"}`,
		`payload.cnf.jkt="thumb"`,
		`payload.iat=1795319017`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("members =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, value := range []string{"only.two", "a.b.c.d", "!!!." + "e30" + ".sig", exampleJWS(`["not","an","object"]`, `{}`)} {
		if _, err := example.DecodeExample(value); err == nil {
			t.Fatalf("DecodeExample(%q) must fail", value)
		}
	}
}

func TestCheckExampleFindsUnannotatedAndAbsentMembers(t *testing.T) {
	example := exampleFixture()
	if err := example.CheckExample(exampleJWS(exampleHeaderJSON, examplePayloadJSON)); err != nil {
		t.Fatalf("every member is annotated and every field is present: %v", err)
	}

	extra := exampleJWS(`{"typ":"dpop+jwt","alg":"ES256","kid":"k1"}`, examplePayloadJSON)
	if err := example.CheckExample(extra); err == nil || !strings.Contains(err.Error(), "no field annotates header.kid") {
		t.Fatalf("an unannotated member must be reported: %v", err)
	}

	missing := exampleJWS(exampleHeaderJSON, `{"zeta":1.0,"cnf":{"other":2},"iat":1}`)
	if err := example.CheckExample(missing); err == nil || !strings.Contains(err.Error(), "the value has no payload.cnf.jkt") {
		t.Fatalf("a field whose member is absent must be reported: %v", err)
	}
}

func TestDocumentExampleIsOnePartInTheSendersBytes(t *testing.T) {
	// A trailing newline and odd spacing are the sender's and stay.
	const body = `{"issuer":"https://as.example", "scopes_supported":["openid","profile"],"extension":{"a":1}}` + "\n"
	field := func(path string) ExampleField {
		return ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	example := Example{
		ID:     "sample-document",
		Format: ExampleFormatJSON,
		Fields: []ExampleField{field("document.issuer"), field("document.scopes_supported"), field("document.extension")},
	}
	parts, err := example.DecodeExample(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].Name != "document" || parts[0].JSON != body {
		t.Fatalf("parts = %+v", parts)
	}
	want := []ExampleMember{
		{Path: "document.issuer", Value: `"https://as.example"`},
		{Path: "document.scopes_supported", Value: `["openid","profile"]`},
		{Path: "document.extension", Value: `{"a":1}`},
	}
	if !reflect.DeepEqual(parts[0].Members, want) {
		t.Fatalf("members = %+v, want %+v", parts[0].Members, want)
	}
	if err := example.CheckExample(body); err != nil {
		t.Fatal(err)
	}
	example.Fields = example.Fields[:2]
	if err := example.CheckExample(body); err == nil || !strings.Contains(err.Error(), "no field annotates document.extension") {
		t.Fatalf("err = %v, want the unannotated member named", err)
	}
}

func TestExampleWithoutAFlowOffersNoneToRun(t *testing.T) {
	registry := catalogueRegistry()
	example := exampleFixture()
	example.LookingGlass = ExampleFlow{}
	registry.Examples = []Example{example}
	c := NewCatalogue(registry, nil, testBuildCommit, mapExplainers{"al-010": "x"})
	_, body := serve(t, c, "/examples/sample-proof")
	if _, present := body["run_url"]; present {
		t.Fatalf("run_url = %v, want it absent", body["run_url"])
	}
}

func exampleCatalogue(report bool, captured *ArtefactSet) *Catalogue {
	registry := catalogueRegistry()
	registry.Examples = []Example{exampleFixture()}
	var r *Report
	if report {
		r = catalogueReport(registry, nil)
	}
	c := NewCatalogue(registry, r, testBuildCommit, mapExplainers{"al-010": "x"})
	if captured != nil {
		c.SetArtefacts(captured)
	}
	return c
}

func capturedExampleFixture(commit string, publishAfter time.Time) *ArtefactSet {
	jwksExchange := 1
	value := exampleJWS(exampleHeaderJSON, examplePayloadJSON)
	issued := time.Date(2026, 11, 22, 3, 43, 37, 0, time.UTC)
	return &ArtefactSet{
		SchemaVersion: ArtefactSchemaVersion,
		Commit:        commit,
		CapturedAt:    publishAfter.Add(-5 * time.Minute),
		PublishAfter:  publishAfter,
		Examples: []CapturedExample{{
			ID:          "sample-proof",
			Actor:       ActorConformanceClient,
			Description: "The conformance client presents a token.",
			Value:       value,
			Source:      ExampleSource{Exchange: 0, Message: ExampleInRequest, Location: "the DPoP header"},
			Verification: ExampleVerification{
				Method: VerifiedByJWKS, Algorithm: "RS256", KeyID: "k1", JWKSExchange: &jwksExchange,
			},
			Exchanges: []lookingglass.CapturedExchange{
				{
					ID:       "resource",
					Request:  lookingglass.CapturedMessage{Method: http.MethodGet, URL: "https://protocolsoup.test/oauth2/resource"},
					Response: lookingglass.CapturedMessage{Status: http.StatusOK},
					Timing:   lookingglass.ExchangeTiming{StartUnixMicro: issued.UnixMicro()},
				},
				{
					ID:       "jwks",
					Request:  lookingglass.CapturedMessage{Method: http.MethodGet, URL: "https://protocolsoup.test/jwks.json"},
					Response: lookingglass.CapturedMessage{Status: http.StatusOK},
				},
			},
		}},
	}
}

func TestExampleRoute(t *testing.T) {
	publishAfter := time.Date(2026, 11, 22, 4, 0, 0, 0, time.UTC)

	t.Run("definition without a capture", func(t *testing.T) {
		c := exampleCatalogue(true, nil)
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsNotCaptured) || body["value"] != nil || body["indexable"] != false {
			t.Fatalf("body = %+v", body)
		}
		if body["question"] != "What does a sample proof look like?" ||
			body["run_url"] != "/looking-glass?protocol=oauth2&flow=client_credentials&token_mode=dpop" {
			t.Fatalf("body = %+v", body)
		}
		fields := body["fields"].([]any)
		if len(fields) != 6 {
			t.Fatalf("fields = %d, want 6", len(fields))
		}
		first := fields[0].(map[string]any)
		link := first["requirements"].([]any)[0].(map[string]any)
		if link["id"] != "AL-010" || link["path"] != "/spec/alpha/al-010" || link["question"] != "What about ten?" {
			t.Fatalf("requirement link = %+v", link)
		}
		if _, present := link["verdict"]; present {
			t.Fatalf("a verdict belongs on the requirement page, beside the self-test statement: %+v", link)
		}
		if got := fields[1].(map[string]any)["requirements"].([]any); len(got) != 0 {
			t.Fatalf("a field without requirements must list none: %+v", got)
		}
	})

	t.Run("captured from a different build", func(t *testing.T) {
		c := exampleCatalogue(true, capturedExampleFixture("other", publishAfter))
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsNotCaptured) || body["commit"] != nil {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("pending until tokens expire", func(t *testing.T) {
		c := exampleCatalogue(true, capturedExampleFixture(testBuildCommit, publishAfter))
		c.now = func() time.Time { return publishAfter.Add(-time.Second) }
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsPending) || body["publish_after"] != "2026-11-22T04:00:00Z" {
			t.Fatalf("body = %+v", body)
		}
		if body["value"] != nil || body["exchanges"] != nil || body["parts"] != nil {
			t.Fatal("the value and its exchanges must be withheld before publish_after")
		}
		if body["indexable"] != true {
			t.Fatal("a captured example stays indexable while it waits to publish")
		}
	})

	t.Run("a value that cannot be revoked waits for its own expiry", func(t *testing.T) {
		expires := publishAfter.Add(40 * time.Minute)
		set := capturedExampleFixture(testBuildCommit, publishAfter)
		set.Examples[0].PublishAfter = expires
		c := exampleCatalogue(true, set)

		c.now = func() time.Time { return expires.Add(-time.Second) }
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsPending) || body["publish_after"] != "2026-11-22T04:40:00Z" || body["value"] != nil {
			t.Fatalf("the set's publish time passed but the value has not expired: %+v", body)
		}

		c.now = func() time.Time { return expires }
		_, body = serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsPublished) || body["value"] == nil {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("an expiry before the set's publish time does not bring it forward", func(t *testing.T) {
		set := capturedExampleFixture(testBuildCommit, publishAfter)
		set.Examples[0].PublishAfter = publishAfter.Add(-time.Hour)
		c := exampleCatalogue(true, set)
		c.now = func() time.Time { return publishAfter.Add(-time.Second) }
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsPending) || body["publish_after"] != "2026-11-22T04:00:00Z" {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("published in full", func(t *testing.T) {
		c := exampleCatalogue(true, capturedExampleFixture(testBuildCommit, publishAfter))
		c.now = func() time.Time { return publishAfter }
		_, body := serve(t, c, "/examples/sample-proof")
		if body["status"] != string(ArtefactsPublished) || body["commit"] != testBuildCommit {
			t.Fatalf("body = %+v", body)
		}
		if body["value"] != exampleJWS(exampleHeaderJSON, examplePayloadJSON) {
			t.Fatalf("value = %v", body["value"])
		}
		if body["issued_at"] != "2026-11-22T03:43:37Z" {
			t.Fatalf("issued_at = %v, want the source exchange's start", body["issued_at"])
		}
		parts := body["parts"].([]any)
		if parts[1].(map[string]any)["json"] != examplePayloadJSON {
			t.Fatalf("payload = %v", parts[1])
		}
		source := body["source"].(map[string]any)
		if source["message"] != ExampleInRequest || source["location"] != "the DPoP header" {
			t.Fatalf("source = %+v", source)
		}
		verification := body["verification"].(map[string]any)
		if verification["method"] != VerifiedByJWKS || verification["key_id"] != "k1" || verification["jwks_exchange"] != float64(1) {
			t.Fatalf("verification = %+v", verification)
		}
		if len(body["exchanges"].([]any)) != 2 || body["actor"] != string(ActorConformanceClient) {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("a source outside the exchanges is an error, not a guess", func(t *testing.T) {
		set := capturedExampleFixture(testBuildCommit, publishAfter)
		set.Examples[0].Source.Exchange = 5
		c := exampleCatalogue(true, set)
		c.now = func() time.Time { return publishAfter }
		recorder, _ := serve(t, c, "/examples/sample-proof")
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", recorder.Code)
		}
	})

	t.Run("unknown example", func(t *testing.T) {
		recorder, _ := serve(t, exampleCatalogue(true, nil), "/examples/nothing")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d", recorder.Code)
		}
	})

	t.Run("listing", func(t *testing.T) {
		c := exampleCatalogue(true, capturedExampleFixture(testBuildCommit, publishAfter))
		_, body := serve(t, c, "/examples")
		examples := body["examples"].([]any)
		if len(examples) != 1 {
			t.Fatalf("examples = %+v", examples)
		}
		entry := examples[0].(map[string]any)
		if entry["id"] != "sample-proof" || entry["indexable"] != true || entry["summary"] != "A sample proof is a JWT a client signs." {
			t.Fatalf("entry = %+v", entry)
		}
	})
}

func TestExamplesInSitemapAndOnRequirements(t *testing.T) {
	publishAfter := time.Date(2026, 11, 22, 4, 0, 0, 0, time.UTC)

	sitemap := func(c *Catalogue) []SitemapEntry {
		recorder := httptest.NewRecorder()
		c.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sitemap", nil))
		var entries []SitemapEntry
		if err := json.Unmarshal(recorder.Body.Bytes(), &entries); err != nil {
			t.Fatal(err)
		}
		return entries
	}

	captured := sitemap(exampleCatalogue(true, capturedExampleFixture(testBuildCommit, publishAfter)))
	last := captured[len(captured)-1]
	if last.Path != "/example/sample-proof" || last.LastMod != "2026-11-22T03:55:00Z" {
		t.Fatalf("last sitemap entry = %+v, want the example at its capture time", last)
	}
	for _, entry := range sitemap(exampleCatalogue(true, nil)) {
		if strings.HasPrefix(entry.Path, "/example/") {
			t.Fatalf("an example without a captured value must not be listed: %+v", entry)
		}
	}

	c := exampleCatalogue(true, nil)
	_, body := serve(t, c, "/requirements/AL-010")
	links := body["examples"].([]any)
	if len(links) != 1 || links[0].(map[string]any)["id"] != "sample-proof" {
		t.Fatalf("AL-010 examples = %+v", links)
	}
	_, body = serve(t, c, "/requirements/AL-001")
	if links, ok := body["examples"].([]any); !ok || len(links) != 0 {
		t.Fatalf("AL-001 examples = %+v, want an empty list", body["examples"])
	}
}
