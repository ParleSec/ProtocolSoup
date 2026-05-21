package palette

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlainTextPreviewStripsMarkdown(t *testing.T) {
	a := Artefact{Body: "PKCE (Proof Key for Code Exchange, **RFC 7636**) protects the\nauthorization code grant against `code_verifier` capture.\n\nSecond paragraph not included."}
	p := a.PlainTextPreview(120)
	if strings.Contains(p, "**") || strings.Contains(p, "`") {
		t.Errorf("expected markdown stripped, got %q", p)
	}
	if strings.Contains(p, "Second paragraph") {
		t.Errorf("preview should stop at the first blank line, got %q", p)
	}
	if !strings.Contains(p, "RFC 7636") {
		t.Errorf("expected RFC 7636 text retained, got %q", p)
	}
}

func TestPlainTextPreviewTruncatesOnWordBoundary(t *testing.T) {
	a := Artefact{Body: "The authorization server validates the code_verifier against the stored code_challenge before issuing tokens."}
	p := a.PlainTextPreview(40)
	if len(p) > 45 {
		t.Errorf("expected preview <= ~40 chars, got %d: %q", len(p), p)
	}
	if !strings.HasSuffix(p, "...") {
		t.Errorf("expected ellipsis suffix on truncation, got %q", p)
	}
	if strings.Contains(p, " v") && !strings.HasSuffix(p, "...") {
		// Ensure we did not cut a word in half.
		t.Errorf("preview cut mid-word: %q", p)
	}
}

func TestBuildSnippetReturnsEmptyWhenNoTokenMatches(t *testing.T) {
	body := "OAuth 2.0 is the authorization framework defined by RFC 6749."
	if got := buildSnippet(body, []string{"saml", "xml"}); got != "" {
		t.Errorf("expected empty snippet, got %q", got)
	}
}

func TestBuildSnippetHighlightsMatchingTokens(t *testing.T) {
	body := "OAuth 2.0 is the authorization framework defined by RFC 6749. It lets a client application obtain limited access to a resource server."
	got := buildSnippet(body, []string{"authorization"})
	if got == "" {
		t.Fatal("expected snippet for 'authorization', got empty")
	}
	if !strings.Contains(got, "<mark>authorization</mark>") {
		t.Errorf("expected <mark> wrapping around 'authorization', got %q", got)
	}
}

func TestBuildSnippetIncludesTrailingContextSentence(t *testing.T) {
	body := "PKCE protects against code interception. The client generates a high-entropy verifier. The verifier is presented at the token endpoint."
	got := buildSnippet(body, []string{"pkce"})
	if got == "" {
		t.Fatal("expected snippet, got empty")
	}
	// Should include the matched sentence + one trailing context sentence.
	if !strings.Contains(got, "client generates") {
		t.Errorf("expected trailing context, got %q", got)
	}
}

func TestBuildSnippetMergesOverlappingMatches(t *testing.T) {
	// Two tokens that match the same word should not double-wrap.
	body := "Authorization is hard."
	got := buildSnippet(body, []string{"authorization", "authoriz"})
	// At most one <mark>...</mark> wrapping per occurrence.
	if strings.Count(got, "<mark>") != strings.Count(got, "</mark>") {
		t.Errorf("unbalanced <mark> tags in %q", got)
	}
	if strings.Contains(got, "<mark><mark>") {
		t.Errorf("nested <mark> tags in %q", got)
	}
}

func TestBuildSnippetCapsLength(t *testing.T) {
	// Construct a body longer than the maxLen so we can verify the cap.
	long := strings.Repeat("authorization is the cornerstone of modern api access patterns. ", 20)
	got := buildSnippet(long, []string{"authorization"})
	if len(got) == 0 {
		t.Fatal("expected snippet, got empty")
	}
	// 360 cap + <mark> tags around each occurrence; ceiling well under 1 KB.
	if len(got) > 1024 {
		t.Errorf("snippet too long: %d chars", len(got))
	}
}

// TestSnippetTokensIncludeAliasMatches verifies that when a query is
// resolved entirely through an alias (no free tokens left), the snippet
// builder still receives the original matched token so highlights work.
// Regression: live testing showed `q="pkce"` resolved to the pkce artefact
// alias, leaving FreeTokens empty and producing an un-highlighted snippet.
func TestSnippetTokensIncludeAliasMatches(t *testing.T) {
	parsed := ParsedQuery{
		FreeTokens: nil,
		Resolved: []ResolvedAlias{
			{MatchedToken: "pkce", Artefact: "pkce"},
		},
	}
	got := snippetTokens(parsed)
	if len(got) != 1 || got[0] != "pkce" {
		t.Errorf("expected ['pkce'], got %v", got)
	}
}

func TestSnippetTokensDeduplicatesAcrossSources(t *testing.T) {
	parsed := ParsedQuery{
		FreeTokens:    []string{"pkce", "verifier"},
		Resolved:      []ResolvedAlias{{MatchedToken: "pkce"}},
		PhraseMatches: []string{"verifier"},
	}
	got := snippetTokens(parsed)
	if len(got) != 2 {
		t.Errorf("expected dedup to 2 tokens, got %v", got)
	}
}

func TestIndexerStoresBodyAndPreviewOnResult(t *testing.T) {
	svc := queryServiceForTest(t, seedContent(t))
	defer svc.Close()

	// "authorization" hits the body of the seed PKCE concept
	// ("Binds an authorization request to a per-request code_verifier").
	resp, err := svc.Query(t.Context(), Request{Q: "authorization"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatal("expected results")
	}

	var found *Result
	for i := range resp.Results {
		if resp.Results[i].ID == "pkce" {
			found = &resp.Results[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected pkce result in seed content")
	}
	if found.Body == "" {
		t.Error("Result.Body empty; expected full markdown body")
	}
	if found.BodyPreview == "" {
		t.Error("Result.BodyPreview empty; expected first-paragraph preview")
	}
	if found.Snippet == "" {
		t.Error("Result.Snippet empty for query that matches body")
	} else if !strings.Contains(found.Snippet, "<mark>") {
		t.Errorf("expected highlighted snippet, got %q", found.Snippet)
	}
}

// TestNormativeAnchorJSONFieldNames locks the wire shape of NormativeAnchor.
// The frontend reads `rfc`/`sections` (lowercase); without explicit JSON
// tags Go would emit `RFC`/`Sections` and the React row crashes on
// `anchor.sections.length`. This test prevents that regression.
func TestNormativeAnchorJSONFieldNames(t *testing.T) {
	a := NormativeAnchor{RFC: "RFC 7636", Sections: []string{"4.1.3"}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(raw)
	want := `{"rfc":"RFC 7636","sections":["4.1.3"]}`
	if got != want {
		t.Errorf("NormativeAnchor JSON shape drift:\n got %s\nwant %s", got, want)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := decoded["rfc"]; !ok {
		t.Error("decoded JSON missing lowercase `rfc`")
	}
	if _, ok := decoded["sections"]; !ok {
		t.Error("decoded JSON missing lowercase `sections`")
	}
}
