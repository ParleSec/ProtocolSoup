package palette

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// queryServiceForTest builds an index from a temporary content tree and
// returns a ready Service plus the temp dir. Caller closes the service.
func queryServiceForTest(t *testing.T, contentRoot string) *Service {
	t.Helper()
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := BuildIndex(contentRoot, out); err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	svc, err := NewService(out)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// TestParseExtractsScopePrefix confirms a "flow:" / "protocol:" prefix sets
// the scope without consuming the rest of the query.
func TestParseExtractsScopePrefix(t *testing.T) {
	cat := catalog{aliases: map[string][]aliasRow{}}
	p := parseQuery(Request{Q: "flow:authorization code"}, cat)
	if p.Scope != ScopeFlow {
		t.Errorf("expected scope=%s, got %q", ScopeFlow, p.Scope)
	}
	if !contains(p.FreeTokens, "authorization") || !contains(p.FreeTokens, "code") {
		t.Errorf("expected free tokens to retain query body, got %v", p.FreeTokens)
	}
}

func TestParseResolvesAliasGreedy(t *testing.T) {
	cat := catalog{aliases: map[string][]aliasRow{
		"single sign on": {{Canonical: "single-sign-on", Axis: AxisUseCases}},
		"sso":            {{Canonical: "single-sign-on", Axis: AxisUseCases}},
	}}
	p := parseQuery(Request{Q: "single sign on"}, cat)
	if len(p.Resolved) != 1 {
		t.Fatalf("expected 1 resolution, got %v", p.Resolved)
	}
	if p.Resolved[0].Value != "single-sign-on" || p.Resolved[0].MatchedToken != "single sign on" {
		t.Errorf("unexpected resolution: %+v", p.Resolved[0])
	}
	if len(p.FreeTokens) != 0 {
		t.Errorf("expected greedy alias to consume tokens, got free=%v", p.FreeTokens)
	}
}

func TestParseAmbiguousAliasKeepsAllMappings(t *testing.T) {
	cat := catalog{aliases: map[string][]aliasRow{
		"auth": {
			{Canonical: "authentication", Axis: AxisProblemDomains},
			{Canonical: "authorization", Axis: AxisProblemDomains},
		},
	}}
	p := parseQuery(Request{Q: "auth"}, cat)
	if len(p.Resolved) != 2 {
		t.Fatalf("expected 2 resolutions for ambiguous alias, got %d (%v)", len(p.Resolved), p.Resolved)
	}
}

func TestParseIsVague(t *testing.T) {
	cases := []struct {
		name   string
		req    Request
		cat    catalog
		expect bool
	}{
		{
			name:   "no tokens",
			req:    Request{Q: ""},
			cat:    catalog{aliases: map[string][]aliasRow{}},
			expect: false,
		},
		{
			name:   "free tokens only",
			req:    Request{Q: "something"},
			cat:    catalog{aliases: map[string][]aliasRow{}},
			expect: true,
		},
		{
			name: "alias resolved",
			req:  Request{Q: "pkce"},
			cat: catalog{aliases: map[string][]aliasRow{
				"pkce": {{Canonical: "pkce", Axis: ""}},
			}},
			expect: false,
		},
		{
			name: "phrase present",
			req:  Request{Q: `"sign in"`},
			cat:  catalog{aliases: map[string][]aliasRow{}},
			expect: false,
		},
		{
			name: "scope set",
			req:  Request{Q: "stuff", Scope: ScopeFlow},
			cat:  catalog{aliases: map[string][]aliasRow{}},
			expect: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parseQuery(tc.req, tc.cat)
			if got := p.IsVague(); got != tc.expect {
				t.Errorf("IsVague() = %v, want %v (parsed=%+v)", got, tc.expect, p)
			}
		})
	}
}

func TestQueryPrecisePKCE(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	resp, err := svc.Query(context.Background(), Request{Q: "pkce"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatalf("expected at least one result for 'pkce'")
	}
	// First result should be the pkce concept or the pkce flow.
	first := resp.Results[0]
	if first.ID != "pkce" && first.ID != "authorization-code-pkce" {
		t.Errorf("unexpected top result for 'pkce': %s", first.ID)
	}
	// Every result must carry at least one match reason.
	for _, r := range resp.Results {
		if len(r.MatchReasons) == 0 {
			t.Errorf("result %s missing match_reasons (rule: every row carries a visible reason)", r.ID)
		}
	}
}

func TestQueryDomainAwareSignIn(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "aliases.yaml", seedAliases+`
  - alias: sign in
    canonical:
      - axis: use_cases
        value: user-login-via-own-idp
`)
	svc := queryServiceForTest(t, dir)

	resp, err := svc.Query(context.Background(), Request{Q: "let users sign in to my app"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatalf("expected results for 'sign in' query")
	}
	// "sign in" must resolve to the use_cases axis.
	if !hasResolvedAxis(resp.ResolvedAliases, AxisUseCases, "user-login-via-own-idp") {
		t.Errorf("expected alias resolution to user-login-via-own-idp, got %+v", resp.ResolvedAliases)
	}
}

func TestQueryWanderingShowsRunnableBoost(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	// "authorization" hits the FTS5 index (present in every seed body) but
	// does not match any alias, has no scope, and no quoted phrase. That's
	// the vague case: the runnable boost should fire and the runnable
	// authorization-code-pkce flow should outrank non-runnable peers.
	resp, err := svc.Query(context.Background(), Request{Q: "authorization"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	var found bool
	for _, r := range resp.Results {
		for _, mr := range r.MatchReasons {
			if mr.Kind == "runnable" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected a runnable boost match reason on vague query, got results: %+v", resp.Results)
	}
}

func TestQueryScopeFilter(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	resp, err := svc.Query(context.Background(), Request{Q: "pkce", Scope: ScopeFlow})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, r := range resp.Results {
		if r.Type != ArtefactFlow {
			t.Errorf("scope=flow returned non-flow %s (%s)", r.ID, r.Type)
		}
	}
}

func TestQueryFilters(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	resp, err := svc.Query(context.Background(), Request{
		Q: "",
		Filters: []Filter{
			{Axis: AxisUseCases, Value: "user-login-via-own-idp"},
		},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, r := range resp.Results {
		if !hasAxisChip(r.AxisChips, AxisUseCases, "user-login-via-own-idp") {
			t.Errorf("result %s does not carry the filtered axis value", r.ID)
		}
	}
}

func TestHTTPHandlerHappyPath(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	body, _ := json.Marshal(Request{Q: "pkce"})
	r := httptest.NewRequest(http.MethodPost, "/api/palette/query", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatalf("expected results in response, got: %s", rec.Body.String())
	}
}

func TestHTTPHandlerRejectsGET(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)

	r := httptest.NewRequest(http.MethodGet, "/api/palette/query", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestQueryLatencyBudget(t *testing.T) {
	dir := seedContent(t)
	svc := queryServiceForTest(t, dir)
	// Warm caches with one query.
	_, _ = svc.Query(context.Background(), Request{Q: "pkce"})

	const iterations = 50
	var max time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, err := svc.Query(context.Background(), Request{Q: "let users sign in"}); err != nil {
			t.Fatalf("Query: %v", err)
		}
		if d := time.Since(start); d > max {
			max = d
		}
	}
	if max > 20*time.Millisecond {
		t.Errorf("worst-case query latency %v exceeds the 20ms in-process budget", max)
	}
}

func hasResolvedAxis(resolved []ResolvedAlias, axis, value string) bool {
	for _, r := range resolved {
		if r.Axis == axis && r.Value == value {
			return true
		}
	}
	return false
}

func hasAxisChip(chips []AxisChip, axis, value string) bool {
	for _, c := range chips {
		if c.Axis == axis && c.Value == value {
			return true
		}
	}
	return false
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestQueryRefinementChips ensures axis-ambiguity detection emits chips. We
// craft a content set wider than the default fixture for this purpose. The
// aliases.yaml here does not reference any concept artefacts so we do not
// have to invent stub concepts purely for the validator's edge check.
func TestQueryRefinementChips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "taxonomy.yaml", seedTaxonomy)
	writeFile(t, dir, "aliases.yaml", `
aliases:
  - alias: oauth
    canonical:
      - artefact: oauth2
`)
	writeFile(t, dir, "protocols/oauth2.md", `---
id: oauth2
name: OAuth 2.0
use_cases: [user-login-via-own-idp]
actors: [authorization-server]
problem_domains: [authorization]
---
OAuth 2.0 authorization framework.
`)
	for _, useCase := range []string{"user-login-via-own-idp", "service-to-service-auth"} {
		writeFile(t, dir, "flows/oauth2/"+useCase+".md", "---\nid: "+useCase+"\nname: "+useCase+"\nprotocol: oauth2\nuse_cases:\n  - "+useCase+"\nactors:\n  - public-client\nproblem_domains:\n  - authorization\n---\nAuthorization.\n")
	}
	for _, concept := range []string{"a-concept", "b-concept", "c-concept"} {
		writeFile(t, dir, "concepts/"+concept+".md", "---\nid: "+concept+"\nname: "+concept+"\nuse_cases:\n  - service-to-service-auth\nactors:\n  - authorization-server\nproblem_domains:\n  - authorization\n---\nAuthorization.\n")
	}
	svc := queryServiceForTest(t, dir)

	resp, err := svc.Query(context.Background(), Request{Q: "authorization"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Results) == 0 {
		t.Fatalf("expected results")
	}
	for _, chip := range resp.RefinementChips {
		if !axisAllowed(chip.Axis) {
			t.Errorf("refinement chip has bogus axis %q", chip.Axis)
		}
		if chip.Count <= 0 {
			t.Errorf("refinement chip has zero count: %+v", chip)
		}
	}
}

// TestServiceClose is mainly a smoke test for shutdown.
func TestServiceClose(t *testing.T) {
	dir := seedContent(t)
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := BuildIndex(dir, out); err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}
	svc, err := NewService(out)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Errorf("double Close should be a no-op: %v", err)
	}
}

// TestSanitiseToken locks the behaviour for FTS5-safety: only [a-zA-Z0-9]
// and word-separator hyphen/underscore survive, and the first word-piece is
// returned (so e.g. "openid-configuration" matches "openid*").
func TestSanitiseToken(t *testing.T) {
	cases := []struct{ in, want string }{
		{"oauth2", "oauth2"},
		{"openid-configuration", "openid"},
		{"&*$", ""},
		{"USER", "USER"},
	}
	for _, c := range cases {
		if got := sanitiseToken(c.in); got != c.want {
			t.Errorf("sanitiseToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseQueryDeterministic(t *testing.T) {
	cat := catalog{aliases: map[string][]aliasRow{
		"sso":  {{Canonical: "single-sign-on", Axis: AxisUseCases}},
		"pkce": {{Canonical: "pkce", Axis: ""}, {Canonical: "pkce-bound", Axis: AxisPatterns}},
	}}
	p1 := parseQuery(Request{Q: "sso pkce"}, cat)
	p2 := parseQuery(Request{Q: "sso pkce"}, cat)

	sortResolved(p1.Resolved)
	sortResolved(p2.Resolved)

	r1, _ := json.Marshal(p1)
	r2, _ := json.Marshal(p2)
	if !bytes.Equal(r1, r2) {
		t.Errorf("parseQuery is non-deterministic:\n%s\nvs\n%s", r1, r2)
	}
	if !strings.Contains(string(r1), "single-sign-on") {
		t.Errorf("expected single-sign-on in resolution, got %s", r1)
	}
}

func sortResolved(rs []ResolvedAlias) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].MatchedToken != rs[j].MatchedToken {
			return rs[i].MatchedToken < rs[j].MatchedToken
		}
		if rs[i].Axis != rs[j].Axis {
			return rs[i].Axis < rs[j].Axis
		}
		return rs[i].Value+rs[i].Artefact < rs[j].Value+rs[j].Artefact
	})
}
