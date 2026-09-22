package conformance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func writeJSONFile(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func serve(t *testing.T, c *Catalogue, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	c.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if recorder.Code == http.StatusOK && strings.HasPrefix(recorder.Body.String(), "{") {
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v\n%s", path, err, recorder.Body.String())
		}
	}
	return recorder, body
}

func TestSpecsRouteValidReport(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, mapExplainers{"al-010": "# x"})

	recorder, body := serve(t, c, "/specs")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != cacheControl {
		t.Fatalf("Cache-Control = %q", got)
	}
	if body["report_valid"] != true || body["launch_gate_open"] != true {
		t.Fatalf("report_valid/launch_gate_open = %v/%v", body["report_valid"], body["launch_gate_open"])
	}
	if body["commit"] != testBuildCommit || body["generated_at"] != "2026-09-22T00:00:00Z" {
		t.Fatalf("commit/generated_at = %v/%v", body["commit"], body["generated_at"])
	}
	specs := body["specs"].([]any)
	if len(specs) != 2 {
		t.Fatalf("specs = %d, want 2 (empty spec excluded)", len(specs))
	}
	alpha := specs[0].(map[string]any)
	if alpha["short_title"] != "Alpha 1.0" || alpha["requirement_count"] != float64(4) || alpha["indexable"] != true {
		t.Fatalf("alpha summary = %+v", alpha)
	}
	if alpha["verdicts"].(map[string]any)["PASS"] != float64(4) {
		t.Fatalf("alpha verdicts = %+v", alpha["verdicts"])
	}
	beta := specs[1].(map[string]any)
	if beta["indexable"] != false {
		t.Fatalf("beta should not be indexable without an explainer: %+v", beta)
	}
}

func TestSpecsRouteInvalidReportOmitsProvenance(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), "different", nil)
	_, body := serve(t, c, "/specs")
	if body["report_valid"] != false || body["launch_gate_open"] != false {
		t.Fatalf("report_valid/launch_gate_open = %v/%v", body["report_valid"], body["launch_gate_open"])
	}
	for _, key := range []string{"commit", "generated_at"} {
		if _, present := body[key]; present {
			t.Fatalf("%s must be omitted when the report is invalid", key)
		}
	}
	alpha := body["specs"].([]any)[0].(map[string]any)
	if _, present := alpha["verdicts"]; present {
		t.Fatal("verdict summary must be omitted when the report is invalid")
	}
}

func TestSpecRouteOrderingLookupAndNotFound(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, nil)

	recorder, body := serve(t, c, "/specs/ALPHA")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d for case-insensitive spec lookup", recorder.Code)
	}
	if body["id"] != "alpha" {
		t.Fatalf("id = %v, want canonical alpha", body["id"])
	}
	rows := body["requirements"].([]any)
	wantOrder := []string{"AL-001", "AL-002", "AL-003", "AL-010"}
	for i, want := range wantOrder {
		row := rows[i].(map[string]any)
		if row["id"] != want {
			t.Fatalf("requirements[%d].id = %v, want %v", i, row["id"], want)
		}
		if row["verdict"] != "PASS" {
			t.Fatalf("requirements[%d].verdict = %v, want PASS", i, row["verdict"])
		}
	}

	for _, path := range []string{"/specs/empty", "/specs/missing"} {
		recorder, _ := serve(t, c, path)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", path, recorder.Code)
		}
	}
}

func TestRequirementRouteValidReport(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, mapExplainers{"al-002": "## What this requires"})

	recorder, body := serve(t, c, "/requirements/al-002")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if body["id"] != "AL-002" {
		t.Fatalf("id = %v, want canonical AL-002", body["id"])
	}
	if body["section_url"] != "https://example.test/alpha#section-5.9.1" {
		t.Fatalf("section_url = %v", body["section_url"])
	}
	if body["verdict"] != "PASS" || body["commit"] != testBuildCommit {
		t.Fatalf("verdict/commit = %v/%v", body["verdict"], body["commit"])
	}
	if body["source_base_url"] != SourceRepository+"/blob/"+testBuildCommit+"/" {
		t.Fatalf("source_base_url = %v", body["source_base_url"])
	}
	if body["explainer_markdown"] != "## What this requires" || body["indexable"] != true {
		t.Fatalf("explainer/indexable = %v/%v", body["explainer_markdown"], body["indexable"])
	}
	tests := body["tests"].([]any)
	test := tests[0].(map[string]any)
	if test["name"] != "TestTwo" || test["file"] != "backend/a_test.go" || test["line"] != float64(42) || test["verdict"] != "PASS" {
		t.Fatalf("tests[0] = %+v", test)
	}
	if _, present := test["output"]; present {
		t.Fatal("test output must never be included in responses")
	}
	if strings.Contains(recorder.Body.String(), "secret test output") {
		t.Fatal("response body leaked test output")
	}
	siblings := body["siblings"].([]any)
	if len(siblings) != 1 || siblings[0].(map[string]any)["id"] != "AL-003" {
		t.Fatalf("siblings = %+v", siblings)
	}
	if body["previous"].(map[string]any)["id"] != "AL-001" || body["next"].(map[string]any)["id"] != "AL-003" {
		t.Fatalf("previous/next = %v/%v", body["previous"], body["next"])
	}
	spec := body["specification"].(map[string]any)
	if spec["id"] != "alpha" || spec["short_title"] != "Alpha 1.0" {
		t.Fatalf("specification = %+v", spec)
	}
}

func TestRequirementRouteInvalidReportOmitsVerdictAndSourceLinks(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, catalogueReport(registry, nil), "different", mapExplainers{"al-002": "x"})

	recorder, body := serve(t, c, "/requirements/AL-002")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	for _, key := range []string{"verdict", "commit", "generated_at", "source_base_url"} {
		if _, present := body[key]; present {
			t.Fatalf("%s must be omitted when the report is invalid", key)
		}
	}
	if body["indexable"] != false {
		t.Fatal("indexable must be false when the report is invalid")
	}
	test := body["tests"].([]any)[0].(map[string]any)
	if _, present := test["verdict"]; present {
		t.Fatal("per-test verdict must be omitted when the report is invalid")
	}
	if _, present := test["line"]; present {
		t.Fatal("line must be omitted when no valid report supplies it")
	}
	if body["statement"] == "" || body["title"] != "Two" {
		t.Fatalf("registry fields must still render: %+v", body)
	}
}

func TestRequirementRouteNotFound(t *testing.T) {
	registry := catalogueRegistry()
	c := NewCatalogue(registry, nil, "", nil)
	recorder, _ := serve(t, c, "/requirements/ZZ-404")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestSitemapRoute(t *testing.T) {
	registry := catalogueRegistry()

	t.Run("indexable pages only", func(t *testing.T) {
		c := NewCatalogue(registry, catalogueReport(registry, nil), testBuildCommit, mapExplainers{"al-010": "x", "be-001": "y"})
		recorder := httptest.NewRecorder()
		c.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sitemap", nil))
		var entries []SitemapEntry
		if err := json.Unmarshal(recorder.Body.Bytes(), &entries); err != nil {
			t.Fatal(err)
		}
		want := []SitemapEntry{
			{Path: "/spec/alpha", LastMod: "2026-09-22T00:00:00Z"},
			{Path: "/spec/alpha/al-010", LastMod: "2026-09-22T00:00:00Z"},
			{Path: "/spec/beta", LastMod: "2026-09-22T00:00:00Z"},
			{Path: "/spec/beta/be-001", LastMod: "2026-09-22T00:00:00Z"},
		}
		if len(entries) != len(want) {
			t.Fatalf("entries = %+v, want %+v", entries, want)
		}
		for i := range want {
			if entries[i] != want[i] {
				t.Fatalf("entries[%d] = %+v, want %+v", i, entries[i], want[i])
			}
		}
	})

	t.Run("empty array when nothing indexable", func(t *testing.T) {
		c := NewCatalogue(registry, nil, testBuildCommit, nil)
		recorder := httptest.NewRecorder()
		c.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/sitemap", nil))
		if strings.TrimSpace(recorder.Body.String()) != "[]" {
			t.Fatalf("body = %q, want []", recorder.Body.String())
		}
	})
}

func TestLoadReportFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/report.json"
	if err := writeJSONFile(path, catalogueReport(catalogueRegistry(), nil)); err != nil {
		t.Fatal(err)
	}
	report, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if report.Commit != testBuildCommit || len(report.Requirements) != 5 {
		t.Fatalf("LoadReport returned %+v", report)
	}
	if _, err := LoadReport(dir + "/missing.json"); err == nil {
		t.Fatal("LoadReport(missing) should fail")
	}
}
