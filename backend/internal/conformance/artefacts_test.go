package conformance

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

func artefactFixture(commit string, publishAfter time.Time) *ArtefactSet {
	body := strings.Repeat("x", 200*1024) // larger than the Looking Glass capture limit
	return &ArtefactSet{
		SchemaVersion: ArtefactSchemaVersion,
		Commit:        commit,
		CapturedAt:    publishAfter.Add(-5 * time.Minute),
		PublishAfter:  publishAfter,
		BaseURLs:      map[string]string{"base": "https://protocolsoup.test"},
		Requirements: []RequirementArtefacts{{
			ID: "AL-002",
			Passing: &Artefact{
				Scenario: "single-header", Actor: ActorConformanceClient,
				Expected: OutcomeAccepted, Outcome: OutcomeAccepted,
				Exchanges: []lookingglass.CapturedExchange{{
					ID:       "one",
					Request:  lookingglass.CapturedMessage{Method: http.MethodPost, URL: "https://protocolsoup.test/token"},
					Response: lookingglass.CapturedMessage{Status: http.StatusOK, Body: lookingglass.EncodePayload([]byte(body), int64(len(body)), false, "application/json")},
				}},
			},
			Unavailable: map[ArtefactKind]string{KindFailing: "not observable over HTTP"},
		}},
	}
}

func TestLoadArtefactsRejectsUnknownSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artefacts.json")
	set := artefactFixture("abc", time.Now())
	if err := writeJSONFile(path, set); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadArtefacts(path)
	if err != nil || loaded.Commit != "abc" || len(loaded.Requirements) != 1 {
		t.Fatalf("LoadArtefacts = %+v, %v", loaded, err)
	}

	set.SchemaVersion = ArtefactSchemaVersion + 1
	if err := writeJSONFile(path, set); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtefacts(path); err == nil {
		t.Fatal("an unknown schema_version must be refused")
	}
}

func TestRequirementArtefactsRoute(t *testing.T) {
	registry := catalogueRegistry()
	publishAfter := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	t.Run("no artefacts loaded", func(t *testing.T) {
		c := NewCatalogue(registry, nil, "abc", nil)
		_, body := serve(t, c, "/requirements/al-002/artefacts")
		if body["status"] != string(ArtefactsNotCaptured) || body["passing"] != nil {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("captured from a different build", func(t *testing.T) {
		c := NewCatalogue(registry, nil, "abc", nil)
		c.SetArtefacts(artefactFixture("other", publishAfter))
		if c.ArtefactsValid() {
			t.Fatal("artefacts from another commit must not be valid")
		}
		_, body := serve(t, c, "/requirements/AL-002/artefacts")
		if body["status"] != string(ArtefactsNotCaptured) || body["commit"] != nil {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("pending until tokens expire", func(t *testing.T) {
		c := NewCatalogue(registry, nil, "abc", nil)
		c.SetArtefacts(artefactFixture("abc", publishAfter))
		c.now = func() time.Time { return publishAfter.Add(-time.Second) }
		_, body := serve(t, c, "/requirements/AL-002/artefacts")
		if body["status"] != string(ArtefactsPending) || body["publish_after"] != "2026-10-27T12:00:00Z" {
			t.Fatalf("body = %+v", body)
		}
		if body["passing"] != nil {
			t.Fatal("exchanges must be withheld before publish_after")
		}
	})

	t.Run("published in full", func(t *testing.T) {
		c := NewCatalogue(registry, nil, "abc", nil)
		c.SetArtefacts(artefactFixture("abc", publishAfter))
		c.now = func() time.Time { return publishAfter }
		_, body := serve(t, c, "/requirements/AL-002/artefacts")
		if body["status"] != string(ArtefactsPublished) {
			t.Fatalf("body = %+v", body)
		}
		passing := body["passing"].(map[string]any)
		exchange := passing["exchanges"].([]any)[0].(map[string]any)
		data := exchange["response"].(map[string]any)["body"].(map[string]any)["data"].(string)
		if len(data) != 200*1024 {
			t.Fatalf("response body has %d bytes; artefacts must keep the full payload", len(data))
		}
		if body["unavailable"].(map[string]any)["failing"] != "not observable over HTTP" {
			t.Fatalf("unavailable = %+v", body["unavailable"])
		}
		if !strings.Contains(body["source_base_url"].(string), "/blob/abc/") {
			t.Fatalf("source_base_url = %v", body["source_base_url"])
		}
	})

	t.Run("unknown requirement", func(t *testing.T) {
		c := NewCatalogue(registry, nil, "abc", nil)
		recorder, _ := serve(t, c, "/requirements/ZZ-404/artefacts")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status = %d", recorder.Code)
		}
	})
}
