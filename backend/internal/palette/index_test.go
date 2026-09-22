package palette

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBuildIndexIdempotent(t *testing.T) {
	contentDir := seedContent(t)
	out1 := filepath.Join(t.TempDir(), "palette.db")
	out2 := filepath.Join(t.TempDir(), "palette.db")

	if err := BuildIndex(contentDir, out1, nil); err != nil {
		t.Fatalf("BuildIndex #1: %v", err)
	}
	if err := BuildIndex(contentDir, out2, nil); err != nil {
		t.Fatalf("BuildIndex #2: %v", err)
	}

	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatalf("read out1: %v", err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatalf("read out2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		h1 := sha256.Sum256(b1)
		h2 := sha256.Sum256(b2)
		t.Fatalf("indexer is not idempotent: sha256(out1)=%s sha256(out2)=%s",
			hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:]))
	}
}

func TestBuildIndexContent(t *testing.T) {
	contentDir := seedContent(t)
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := BuildIndex(contentDir, out, nil); err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(out)+"?mode=ro")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var artefactCount, axisCount, edgeCount, aliasCount, ftsCount int
	row := db.QueryRow("SELECT COUNT(*) FROM artefacts")
	if err := row.Scan(&artefactCount); err != nil {
		t.Fatalf("count artefacts: %v", err)
	}
	if artefactCount != 3 {
		t.Errorf("expected 3 artefacts, got %d", artefactCount)
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM axis_values").Scan(&axisCount); err != nil {
		t.Fatalf("count axis_values: %v", err)
	}
	if axisCount == 0 {
		t.Errorf("axis_values is empty")
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM edges").Scan(&edgeCount); err != nil {
		t.Fatalf("count edges: %v", err)
	}
	if edgeCount == 0 {
		t.Errorf("edges is empty (expected at least the flow→protocol edge)")
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM aliases").Scan(&aliasCount); err != nil {
		t.Fatalf("count aliases: %v", err)
	}
	if aliasCount == 0 {
		t.Errorf("aliases is empty")
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM artefacts_fts").Scan(&ftsCount); err != nil {
		t.Fatalf("count artefacts_fts: %v", err)
	}
	if ftsCount != artefactCount {
		t.Errorf("FTS row count (%d) != artefacts count (%d)", ftsCount, artefactCount)
	}

	// FTS5 lookup works.
	var name string
	err = db.QueryRow(`SELECT name FROM artefacts WHERE id IN (SELECT id FROM artefacts_fts WHERE artefacts_fts MATCH 'pkce') LIMIT 1`).Scan(&name)
	if err != nil {
		t.Fatalf("FTS5 lookup failed: %v", err)
	}
	if name == "" {
		t.Errorf("FTS5 returned empty name")
	}
}

// TestBuildIndexExplainerHrefAndService covers the explainer path end to
// end: the indexer stores the registry-derived href and spec, and the query
// service exposes the body through Explainer for the conformance catalogue.
func TestBuildIndexExplainerHrefAndService(t *testing.T) {
	contentDir := seedContent(t)
	writeFile(t, contentDir, "assertions/vp-001.md", explainerFrontmatter+explainerBody)
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := BuildIndex(contentDir, out, seedRequirements); err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(out)+"?mode=ro")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var href string
	if err := db.QueryRow(`SELECT href FROM artefacts WHERE id = 'vp-001'`).Scan(&href); err != nil {
		t.Fatalf("select href: %v", err)
	}
	if href != "/spec/oid4vp/vp-001" {
		t.Errorf("href = %q; want /spec/oid4vp/vp-001", href)
	}

	svc, err := NewService(out)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Close()

	if got := svc.catalog.artefacts["vp-001"].Spec; got != "oid4vp" {
		t.Errorf("payload spec = %q; want oid4vp", got)
	}
	body, ok := svc.Explainer("VP-001")
	if !ok {
		t.Fatalf("Explainer(VP-001) not found; lookup must be case-insensitive on the requirement id")
	}
	if !bytes.Contains([]byte(body), []byte("## How ProtocolSoup tests it")) {
		t.Errorf("Explainer body missing headings: %q", body)
	}
	if _, ok := svc.Explainer("pkce"); ok {
		t.Errorf("Explainer(pkce) returned a concept body; only spec-assertions qualify")
	}
	if _, ok := svc.Explainer("vp-404"); ok {
		t.Errorf("Explainer(vp-404) found for an unknown id")
	}
}

// TestBuildIndexRefusesInvalidExplainer pins that a broken explainer never
// reaches palette.db: the indexer stops on validation issues.
func TestBuildIndexRefusesInvalidExplainer(t *testing.T) {
	contentDir := seedContent(t)
	writeFile(t, contentDir, "assertions/vp-001.md", explainerFrontmatter+"## What this requires\n\nOnly one heading.\n")
	out := filepath.Join(t.TempDir(), "palette.db")
	err := BuildIndex(contentDir, out, seedRequirements)
	if err == nil {
		t.Fatalf("expected BuildIndex to fail on a malformed explainer")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatalf("palette.db written despite validation failure")
	}
}

func TestBuildIndexAliasComposite(t *testing.T) {
	// aliases.yaml in seed has the "pkce" alias mapping to both an axis value
	// and an artefact. Both rows must be present.
	contentDir := seedContent(t)
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := BuildIndex(contentDir, out, nil); err != nil {
		t.Fatalf("BuildIndex: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(out)+"?mode=ro")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM aliases WHERE alias = 'pkce'`).Scan(&n); err != nil {
		t.Fatalf("count pkce: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 alias rows for 'pkce', got %d", n)
	}
}
