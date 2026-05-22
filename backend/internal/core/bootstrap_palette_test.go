package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/palette"
)

func TestBootstrap_paletteRequiredInProduction(t *testing.T) {
	t.Setenv("SHOWCASE_ENV", "production")
	t.Setenv("SHOWCASE_PALETTE_DB", "")

	_, err := Bootstrap(BootstrapOptions{EnablePalette: true})
	if err == nil {
		t.Fatal("expected error when SHOWCASE_PALETTE_DB is empty in production")
	}
}

func TestBootstrap_paletteMissingFileFailsInProduction(t *testing.T) {
	t.Setenv("SHOWCASE_ENV", "production")
	t.Setenv("SHOWCASE_PALETTE_DB", filepath.Join(t.TempDir(), "missing.db"))

	_, err := Bootstrap(BootstrapOptions{EnablePalette: true})
	if err == nil {
		t.Fatal("expected error when palette db is missing in production")
	}
}

func TestBootstrap_paletteOptionalInDevelopment(t *testing.T) {
	t.Setenv("SHOWCASE_ENV", "development")
	t.Setenv("SHOWCASE_PALETTE_DB", "")

	result, err := Bootstrap(BootstrapOptions{EnablePalette: true})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if result.Palette != nil {
		t.Fatal("expected nil palette when path is empty in development")
	}
}

func TestBootstrap_paletteLoadsFromFile(t *testing.T) {
	contentDir := filepath.Join("..", "..", "..", "content")
	if _, err := os.Stat(contentDir); err != nil {
		t.Skipf("content tree not available: %v", err)
	}
	out := filepath.Join(t.TempDir(), "palette.db")
	if err := palette.BuildIndex(contentDir, out); err != nil {
		t.Fatalf("build index: %v", err)
	}

	t.Setenv("SHOWCASE_ENV", "development")
	t.Setenv("SHOWCASE_PALETTE_DB", out)

	result, err := Bootstrap(BootstrapOptions{EnablePalette: true})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if result.Palette == nil {
		t.Fatal("expected palette service")
	}
	t.Cleanup(func() {
		_ = result.Palette.Close()
	})
	stats := result.Palette.Stats()
	if !stats.Loaded || stats.ArtefactCount == 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
