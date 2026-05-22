// Command palette-indexer builds the ProtocolSoup palette SQLite index from a
// content tree. The output file is deterministic for fixed input: running the
// indexer twice on the same tree produces a byte-identical database, which is
// what lets CI compare deploy artefacts.
//
// Canonical paths:
//   - Build-time output (local/CI): backend/dist/palette.db  (-out ./dist/palette.db from backend/)
//   - Container build output:       /app/palette.db           (Dockerfile.backend / Dockerfile.fly)
//   - Runtime (containers):         /app/palette.db           (SHOWCASE_PALETTE_DB)
//
// The index is a backend artefact served by Go at POST /api/palette/query, not
// a frontend static file.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ParleSec/ProtocolSoup/internal/palette"
)

func main() {
	contentDir := flag.String("content", "content", "path to content directory")
	outPath := flag.String("out", "dist/palette.db", "output sqlite path")
	flag.Parse()

	if err := palette.BuildIndex(*contentDir, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, "palette-indexer:", err)
		os.Exit(1)
	}
	fmt.Printf("palette-indexer: wrote %s\n", *outPath)
}
