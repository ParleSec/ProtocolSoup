// Command content-validate walks the ProtocolSoup content tree, validates
// every artefact's frontmatter against the taxonomy, and verifies cross-
// artefact edges. It exits non-zero if any issue is found so it can be wired
// directly into CI.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ParleSec/ProtocolSoup/internal/palette"
)

func main() {
	contentDir := flag.String("content", "content", "path to content directory")
	flag.Parse()

	if err := run(*contentDir); err != nil {
		fmt.Fprintln(os.Stderr, "content-validate:", err)
		os.Exit(2)
	}
}

func run(contentDir string) error {
	artefacts, _, _, issues, err := palette.ValidateContent(contentDir)
	if err != nil {
		return err
	}
	if len(issues) == 0 {
		fmt.Printf("content-validate: %d artefacts OK\n", len(artefacts))
		return nil
	}
	fmt.Fprintf(os.Stderr, "content-validate: %d issue(s) across %d artefact(s)\n", len(issues), len(artefacts))
	for _, issue := range issues {
		fmt.Fprintln(os.Stderr, "  "+issue.Format())
	}
	os.Exit(1)
	return nil
}
