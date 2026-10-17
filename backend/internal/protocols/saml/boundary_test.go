package saml

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestRolesDoNotImportEachOther keeps the IdP and the SP separate entities:
// each may learn about the other only from published metadata and messages
// received over a binding, never from the other's code or state.
func TestRolesDoNotImportEachOther(t *testing.T) {
	const module = "github.com/ParleSec/ProtocolSoup/internal/protocols/saml/"
	for role, forbidden := range map[string]string{"idp": module + "sp", "sp": module + "idp"} {
		files, err := filepath.Glob(filepath.Join(role, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files found for package %s", role)
		}
		for _, file := range files {
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range parsed.Imports {
				path, _ := strconv.Unquote(spec.Path.Value)
				if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
					t.Errorf("%s imports %s; the SAML roles must stay separate entities", file, path)
				}
			}
		}
	}
}
