package palette

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a test helper that writes contents under dir/path, creating
// parents as needed. The path is relative to dir and uses forward slashes.
func writeFile(t *testing.T, dir, rel, contents string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

const seedTaxonomy = `
use_cases:
  user-login-via-own-idp:
    note: User signs into a relying party.
  service-to-service-auth:
    note: Service authenticates as itself.
actors:
  public-client:
    note: SPA, mobile, or native client.
  authorization-server:
    note: OAuth AS.
  resource-server:
    note: API enforcing access tokens.
patterns:
  pkce-bound:
    note: PKCE-bound authorization.
  back-channel:
    note: Server-to-server.
problem_domains:
  authorization:
    note: Deciding what an authenticated party may do.
  authentication:
    note: Verifying who someone is.
`

const seedAliases = `
aliases:
  - alias: pkce
    canonical:
      - axis: patterns
        value: pkce-bound
      - artefact: pkce
  - alias: m2m
    canonical:
      - axis: use_cases
        value: service-to-service-auth
`

func seedContent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "taxonomy.yaml", seedTaxonomy)
	writeFile(t, dir, "aliases.yaml", seedAliases)
	writeFile(t, dir, "protocols/oauth2.md", `---
id: oauth2
name: OAuth 2.0
use_cases:
  - service-to-service-auth
  - user-login-via-own-idp
actors:
  - public-client
  - authorization-server
  - resource-server
patterns:
  - back-channel
problem_domains:
  - authorization
---
OAuth 2.0 is the authorization framework for delegated API access. It defines flows used by clients to obtain access tokens.
`)
	writeFile(t, dir, "flows/oauth2/authorization-code-pkce.md", `---
id: authorization-code-pkce
name: Authorization code + PKCE
protocol: oauth2
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
  - authorization-server
patterns:
  - pkce-bound
  - back-channel
problem_domains:
  - authorization
runnable: true
backend_id: authorization_code_pkce
---
Authorization code flow bound to a PKCE verifier. The canonical sign-in flow for public clients.
`)
	writeFile(t, dir, "concepts/pkce.md", `---
id: pkce
name: PKCE
protocols:
  - oauth2
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
patterns:
  - pkce-bound
problem_domains:
  - authorization
---
Proof Key for Code Exchange. Binds an authorization request to a per-request code_verifier.
`)
	return dir
}

func TestValidateContentClean(t *testing.T) {
	dir := seedContent(t)
	artefacts, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected clean validation, got %d issues:\n%v", len(issues), issues)
	}
	if len(artefacts) != 3 {
		t.Fatalf("expected 3 artefacts, got %d", len(artefacts))
	}
}

func TestValidateContentUnknownAxisValue(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/bad-axis.md", `---
id: bad-axis
name: Bad axis
use_cases:
  - not-a-real-use-case
actors:
  - public-client
problem_domains:
  - authorization
---
`)
	_, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "concepts/bad-axis.md", "unknown value \"not-a-real-use-case\"") {
		t.Fatalf("expected unknown-value issue, got: %v", issues)
	}
}

func TestValidateContentMissingRequired(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/missing.md", `---
id: missing
name: Missing fields
---
`)
	_, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	wanted := []string{
		"missing required field use_cases",
		"missing required field actors",
		"missing required field problem_domains",
	}
	for _, m := range wanted {
		if !containsIssue(issues, "concepts/missing.md", m) {
			t.Fatalf("expected issue containing %q, got: %v", m, issues)
		}
	}
}

func TestValidateContentDuplicateAlias(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "aliases.yaml", seedAliases+`
  - alias: m2m
    canonical:
      - axis: actors
        value: public-client
`)
	_, _, _, _, err := ValidateContent(dir)
	if err == nil {
		t.Fatalf("expected duplicate alias error")
	}
	if !strings.Contains(err.Error(), "duplicate alias keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContentDanglingEdge(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/with-dangling.md", `---
id: with-dangling
name: Dangling reference
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
problem_domains:
  - authorization
related_concepts:
  - does-not-exist
---
`)
	_, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "concepts/with-dangling.md", "related_concepts references unknown artefact id \"does-not-exist\"") {
		t.Fatalf("expected dangling-edge issue, got: %v", issues)
	}
}

func TestValidateContentFilenameMismatch(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/mismatch.md", `---
id: not-mismatch
name: Filename mismatch
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
problem_domains:
  - authorization
---
`)
	_, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "concepts/mismatch.md", "does not match filename stem") {
		t.Fatalf("expected filename mismatch issue, got: %v", issues)
	}
}

func TestValidateContentUnknownTopLevelField(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/unknown-field.md", `---
id: unknown-field
name: Unknown
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
problem_domains:
  - authorization
mystery: 42
---
`)
	_, _, _, _, err := ValidateContent(dir)
	if err == nil {
		t.Fatalf("expected unknown-field error")
	}
	if !strings.Contains(err.Error(), "unknown frontmatter fields: mystery") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContentFlowProtocolMismatch(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "flows/oauth2/wrong-protocol.md", `---
id: wrong-protocol
name: Mismatched protocol
protocol: oidc
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
problem_domains:
  - authorization
---
`)
	_, _, _, issues, err := ValidateContent(dir)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "flows/oauth2/wrong-protocol.md", "flow protocol \"oidc\" does not match parent directory \"oauth2\"") {
		t.Fatalf("expected protocol mismatch issue, got: %v", issues)
	}
}

func containsIssue(issues []Issue, path, needle string) bool {
	for _, i := range issues {
		if i.Path == path && strings.Contains(i.Message, needle) {
			return true
		}
	}
	return false
}
