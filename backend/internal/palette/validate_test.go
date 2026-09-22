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
	artefacts, _, _, issues, err := ValidateContent(dir, nil)
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
	_, _, _, issues, err := ValidateContent(dir, nil)
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
	_, _, _, issues, err := ValidateContent(dir, nil)
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
	_, _, _, _, err := ValidateContent(dir, nil)
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
	_, _, _, issues, err := ValidateContent(dir, nil)
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
	_, _, _, issues, err := ValidateContent(dir, nil)
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
	_, _, _, _, err := ValidateContent(dir, nil)
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
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "flows/oauth2/wrong-protocol.md", "flow protocol \"oidc\" does not match parent directory \"oauth2\"") {
		t.Fatalf("expected protocol mismatch issue, got: %v", issues)
	}
}

func TestValidateContentRunDefaultsValid(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "flows/oauth2/dpop-run-default.md", `---
id: dpop-run-default
name: DPoP-preset flow
protocol: oauth2
use_cases:
  - service-to-service-auth
actors:
  - authorization-server
problem_domains:
  - authorization
runnable: true
backend_id: dpop_run_default
run_defaults:
  client_auth: private_key_jwt
  token_mode: dpop
---
`)
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if containsIssue(issues, "flows/oauth2/dpop-run-default.md", "run_defaults") {
		t.Fatalf("expected no run_defaults issue, got: %v", issues)
	}
}

func TestValidateContentRunDefaultsRejectsUnknownValues(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "flows/oauth2/bad-run-default.md", `---
id: bad-run-default
name: Bad run default
protocol: oauth2
use_cases:
  - service-to-service-auth
actors:
  - authorization-server
problem_domains:
  - authorization
runnable: true
backend_id: bad_run_default
run_defaults:
  client_auth: shared-secret
  token_mode: mac
---
`)
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "flows/oauth2/bad-run-default.md", "run_defaults.client_auth \"shared-secret\"") {
		t.Fatalf("expected client_auth issue, got: %v", issues)
	}
	if !containsIssue(issues, "flows/oauth2/bad-run-default.md", "run_defaults.token_mode \"mac\"") {
		t.Fatalf("expected token_mode issue, got: %v", issues)
	}
}

func TestValidateContentRunDefaultsRejectedOnNonRunnableFlow(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "flows/oauth2/non-runnable-run-default.md", `---
id: non-runnable-run-default
name: Non-runnable with run_defaults
protocol: oauth2
use_cases:
  - service-to-service-auth
actors:
  - authorization-server
problem_domains:
  - authorization
runnable: false
run_defaults:
  token_mode: dpop
---
`)
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "flows/oauth2/non-runnable-run-default.md", "run_defaults is set but the flow is not runnable") {
		t.Fatalf("expected non-runnable issue, got: %v", issues)
	}
}

func TestValidateContentRunDefaultsRejectedOnNonFlowArtefact(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "concepts/run-default-on-concept.md", `---
id: run-default-on-concept
name: run_defaults on a concept
use_cases:
  - user-login-via-own-idp
actors:
  - public-client
problem_domains:
  - authorization
run_defaults:
  token_mode: dpop
---
`)
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "concepts/run-default-on-concept.md", "run_defaults is only valid on flow artefacts") {
		t.Fatalf("expected flow-only issue, got: %v", issues)
	}
}

// seedRequirements is the registry slice the explainer tests resolve against.
var seedRequirements = RequirementIndex{
	"vp-001": {ID: "VP-001", Spec: "oid4vp"},
}

const explainerFrontmatter = `---
id: vp-001
name: Client identifier prefix
protocols:
  - oauth2
use_cases:
  - user-login-via-own-idp
actors:
  - authorization-server
problem_domains:
  - authentication
normative_level: MUST
normative_anchors:
  - rfc: OpenID4VP
    sections: ["5.9.1"]
assertion_text: The Verifier MUST use a Client Identifier Prefix.
---
`

const explainerBody = `## What this requires

The client_id carries a prefix that names how the wallet should authenticate the verifier.

## Why it exists

Without a prefix a wallet cannot tell a redirect_uri identifier from an x509_san_dns one.

## What non-compliance looks like

A bare hostname as client_id, accepted by a wallet that guesses the scheme.

## How ProtocolSoup tests it

The verifier rejects request objects whose client_id has no recognised prefix.
`

// TestLoadRequirementIndex checks both loaders against the real registry:
// the embedded copy and the on-disk file must agree, and IDs resolve
// case-insensitively to their specification.
func TestLoadRequirementIndex(t *testing.T) {
	embedded, err := LoadRequirementIndex("")
	if err != nil {
		t.Fatalf("embedded registry: %v", err)
	}
	fromDisk, err := LoadRequirementIndex(filepath.Join("..", "conformance", "vc-requirements.yaml"))
	if err != nil {
		t.Fatalf("on-disk registry: %v", err)
	}
	if len(embedded) == 0 || len(embedded) != len(fromDisk) {
		t.Fatalf("embedded has %d requirements, disk has %d", len(embedded), len(fromDisk))
	}
	ref, ok := embedded["vp-001"]
	if !ok || ref.ID != "VP-001" || ref.Spec != "oid4vp" {
		t.Fatalf("vp-001 resolved to %+v (ok=%t); want VP-001 in oid4vp", ref, ok)
	}
	if _, err := LoadRequirementIndex(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatalf("expected an error for a missing registry path")
	}
}

func TestValidateExplainerClean(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/vp-001.md", explainerFrontmatter+explainerBody)
	artefacts, _, _, issues, err := ValidateContent(dir, seedRequirements)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected clean validation, got: %v", issues)
	}
	var found bool
	for _, a := range artefacts {
		if a.ID != "vp-001" {
			continue
		}
		found = true
		if a.Spec != "oid4vp" {
			t.Errorf("Spec = %q; want oid4vp (resolved from registry)", a.Spec)
		}
		if got := a.DefaultHref(); got != "/spec/oid4vp/vp-001" {
			t.Errorf("DefaultHref = %q; want /spec/oid4vp/vp-001", got)
		}
	}
	if !found {
		t.Fatalf("explainer artefact not returned")
	}
}

func TestValidateExplainerRejectsUnknownRequirement(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/vp-999.md", strings.Replace(explainerFrontmatter, "id: vp-001", "id: vp-999", 1)+explainerBody)
	_, _, _, issues, err := ValidateContent(dir, seedRequirements)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "assertions/vp-999.md", `spec-assertion id "vp-999" is not a requirement in the conformance registry`) {
		t.Fatalf("expected unknown-requirement issue, got: %v", issues)
	}
}

func TestValidateExplainerRejectsUppercaseID(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/VP-001.md", strings.Replace(explainerFrontmatter, "id: vp-001", "id: VP-001", 1)+explainerBody)
	_, _, _, issues, err := ValidateContent(dir, seedRequirements)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "assertions/VP-001.md", "must be the lowercase registry requirement id") {
		t.Fatalf("expected lowercase issue, got: %v", issues)
	}
}

func TestValidateExplainerRequiresRegistry(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/vp-001.md", explainerFrontmatter+explainerBody)
	_, _, _, issues, err := ValidateContent(dir, nil)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "assertions/vp-001.md", "no requirement registry loaded") {
		t.Fatalf("expected missing-registry issue, got: %v", issues)
	}
}

func TestValidateExplainerRejectsHeadingMismatch(t *testing.T) {
	cases := map[string]string{
		"missing heading": strings.Replace(explainerBody, "## Why it exists\n\n", "", 1),
		"wrong order":     strings.Replace(strings.Replace(explainerBody, "## Why it exists", "## TEMP", 1), "## What this requires", "## Why it exists", 1),
		"extra heading":   explainerBody + "\n## Further reading\n\nMore.\n",
		"renamed heading": strings.Replace(explainerBody, "## How ProtocolSoup tests it", "## How we test it", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := seedContent(t)
			writeFile(t, dir, "assertions/vp-001.md", explainerFrontmatter+body)
			_, _, _, issues, err := ValidateContent(dir, seedRequirements)
			if err != nil {
				t.Fatalf("ValidateContent error: %v", err)
			}
			if !containsIssue(issues, "assertions/vp-001.md", "must contain exactly these ## headings in order") {
				t.Fatalf("expected heading issue, got: %v", issues)
			}
		})
	}
}

func TestValidateExplainerRejectsFencesAndHTML(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/vp-001.md", explainerFrontmatter+
		strings.Replace(explainerBody, "A bare hostname as client_id, accepted by a wallet that guesses the scheme.",
			"```json\n{\"client_id\": \"verifier.example\"}\n```\n\n<details>A bare hostname.</details>", 1))
	_, _, _, issues, err := ValidateContent(dir, seedRequirements)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if !containsIssue(issues, "assertions/vp-001.md", "must not contain fenced code blocks") {
		t.Fatalf("expected fence issue, got: %v", issues)
	}
	if !containsIssue(issues, "assertions/vp-001.md", "must not contain raw HTML") {
		t.Fatalf("expected HTML issue, got: %v", issues)
	}
}

func TestValidateExplainerAllowsInlineCodeAndComparisons(t *testing.T) {
	dir := seedContent(t)
	writeFile(t, dir, "assertions/vp-001.md", explainerFrontmatter+
		strings.Replace(explainerBody, "The client_id carries a prefix", "The `client_id` carries a prefix (and 1 < 2 is still prose)", 1))
	_, _, _, issues, err := ValidateContent(dir, seedRequirements)
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("inline code and a bare '<' must not be flagged, got: %v", issues)
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
