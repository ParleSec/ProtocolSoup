package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

const (
	walletDocsURL           = "https://docs.protocolsoup.com/deploy/services/wallet/"
	walletOID4VCIDocsURL    = "https://docs.protocolsoup.com/protocols/oid4vci/"
	walletOID4VPDocsURL     = "https://docs.protocolsoup.com/protocols/oid4vp/"
	walletAgentSkillName    = "use-wallet-harness"
	walletAgentSkillsSchema = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
	walletContentSignal     = "search=yes, ai-input=yes, ai-train=no"
)

type walletAgentSkill struct {
	name        string
	description string
	body        string
}

func (s *walletHarnessServer) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/api/resolve", s.handleAPIResolve)
	mux.HandleFunc("/api/session", s.handleAPISession)
	mux.HandleFunc("/api/issue", s.handleAPIIssue)
	mux.HandleFunc("/api/import", s.handleAPIImport)
	mux.HandleFunc("/api/oid4vci/callback", s.handleAPIOID4VCICallback)
	mux.HandleFunc("/api/preview", s.handleAPIPreview)
	mux.HandleFunc("/api/present", s.handleAPIPresent)
	mux.HandleFunc("/.well-known/did.json", s.handleWalletDIDDocument)
	mux.HandleFunc("/wallet/", s.handleWalletDIDDocument)
	mux.HandleFunc("/llms.txt", s.handleLLMsTxt)
	mux.HandleFunc("/llms-full.txt", s.handleLLMsFullTxt)
	mux.HandleFunc("/robots.txt", s.handleRobotsTxt)
	mux.HandleFunc("/.well-known/api-catalog", s.handleAPICatalog)
	mux.HandleFunc("/.well-known/agent-skills/index.json", s.handleAgentSkillsIndex)
	mux.HandleFunc("/.well-known/agent-skills/{name}/SKILL.md", s.handleAgentSkill)
	mux.HandleFunc("/", s.handleWalletApp)
}

func (s *walletHarnessServer) handleLLMsTxt(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	origin := requestBaseURL(r)
	writePlain(w, http.StatusOK, "text/plain; charset=utf-8", walletLLMsTxt(origin, s.siteOrigin()))
}

func (s *walletHarnessServer) handleLLMsFullTxt(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	writePlain(w, http.StatusOK, "text/plain; charset=utf-8", s.walletSkill(requestBaseURL(r)).body)
}

func (s *walletHarnessServer) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	origin := requestBaseURL(r)
	host := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	body := strings.Join([]string{
		"# Content Signals — https://contentsignals.org/",
		"#",
		"# search=yes, ai-input=yes, ai-train=no",
		"# Indexing and inference-time grounding are permitted; training is not.",
		"",
		"User-agent: *",
		"Content-Signal: " + walletContentSignal,
		"Allow: /",
		"Disallow: /api/",
		"Disallow: /submit",
		"Disallow: /health",
		"Disallow: /authorize",
		"",
		"Host: " + host,
		"Sitemap: " + origin + "/sitemap.xml",
		"",
	}, "\n")
	writePlain(w, http.StatusOK, "text/plain; charset=utf-8", body)
}

func (s *walletHarnessServer) handleAPICatalog(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	origin := requestBaseURL(r)
	site := s.siteOrigin()
	payload := map[string]interface{}{
		"linkset": []map[string]interface{}{
			{
				"anchor": origin + "/",
				"service-doc": []map[string]string{
					{"href": walletDocsURL, "type": "text/html", "title": "Wallet harness runtime contract"},
					{"href": walletOID4VCIDocsURL, "type": "text/html", "title": "OID4VCI protocol guide"},
					{"href": walletOID4VPDocsURL, "type": "text/html", "title": "OID4VP protocol guide"},
				},
				"describedby": []map[string]string{
					{"href": origin + "/llms.txt", "type": "text/plain", "title": "Wallet profile for agents"},
					{"href": origin + "/llms-full.txt", "type": "text/plain", "title": "Wallet API recipes for agents"},
					{"href": origin + "/.well-known/agent-skills/index.json", "type": "application/json", "title": "Agent skills index"},
					{"href": site + "/", "type": "text/html", "title": "ProtocolSoup Looking Glass"},
				},
				"status": []map[string]string{
					{"href": origin + "/health", "type": "application/json", "title": "Runtime health"},
				},
			},
		},
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Content-Type", "application/linkset+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Link", `<`+origin+`/.well-known/api-catalog>; rel="self"; type="application/linkset+json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

func (s *walletHarnessServer) handleAgentSkillsIndex(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	origin := requestBaseURL(r)
	skill := s.walletSkill(origin)
	payload := map[string]interface{}{
		"$schema": walletAgentSkillsSchema,
		"skills": []map[string]string{
			{
				"name":        skill.name,
				"type":        "skill-md",
				"description": skill.description,
				"url":         origin + "/.well-known/agent-skills/" + skill.name + "/SKILL.md",
				"digest":      "sha256:" + sha256Hex(skill.body),
			},
		},
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writePlain(w, http.StatusOK, "application/json; charset=utf-8", string(body)+"\n")
}

func (s *walletHarnessServer) handleAgentSkill(w http.ResponseWriter, r *http.Request) {
	if !allowAgentGET(w, r) {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	skill := s.walletSkill(requestBaseURL(r))
	if name != skill.name {
		http.NotFound(w, r)
		return
	}
	writePlain(w, http.StatusOK, "text/markdown; charset=utf-8", skill.body)
}

func (s *walletHarnessServer) setAgentHeaders(w http.ResponseWriter, r *http.Request) {
	origin := requestBaseURL(r)
	w.Header().Set("Link", strings.Join([]string{
		`<` + origin + `/.well-known/api-catalog>; rel="api-catalog"; type="application/linkset+json"`,
		`<` + walletDocsURL + `>; rel="service-doc"; type="text/html"`,
		`<` + origin + `/.well-known/agent-skills/index.json>; rel="describedby"; type="application/json"`,
		`<` + origin + `/llms.txt>; rel="describedby"; type="text/plain"`,
		`<` + origin + `/health>; rel="status"; type="application/json"`,
	}, ", "))
}

func (s *walletHarnessServer) siteOrigin() string {
	base := strings.TrimRight(strings.TrimSpace(s.targetBaseURL), "/")
	if base != "" {
		return base
	}
	return "https://protocolsoup.com"
}

func (s *walletHarnessServer) walletSkill(origin string) walletAgentSkill {
	site := s.siteOrigin()
	body := strings.ReplaceAll(walletSkillMarkdown, "{{ORIGIN}}", origin)
	body = strings.ReplaceAll(body, "{{SITE}}", site)
	body = strings.ReplaceAll(body, "{{DOCS}}", walletDocsURL)
	return walletAgentSkill{
		name:        walletAgentSkillName,
		description: "Issue and present verifiable credentials through the ProtocolSoup OID4VCI/OID4VP wallet harness.",
		body:        body,
	}
}

func allowAgentGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	return false
}

func writePlain(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func prefersMarkdown(acceptHeader string) bool {
	if strings.TrimSpace(acceptHeader) == "" {
		return false
	}
	type acceptEntry struct {
		typ string
		q   float64
	}
	var entries []acceptEntry
	for _, part := range strings.Split(acceptHeader, ",") {
		rawType, params, _ := strings.Cut(part, ";")
		typ := strings.ToLower(strings.TrimSpace(rawType))
		if typ == "" {
			continue
		}
		quality := 1.0
		for _, parameter := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(parameter, "=")
			if !ok || strings.ToLower(strings.TrimSpace(name)) != "q" {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err == nil && parsed >= 0 && parsed <= 1 {
				quality = parsed
			}
		}
		entries = append(entries, acceptEntry{typ: typ, q: quality})
	}
	qualityOf := func(candidates ...string) float64 {
		best := 0.0
		for _, entry := range entries {
			for _, candidate := range candidates {
				if entry.typ == candidate && entry.q > best {
					best = entry.q
				}
			}
		}
		return best
	}
	markdown := qualityOf("text/markdown", "text/x-markdown")
	if markdown <= 0 {
		return false
	}
	html := qualityOf("text/html", "application/xhtml+xml", "text/*", "*/*")
	return markdown >= html
}

func walletLLMsTxt(origin, site string) string {
	return strings.Join([]string{
		"# ProtocolSoup Wallet Harness",
		"",
		"> Real OID4VCI issuance and OID4VP presentation wallet. This host is the holder, not Looking Glass and not an MCP server.",
		"",
		"## What this origin is",
		"",
		"- Issue mdoc (`mso_mdoc`) and SD-JWT VC credentials from a live issuer.",
		"- Present those credentials to a live verifier (`direct_post` / `direct_post.jwt`, including HAIP).",
		"- Looking Glass on " + site + " creates issuer/verifier traffic; this wallet performs the holder-side hops.",
		"",
		"## Start here",
		"",
		"- [API recipes](" + origin + "/llms-full.txt)",
		"- [Agent skill](" + origin + "/.well-known/agent-skills/" + walletAgentSkillName + "/SKILL.md)",
		"- [API catalog](" + origin + "/.well-known/api-catalog)",
		"- [Health](" + origin + "/health)",
		"- [Runtime docs](" + walletDocsURL + ")",
		"- [Looking Glass](" + site + "/looking-glass)",
		"- [ProtocolSoup MCP](" + site + "/mcp) — not served on this host",
		"",
		"Ask for `Accept: text/markdown` on `" + origin + "/` to receive the same recipes without executing JavaScript.",
		"",
	}, "\n")
}

const walletSkillMarkdown = `# Use the ProtocolSoup Wallet Harness

This origin is a **real OID4VCI / OID4VP wallet**. It is not Looking Glass, not a mock, and not an MCP server. MCP lives at {{SITE}}/mcp.

Human UI: {{ORIGIN}}/
Machine recipes: {{ORIGIN}}/llms-full.txt
Runtime contract: {{DOCS}}

## Isolation

Send a stable session on every API call:

    X-Wallet-Session: {opaque-id}

The browser UI uses an HttpOnly cookie instead. When driving a Looking Glass run, also pass looking_glass_session_id in the JSON body so events attach to that glass session.

Do not GET {{ORIGIN}}/authorize unless you have a live OID4VP request_uri. That path is a protocol hop, not a docs page.

## Health

    GET {{ORIGIN}}/health

Returns {"status":"ok"}. Optional commit is the deployed source SHA.

## Issue a credential (OID4VCI)

### Bootstrap against the configured ProtocolSoup issuer

    POST {{ORIGIN}}/api/issue
    Content-Type: application/json
    X-Wallet-Session: {opaque-id}

    {
      "credential_format": "mso_mdoc",
      "credential_configuration_id": "MobileDrivingLicenceMsoMdoc"
    }

Omit credential_format to use the wallet default (mso_mdoc). Set force_issue to true to mint a new credential even when the session already has one.

### Redeem an offer (Looking Glass pre-authorized path)

    POST {{ORIGIN}}/api/import
    Content-Type: application/json
    X-Wallet-Session: {opaque-id}

    {
      "offer": "openid-credential-offer://?credential_offer=...",
      "tx_code": "optional",
      "looking_glass_session_id": "optional-lg-session"
    }

Provide exactly one of offer, credential, credential_issuer, or discovery_url+resource_endpoint+scope.

A successful import returns the stored credential plus _protocol_exchanges (real wallet-to-issuer HTTP hops) and _looking_glass_events.

If the grant is authorization_code, the response includes authorization_url. Open it, then the issuer redirects to GET {{ORIGIN}}/api/oid4vci/callback.

HAIP configurations require attester JWKs on this process. Without them import returns HTTP 400 explaining that the configuration requires HAIP attestation material.

## Present a credential (OID4VP)

### One-click submit (Looking Glass / automation)

    POST {{ORIGIN}}/submit
    Content-Type: application/json

    {
      "request_id": "{verifier-request-id}",
      "request": "{signed-request-jwt-or-omit-if-request_uri-already-resolved}",
      "mode": "one_click",
      "looking_glass_session_id": "optional-lg-session"
    }

mode=one_click bootstraps a matching credential if the store has no DCQL match, builds the presentation, and POSTs to the verifier response_uri. For direct_post.jwt the wallet encrypts the Authorization Response.

Stepwise alternative: mode=stepwise with step of bootstrap, issue_credential, build_presentation, or submit_response.

### Resolve then present (wallet UI path)

    POST {{ORIGIN}}/api/resolve
    {"request_uri": "https://verifier.example/request/...", "request_uri_method": "post"}

    POST {{ORIGIN}}/api/present
    {"request_id": "...", "approve_external_trust": false}

GET {{ORIGIN}}/api/session returns the current store for the X-Wallet-Session scope.

## Related hosts

- Looking Glass: {{SITE}}/looking-glass
- Protocol catalog: {{SITE}}/api/protocols
- Agent skills on the main site: {{SITE}}/.well-known/agent-skills/index.json
- This host does not serve /mcp.
`
