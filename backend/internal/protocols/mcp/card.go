package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Media types for the two discovery documents.
const (
	serverCardMediaType = "application/mcp-server-card+json"
	aiCatalogMediaType  = "application/ai-catalog+json"
)

// serverCardSchema is the only value the Server Card schema accepts for
// $schema. Schema URLs are versioned by their vN segment, not by date.
const serverCardSchema = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"

// cardCacheControl is the freshness the discovery spec asks hosts to declare.
const cardCacheControl = "public, max-age=3600"

// serverCard is the SEP-2127 Server Card: identity, transport, and supported
// protocol versions, and nothing else.
//
// The card deliberately does not enumerate tools, resources or prompts. That
// omission is a safety property: a static document fetched before the client
// connects must not become something a client trusts for access-control
// decisions. Primitives are discovered at runtime through tools/list.
type serverCard struct {
	Schema      string      `json:"$schema"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Title       string      `json:"title,omitempty"`
	WebsiteURL  string      `json:"websiteUrl,omitempty"`
	Repository  *repository `json:"repository,omitempty"`
	Remotes     []remote    `json:"remotes,omitempty"`
}

type repository struct {
	URL       string `json:"url"`
	Source    string `json:"source"`
	Subfolder string `json:"subfolder,omitempty"`
}

type remote struct {
	Type                      string   `json:"type"`
	URL                       string   `json:"url"`
	SupportedProtocolVersions []string `json:"supportedProtocolVersions,omitempty"`
}

// cardDescription is capped at 100 characters by the schema.
const cardDescription = "Read-only tools over a sandbox that runs real authentication and identity protocols"

// buildServerCard assembles the canonical card.
func (p *Plugin) buildServerCard() serverCard {
	return serverCard{
		Schema:      serverCardSchema,
		Name:        serverName,
		Version:     serverVersion,
		Description: cardDescription,
		Title:       "ProtocolSoup",
		WebsiteURL:  p.origin(),
		Repository: &repository{
			URL:       "https://github.com/ParleSec/ProtocolSoup",
			Source:    "github",
			Subfolder: "ProtocolLens/backend/internal/protocols/mcp",
		},
		Remotes: []remote{
			{
				Type:                      "streamable-http",
				URL:                       p.endpoint(),
				SupportedProtocolVersions: []string{protocolVersion},
			},
		},
	}
}

// handleServerCard serves the canonical card at the location the discovery
// spec reserves: the /server-card suffix on the server's own endpoint.
func (p *Plugin) handleServerCard(w http.ResponseWriter, r *http.Request) {
	p.writeDocument(w, r, p.buildServerCard(), serverCardMediaType)
}

// handleAICatalog serves the site-wide index of AI artifacts. This is the
// document domain-level discovery is specified to start from, and the only
// .well-known location the spec endorses for it.
func (p *Plugin) handleAICatalog(w http.ResponseWriter, r *http.Request) {
	catalog := map[string]interface{}{
		"specVersion": "1.0",
		"entries": []map[string]interface{}{
			{
				"identifier": p.catalogIdentifier(),
				"type":       serverCardMediaType,
				"url":        p.endpoint() + "/server-card",
			},
		},
	}

	p.writeDocument(w, r, catalog, aiCatalogMediaType)
}

// catalogIdentifier builds the domain-anchored URN an AI Catalog entry uses,
// in the form urn:air:{publisher}:{namespace}:{name}.
func (p *Plugin) catalogIdentifier() string {
	publisher := "protocolsoup.com"
	if parsed, err := url.Parse(p.origin()); err == nil && parsed.Hostname() != "" {
		publisher = parsed.Hostname()
	}

	name := serverName
	if _, after, found := strings.Cut(serverName, "/"); found {
		name = after
	}

	return "urn:air:" + publisher + ":mcp:" + name
}

// writeDocument serves a discovery document with the caching, validation and
// CORS behavior the spec asks for: an entity tag so an unchanged document is
// answered with 304, a freshness lifetime, and open CORS, which is safe
// because these documents carry only public read-only metadata.
func (p *Plugin) writeDocument(w http.ResponseWriter, r *http.Request, document interface{}, mediaType string) {
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		http.Error(w, "could not build the document", http.StatusInternalServerError)
		return
	}

	digest := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, If-None-Match")
	w.Header().Set("Access-Control-Expose-Headers", "ETag")
	w.Header().Set("Cache-Control", cardCacheControl)
	w.Header().Set("ETag", etag)

	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// matchesETag reports whether an If-None-Match header selects the given tag.
func matchesETag(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}

	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}
