package saml

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/idp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/sp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/go-chi/chi/v5"
)

// Plugin implements the SAML 2.0 protocol plugin. It hosts two separate SAML
// entities, an identity provider under /saml/idp (package idp) and a service
// provider under /saml/sp (package sp), each with its own entityID, signing
// key and metadata. The two packages cannot import each other: the roles learn
// about each other only from the metadata each publishes at its entityID, and
// exchange messages only through the SAML bindings.
type Plugin struct {
	*plugin.BasePlugin
	mockIdP    *mockidp.MockIdP
	events     binding.Events
	httpClient *http.Client // fetches peer metadata; nil uses a 10-second client
	idp        *idp.IdentityProvider
	sp         *sp.ServiceProvider
}

// NewPlugin creates a new SAML 2.0 plugin
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "saml",
			Name:        "SAML 2.0",
			Version:     "2.0.0",
			Description: "Security Assertion Markup Language 2.0 for federated identity and SSO",
			Tags:        []string{"federation", "sso", "xml", "assertions", "identity"},
			RFCs:        []string{"SAML 2.0 Core", "SAML 2.0 Bindings", "SAML 2.0 Profiles", "SAML 2.0 Metadata"},
		}),
	}
}

// Initialize creates both entities. Their keys and certificates persist under
// {DataDir}/saml when a data directory is configured, so the certificates in
// published metadata survive restarts.
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	baseURL := strings.TrimRight(config.BaseURL, "/")
	if users, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIdP = users
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.events = binding.Events{Engine: lg}
	}

	credentialDir := ""
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		credentialDir = filepath.Join(dataDir, "saml")
	}
	// Each entityID is the URL its metadata is published at (SAML Metadata
	// Section 4.1.1), so each role resolves the other by dereferencing it.
	idpEntityID := baseURL + "/saml/idp/metadata"
	spEntityID := baseURL + "/saml/sp/metadata"

	idpCreds, err := xmldsig.LoadOrCreateCredentials(credentialDir, "idp", idpEntityID)
	if err != nil {
		return fmt.Errorf("SAML IdP credentials: %w", err)
	}
	spCreds, err := xmldsig.LoadOrCreateCredentials(credentialDir, "sp", spEntityID)
	if err != nil {
		return fmt.Errorf("SAML SP credentials: %w", err)
	}

	client := p.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Each role gets its own metadata resolver, so they share no state.
	p.idp = idp.New(idp.Config{
		EntityID:    idpEntityID,
		SSOURL:      baseURL + "/saml/idp/sso",
		SLOURL:      baseURL + "/saml/idp/slo",
		LoginURL:    baseURL + "/saml/idp/login",
		SPEntityID:  spEntityID,
		Credentials: idpCreds,
		Resolver:    metadata.NewResolver(client),
		Users:       p.mockIdP,
		Events:      p.events,
	})
	p.sp = sp.New(sp.Config{
		EntityID:    spEntityID,
		ACSURL:      baseURL + "/saml/sp/acs",
		SLOURL:      baseURL + "/saml/sp/slo",
		IdPEntityID: idpEntityID,
		Credentials: spCreds,
		Resolver:    metadata.NewResolver(client),
		Events:      p.events,
	})
	return nil
}

// Shutdown shuts down the plugin
func (p *Plugin) Shutdown(ctx context.Context) error {
	return nil
}

// RegisterRoutes registers the plugin's HTTP routes under /saml.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	router.Route("/idp", p.idp.Routes)
	router.Route("/sp", p.sp.Routes)

	router.Get("/demo/users", p.handleListUsers)
	router.Get("/demo/sessions", p.handleListSessions)

	router.Get("/looking-glass/authn-request", p.handleLookingGlassCreateAuthnRequest)
	router.Post("/looking-glass/authenticate", p.handleLookingGlassAuthenticate)
	router.Get("/looking-glass/logout-request", p.handleLookingGlassCreateLogoutRequest)
	router.Post("/looking-glass/logout", p.handleLookingGlassProcessLogout)
}
