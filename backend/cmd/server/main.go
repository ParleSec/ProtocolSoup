package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/core"
	"github.com/ParleSec/ProtocolSoup/internal/palette"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/agentauth"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/mcp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oidc"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/scim"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/spiffe"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/ssf"
)

func main() {
	bootstrap, err := core.Bootstrap(core.BootstrapOptions{
		EnableKeySet:       true,
		EnableMockIdP:      true,
		EnableLookingGlass: true,
		EnablePalette:      true,
	})
	if err != nil {
		log.Fatalf("Failed to bootstrap server: %v", err)
	}

	// Initialize plugin registry
	registry := plugin.NewRegistry()

	// Create plugin configuration
	pluginConfig := bootstrap.PluginConfig

	// Register OAuth 2.0 plugin
	oauth2Plugin := oauth2.NewPlugin()
	if err := registry.Register(oauth2Plugin); err != nil {
		log.Fatalf("Failed to register OAuth 2.0 plugin: %v", err)
	}

	// Register OIDC plugin
	oidcPlugin := oidc.NewPlugin(oauth2Plugin)
	if err := registry.Register(oidcPlugin); err != nil {
		log.Fatalf("Failed to register OIDC plugin: %v", err)
	}

	// Register agentic registration (auth.md) plugin. The OP advertises its
	// endpoints in the agent_auth block of the origin's RFC 8414 metadata, so
	// an agent that resolves the origin issuer discovers where to register.
	agentAuthPlugin := agentauth.NewPlugin()
	if err := registry.Register(agentAuthPlugin); err != nil {
		log.Fatalf("Failed to register agentic registration plugin: %v", err)
	}
	oidcPlugin.SetAgentAuthProvider(agentAuthPlugin)

	// Register OID4VCI plugin
	oid4vciPlugin := oid4vci.NewPlugin()
	if err := registry.Register(oid4vciPlugin); err != nil {
		log.Fatalf("Failed to register OID4VCI plugin: %v", err)
	}

	// Register OID4VP plugin
	oid4vpPlugin := oid4vp.NewPlugin()
	if err := registry.Register(oid4vpPlugin); err != nil {
		log.Fatalf("Failed to register OID4VP plugin: %v", err)
	}

	// Register SAML 2.0 plugin
	samlPlugin := saml.NewPlugin()
	if err := registry.Register(samlPlugin); err != nil {
		log.Fatalf("Failed to register SAML plugin: %v", err)
	}

	// Register SPIFFE/SPIRE plugin
	spiffePlugin := spiffe.NewPlugin()
	if err := registry.Register(spiffePlugin); err != nil {
		log.Fatalf("Failed to register SPIFFE plugin: %v", err)
	}

	// Register SCIM 2.0 plugin
	scimPlugin := scim.NewPlugin()
	if err := registry.Register(scimPlugin); err != nil {
		log.Fatalf("Failed to register SCIM plugin: %v", err)
	}

	// Register SSF (Shared Signals Framework) plugin
	ssfPlugin := ssf.NewPlugin()
	if err := registry.Register(ssfPlugin); err != nil {
		log.Fatalf("Failed to register SSF plugin: %v", err)
	}

	// Register the remote MCP server. Its tools read the registry, so it is
	// registered last and handed the registry it will read from.
	mcpPlugin := mcp.NewPlugin()
	if err := registry.Register(mcpPlugin); err != nil {
		log.Fatalf("Failed to register MCP plugin: %v", err)
	}
	mcpPlugin.SetRegistry(registry)

	// Initialize all plugins
	ctx := context.Background()
	if err := registry.InitializeAll(ctx, pluginConfig); err != nil {
		log.Fatalf("Failed to initialize plugins: %v", err)
	}
	log.Printf("Initialized %d protocol plugins", len(registry.List()))

	// Create and configure server
	server := core.NewServer(bootstrap.Config, registry, bootstrap.LookingGlass, bootstrap.KeySet).
		WithPalette(bootstrap.Palette).
		WithConformance(loadConformanceCatalogue(bootstrap.Config, bootstrap.Palette))
	httpServer := &http.Server{
		Addr:         bootstrap.Config.ListenAddr,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", bootstrap.Config.ListenAddr)
		log.Printf("API available at %s/api", bootstrap.Config.BaseURL)
		if bootstrap.LookingGlass != nil {
			log.Printf("Looking Glass WebSocket at %s/ws/lookingglass", bootstrap.Config.BaseURL)
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown plugins
	if err := registry.ShutdownAll(shutdownCtx); err != nil {
		log.Printf("Plugin shutdown error: %v", err)
	}

	// Shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
}

// loadConformanceCatalogue builds the requirement catalogue from the embedded
// registry and, when configured and readable, the build's conformance
// report. A missing or unusable report is logged once and never blocks
// boot: pages then render "Not evaluated for this build".
//
// The palette service supplies requirement explainers (spec-assertion
// artefacts). When the palette is disabled no requirement has an explainer,
// so none is indexable.
func loadConformanceCatalogue(cfg *core.Config, explainers *palette.Service) *conformance.Catalogue {
	registry, err := conformance.Embedded()
	if err != nil {
		log.Printf("Conformance catalogue disabled: embedded registry invalid: %v", err)
		return nil
	}

	var report *conformance.Report
	if cfg.ConformanceReportPath == "" {
		log.Println("Conformance report not configured (CONFORMANCE_REPORT); requirement pages will show no verdicts")
	} else if loaded, err := conformance.LoadReport(cfg.ConformanceReportPath); err != nil {
		log.Printf("Conformance report unavailable at %s: %v; requirement pages will show no verdicts", cfg.ConformanceReportPath, err)
	} else {
		report = loaded
	}

	// A nil *palette.Service must become a nil interface, not an interface
	// holding a nil pointer, or the catalogue would call through it.
	var source conformance.ExplainerSource
	if explainers != nil {
		source = explainers
	}
	catalogue := conformance.NewCatalogue(registry, report, cfg.BuildCommit, source)
	if report != nil && !catalogue.ReportValid() {
		log.Printf("Conformance report at %s does not match this build (report commit %q, dirty=%t, BUILD_COMMIT %q); requirement pages will show no verdicts",
			cfg.ConformanceReportPath, report.Commit, report.Dirty, cfg.BuildCommit)
	}
	return catalogue
}
