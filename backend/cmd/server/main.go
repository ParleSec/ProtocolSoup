package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oauth2"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oidc"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/scim"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/spiffe"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/ssf"
)

func main() {
	// Load configuration
	cfg := core.LoadConfig()

	// Initialize cryptographic key set
	keySet, err := crypto.NewKeySet()
	if err != nil {
		log.Fatalf("Failed to initialize key set: %v", err)
	}
	log.Println("Cryptographic keys initialized")

	// Initialize mock identity provider
	idp := mockidp.NewMockIdP(keySet)
	log.Println("Mock Identity Provider initialized")

	// Initialize looking glass engine
	lgEngine := lookingglass.NewEngine()
	log.Println("Looking Glass engine initialized")

	// Initialize plugin registry
	registry := plugin.NewRegistry()

	// Create plugin configuration
	pluginConfig := plugin.PluginConfig{
		BaseURL:      cfg.BaseURL,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lgEngine,
	}

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

	// Initialize all plugins
	ctx := context.Background()
	if err := registry.InitializeAll(ctx, pluginConfig); err != nil {
		log.Fatalf("Failed to initialize plugins: %v", err)
	}
	log.Printf("Initialized %d protocol plugins", len(registry.List()))

	// Create and configure server
	server := core.NewServer(cfg, registry, lgEngine, keySet)
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", cfg.ListenAddr)
		log.Printf("API available at %s/api", cfg.BaseURL)
		log.Printf("Looking Glass WebSocket at %s/ws/lookingglass", cfg.BaseURL)
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

