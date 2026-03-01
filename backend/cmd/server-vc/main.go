package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vp"
)

func main() {
	enableLookingGlass := envBool("VC_LOOKING_GLASS", true)

	bootstrap, err := core.Bootstrap(core.BootstrapOptions{
		EnableKeySet:       true,
		EnableMockIdP:      true,
		EnableLookingGlass: enableLookingGlass,
	})
	if err != nil {
		log.Fatalf("Failed to bootstrap VC service: %v", err)
	}

	registry := plugin.NewRegistry()
	pluginConfig := bootstrap.PluginConfig

	oid4vciPlugin := oid4vci.NewPlugin()
	if err := registry.Register(oid4vciPlugin); err != nil {
		log.Fatalf("Failed to register OID4VCI plugin: %v", err)
	}

	oid4vpPlugin := oid4vp.NewPlugin()
	if err := registry.Register(oid4vpPlugin); err != nil {
		log.Fatalf("Failed to register OID4VP plugin: %v", err)
	}

	ctx := context.Background()
	if err := registry.InitializeAll(ctx, pluginConfig); err != nil {
		log.Fatalf("Failed to initialize plugins: %v", err)
	}
	log.Printf("Initialized %d protocol plugins", len(registry.List()))

	server := core.NewServer(bootstrap.Config, registry, bootstrap.LookingGlass, bootstrap.KeySet)
	httpServer := &http.Server{
		Addr:         bootstrap.Config.ListenAddr,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("VC service starting on %s", bootstrap.Config.ListenAddr)
		log.Printf("API available at %s/api", bootstrap.Config.BaseURL)
		if bootstrap.LookingGlass != nil {
			log.Printf("Looking Glass WebSocket at %s/ws/lookingglass", bootstrap.Config.BaseURL)
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down VC service...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registry.ShutdownAll(shutdownCtx); err != nil {
		log.Printf("Plugin shutdown error: %v", err)
	}

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("VC service exited gracefully")
}

func envBool(key string, defaultValue bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}
