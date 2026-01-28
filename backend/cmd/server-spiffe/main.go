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
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/spiffe"
)

func main() {
	bootstrap, err := core.Bootstrap(core.BootstrapOptions{
		EnableKeySet:       false,
		EnableMockIdP:      false,
		EnableLookingGlass: true,
	})
	if err != nil {
		log.Fatalf("Failed to bootstrap SPIFFE service: %v", err)
	}

	registry := plugin.NewRegistry()
	pluginConfig := bootstrap.PluginConfig

	spiffePlugin := spiffe.NewPlugin()
	if err := registry.Register(spiffePlugin); err != nil {
		log.Fatalf("Failed to register SPIFFE plugin: %v", err)
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
		log.Printf("SPIFFE service starting on %s", bootstrap.Config.ListenAddr)
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
	log.Println("Shutting down SPIFFE service...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registry.ShutdownAll(shutdownCtx); err != nil {
		log.Printf("Plugin shutdown error: %v", err)
	}

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("SPIFFE service exited gracefully")
}
