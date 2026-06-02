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
	"github.com/ParleSec/ProtocolSoup/internal/gateway"
	"github.com/ParleSec/ProtocolSoup/internal/palette"
)

func main() {
	cfg := core.LoadConfig()

	var paletteSvc *palette.Service
	if cfg.PaletteDBPath != "" {
		svc, err := palette.NewService(cfg.PaletteDBPath)
		if err != nil {
			if cfg.IsProduction() {
				log.Fatalf("Failed to load palette index at %s: %v", cfg.PaletteDBPath, err)
			}
			log.Printf("Palette service disabled: %v", err)
		} else {
			paletteSvc = svc
			stats := svc.Stats()
			log.Printf("Palette service initialized from %s (%d artefacts, index v%s)",
				cfg.PaletteDBPath, stats.ArtefactCount, stats.IndexVersion)
		}
	}

	upstreams := []gateway.UpstreamConfig{
		{Name: "federation", BaseURL: strings.TrimSpace(os.Getenv("FEDERATION_SERVICE_URL"))},
		{Name: "scim", BaseURL: strings.TrimSpace(os.Getenv("SCIM_SERVICE_URL"))},
		{Name: "spiffe", BaseURL: strings.TrimSpace(os.Getenv("SPIFFE_SERVICE_URL"))},
		{Name: "ssf", BaseURL: strings.TrimSpace(os.Getenv("SSF_SERVICE_URL"))},
	}

	gw, err := gateway.NewGateway(gateway.Config{
		ListenAddr:          cfg.ListenAddr,
		BaseURL:             cfg.BaseURL,
		Upstreams:           upstreams,
		CORSOrigins:         cfg.CORSOrigins,
		RefreshInterval:     envDuration("GATEWAY_REFRESH_INTERVAL", 30*time.Second),
		StartupRetryInitial: envDuration("GATEWAY_STARTUP_RETRY_INITIAL", 2*time.Second),
		StartupRetryMax:     envDuration("GATEWAY_STARTUP_RETRY_MAX", 30*time.Second),
		RequestTimeout:      envDuration("GATEWAY_REQUEST_TIMEOUT", 5*time.Second),
		Palette:             paletteSvc,
	})
	if err != nil {
		log.Fatalf("Failed to initialize gateway: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.StartRefreshLoop(ctx)

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      gw.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Gateway starting on %s", cfg.ListenAddr)
		log.Printf("Gateway API available at %s/api", cfg.BaseURL)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gateway failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down gateway...")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Gateway forced to shutdown: %v", err)
	}

	log.Println("Gateway exited gracefully")
}

func envDuration(key string, defaultValue time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}
