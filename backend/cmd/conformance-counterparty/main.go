// Command conformance-counterparty is the deliberately broken peer the
// conformance capture points the hosted wallet at. Each scenario route serves
// one invalid protocol message, so a requirement page can show the wallet
// refusing it. It is not part of a ProtocolSoup deployment: self-hosters do
// not need it, and no product UI links to it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// notice labels every response, so nothing this service serves can be
// mistaken for a real issuer or verifier.
const notice = "ProtocolSoup conformance counterparty: serves deliberately invalid protocol messages for conformance capture. Do not use as an issuer or verifier."

type config struct {
	listenAddr string
	// baseURL is the public origin scenario messages name as their own
	// identifier (credential_issuer, response_uri, and so on).
	baseURL string
	commit  string
}

func loadConfig() (config, error) {
	cfg := config{
		listenAddr: firstNonEmpty(os.Getenv("COUNTERPARTY_LISTEN_ADDR"), ":8080"),
		baseURL:    strings.TrimRight(firstNonEmpty(os.Getenv("COUNTERPARTY_BASE_URL"), "http://localhost:8080"), "/"),
		commit:     strings.TrimSpace(os.Getenv("BUILD_COMMIT")),
	}
	parsed, err := url.Parse(cfg.baseURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return config{}, fmt.Errorf("COUNTERPARTY_BASE_URL must be an origin such as https://protocolsoup-counterparty.fly.dev, got %q", cfg.baseURL)
	}
	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("conformance-counterparty: %v", err)
	}
	handler, err := newServer(cfg)
	if err != nil {
		log.Fatalf("conformance-counterparty: %v", err)
	}
	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("conformance-counterparty: listening on %s as %s", cfg.listenAddr, cfg.baseURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("conformance-counterparty: %v", err)
	}
}

// newServer builds the counterparty's routes: health, an index that says
// what this service is, and every scenario route.
func newServer(cfg config) (http.Handler, error) {
	c, err := newCounterparty(cfg)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	c.registerVerifierRoutes(mux)
	c.registerIssuerRoutes(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "%s\n\nScenario routes live under /scenarios/ and each serves the invalid message one requirement's failing case needs.\n", notice)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		health := map[string]string{"status": "ok"}
		if cfg.commit != "" {
			health["commit"] = cfg.commit
		}
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	return labelled(mux), nil
}

// labelled adds the counterparty notice to every response and keeps search
// engines from indexing it.
func labelled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Conformance-Counterparty", notice)
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "response serialization failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
