package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

// Config defines gateway configuration.
type Config struct {
	ListenAddr          string
	BaseURL             string
	Upstreams           []UpstreamConfig
	CORSOrigins         []string
	RefreshInterval     time.Duration
	StartupRetryInitial time.Duration
	StartupRetryMax     time.Duration
	RequestTimeout      time.Duration
}

// UpstreamConfig represents an upstream service.
type UpstreamConfig struct {
	Name    string
	BaseURL string
}

// ProtocolSummary mirrors the backend protocol summary payload.
type ProtocolSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

type protocolListResponse struct {
	Protocols []ProtocolSummary `json:"protocols"`
}

type sessionsResponse struct {
	Sessions []map[string]interface{} `json:"sessions"`
}

// Upstream represents a parsed upstream with a reverse proxy.
type Upstream struct {
	Name    string
	BaseURL string
	URL     *url.URL
	Proxy   *httputil.ReverseProxy
}

// Gateway routes API and protocol traffic to upstream services.
type Gateway struct {
	cfg Config

	client    *http.Client
	upstreams map[string]*Upstream
	order     []string

	mu               sync.RWMutex
	protocols        map[string]ProtocolSummary
	protocolServices map[string]string
	sessions         map[string]string
	lastRefresh      time.Time
}

// NewGateway constructs a gateway from config.
func NewGateway(cfg Config) (*Gateway, error) {
	upstreams := make(map[string]*Upstream)
	order := make([]string, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		if u.Name == "" || u.BaseURL == "" {
			continue
		}
		parsed, err := url.Parse(u.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL for %s: %w", u.Name, err)
		}
		proxy := httputil.NewSingleHostReverseProxy(parsed)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": "Upstream unavailable",
			})
		}

		upstreams[u.Name] = &Upstream{
			Name:    u.Name,
			BaseURL: strings.TrimRight(u.BaseURL, "/"),
			URL:     parsed,
			Proxy:   proxy,
		}
		order = append(order, u.Name)
	}

	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Second
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Second
	}
	if cfg.StartupRetryInitial == 0 {
		cfg.StartupRetryInitial = 2 * time.Second
	}
	if cfg.StartupRetryMax == 0 {
		cfg.StartupRetryMax = 30 * time.Second
	}

	return &Gateway{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
		upstreams:        upstreams,
		order:            order,
		protocols:        make(map[string]ProtocolSummary),
		protocolServices: make(map[string]string),
		sessions:         make(map[string]string),
	}, nil
}

// Router returns the gateway HTTP handler.
func (g *Gateway) Router() http.Handler {
	r := chi.NewRouter()

	if len(g.cfg.CORSOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   g.cfg.CORSOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "If-Match", "If-None-Match"},
			ExposedHeaders:   []string{"Link", "X-Request-ID", "ETag", "Location"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	r.Get("/health", g.handleHealth)
	r.Get("/health/upstreams", g.handleUpstreamsHealth)

	r.Get("/api", g.handleAPIIndex)
	r.Route("/api", func(r chi.Router) {
		r.Get("/", g.handleAPIIndex)

		r.Get("/protocols", g.handleProtocols)
		r.Get("/protocols/{id}", g.handleProtocol)
		r.Get("/protocols/{id}/flows", g.handleProtocolFlows)
		r.Post("/protocols/{id}/demo/{flow}", g.handleStartDemo)

		r.Post("/lookingglass/decode", g.handleDecodeToken)
		r.Get("/lookingglass/sessions", g.handleListSessions)
		r.Get("/lookingglass/sessions/{id}", g.handleGetSession)
	})

	r.Get("/ws/lookingglass/{session}", g.handleLookingGlassWS)

	r.Route("/{protocolID}", func(r chi.Router) {
		r.Handle("/*", http.HandlerFunc(g.handleProtocolRoute))
		r.Handle("/", http.HandlerFunc(g.handleProtocolRoute))
	})

	return r
}

// StartRefreshLoop begins background refresh with startup retry.
func (g *Gateway) StartRefreshLoop(ctx context.Context) {
	go func() {
		backoff := g.cfg.StartupRetryInitial
		for {
			if ctx.Err() != nil {
				return
			}
			count, err := g.RefreshProtocols(ctx)
			if err != nil {
				log.Printf("Gateway refresh error: %v", err)
			}
			if count > 0 {
				break
			}
			log.Printf("Gateway waiting for upstreams; retrying in %s", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > g.cfg.StartupRetryMax {
				backoff = g.cfg.StartupRetryMax
			}
		}

		ticker := time.NewTicker(g.cfg.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := g.RefreshProtocols(ctx); err != nil {
					log.Printf("Gateway refresh error: %v", err)
				}
			}
		}
	}()
}

// RefreshProtocols refreshes the protocol map from upstreams.
func (g *Gateway) RefreshProtocols(ctx context.Context) (int, error) {
	if len(g.upstreams) == 0 {
		return 0, nil
	}

	newProtocols := make(map[string]ProtocolSummary)
	newProtocolServices := make(map[string]string)
	successes := 0

	for _, name := range g.order {
		upstream, ok := g.upstreams[name]
		if !ok {
			continue
		}
		resp, err := g.fetchProtocols(ctx, upstream)
		if err != nil {
			log.Printf("Gateway: upstream %s protocols error: %v", upstream.Name, err)
			continue
		}
		successes++
		for _, proto := range resp.Protocols {
			if _, exists := newProtocolServices[proto.ID]; exists {
				log.Printf("Gateway: protocol ID %s already mapped, skipping %s", proto.ID, upstream.Name)
				continue
			}
			newProtocols[proto.ID] = proto
			newProtocolServices[proto.ID] = upstream.Name
		}
	}

	if successes > 0 {
		g.mu.Lock()
		g.protocols = newProtocols
		g.protocolServices = newProtocolServices
		g.lastRefresh = time.Now()
		g.mu.Unlock()
	}

	return successes, nil
}

func (g *Gateway) fetchProtocols(ctx context.Context, upstream *Upstream) (*protocolListResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.BaseURL+"/api/protocols", nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var payload protocolListResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (g *Gateway) ensureProtocols(ctx context.Context) {
	g.mu.RLock()
	needsRefresh := g.lastRefresh.IsZero() || time.Since(g.lastRefresh) > g.cfg.RefreshInterval
	hasProtocols := len(g.protocols) > 0
	g.mu.RUnlock()

	if needsRefresh || !hasProtocols {
		if _, err := g.RefreshProtocols(ctx); err != nil {
			log.Printf("Gateway refresh error: %v", err)
		}
	}
}

func (g *Gateway) getProtocolService(protocolID string) (*Upstream, bool) {
	g.mu.RLock()
	serviceName, ok := g.protocolServices[protocolID]
	g.mu.RUnlock()
	if !ok {
		return nil, false
	}
	upstream, ok := g.upstreams[serviceName]
	return upstream, ok
}

func (g *Gateway) setSession(sessionID string, upstream *Upstream) {
	g.mu.Lock()
	g.sessions[sessionID] = upstream.Name
	g.mu.Unlock()
}

func (g *Gateway) getSession(sessionID string) (*Upstream, bool) {
	g.mu.RLock()
	serviceName, ok := g.sessions[sessionID]
	g.mu.RUnlock()
	if !ok {
		return nil, false
	}
	upstream, ok := g.upstreams[serviceName]
	return upstream, ok
}

func (g *Gateway) listProtocols() []ProtocolSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()
	protocols := make([]ProtocolSummary, 0, len(g.protocols))
	for _, proto := range g.protocols {
		protocols = append(protocols, proto)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].ID < protocols[j].ID
	})
	return protocols
}

func (g *Gateway) proxy(upstream *Upstream, w http.ResponseWriter, r *http.Request) {
	upstream.Proxy.ServeHTTP(w, r)
}

func (g *Gateway) cloneRequest(ctx context.Context, r *http.Request, targetBase string) (*http.Request, []byte, error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, err
		}
	}

	targetURL := targetBase + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header = r.Header.Clone()
	req.Host = ""
	return req, body, nil
}

func (g *Gateway) writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	writeJSON(w, status, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
