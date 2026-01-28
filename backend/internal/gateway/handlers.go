package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type healthResponse struct {
	Status      string `json:"status"`
	Ready       bool   `json:"ready"`
	LastRefresh string `json:"last_refresh,omitempty"`
}

type upstreamHealth struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	ProtocolCount  int    `json:"protocol_count"`
	LastChecked    string `json:"last_checked"`
	HealthEndpoint string `json:"health_endpoint"`
}

type upstreamHealthResponse struct {
	Status    string           `json:"status"`
	Ready     bool             `json:"ready"`
	Upstreams []upstreamHealth `json:"upstreams"`
}

type apiIndexResponse struct {
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Ready     bool              `json:"ready"`
	Protocols []string          `json:"protocols"`
	Endpoints map[string]string `json:"endpoints"`
}

func (g *Gateway) handleAPIIndex(w http.ResponseWriter, r *http.Request) {
	g.ensureProtocols(r.Context())
	protocolSummaries := g.listProtocols()
	protocols := make([]string, 0, len(protocolSummaries))
	for _, proto := range protocolSummaries {
		protocols = append(protocols, proto.ID)
	}

	endpoints := map[string]string{
		"protocols":        "/api/protocols",
		"health":           "/health",
		"health_upstreams": "/health/upstreams",
		"flows":            "/api/protocols/{id}/flows",
		"demo":             "/api/protocols/{id}/demo/{flow}",
		"lookingglass":     "/api/lookingglass",
		"lookingglass_ws":  "/ws/lookingglass/{session}",
	}

	g.writeJSON(w, http.StatusOK, apiIndexResponse{
		Service:   "protocol-lens-gateway",
		Version:   "1.0.0",
		Ready:     g.isReady(),
		Protocols: protocols,
		Endpoints: endpoints,
	})
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	ready := g.isReady()
	resp := healthResponse{
		Status: "ok",
		Ready:  ready,
	}
	if last := g.lastRefreshTime(); !last.IsZero() {
		resp.LastRefresh = last.UTC().Format(time.RFC3339)
	}
	g.writeJSON(w, http.StatusOK, resp)
}

func (g *Gateway) handleUpstreamsHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), g.cfg.RequestTimeout)
	defer cancel()

	ready := false
	results := make([]upstreamHealth, 0, len(g.upstreams))

	for _, name := range g.order {
		upstream, ok := g.upstreams[name]
		if !ok {
			continue
		}
		status := upstreamHealth{
			Name:           upstream.Name,
			URL:            upstream.BaseURL,
			ProtocolCount:  g.protocolCountForService(upstream.Name),
			LastChecked:    time.Now().UTC().Format(time.RFC3339),
			HealthEndpoint: upstream.BaseURL + "/health",
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.BaseURL+"/health", nil)
		if err != nil {
			status.Status = "error"
			status.Error = err.Error()
			results = append(results, status)
			continue
		}
		resp, err := g.client.Do(req)
		if err != nil {
			status.Status = "error"
			status.Error = err.Error()
			results = append(results, status)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			status.Status = "healthy"
			ready = true
		} else {
			status.Status = "unhealthy"
			status.Error = "status " + resp.Status
		}
		results = append(results, status)
	}

	if len(results) == 0 {
		g.writeJSON(w, http.StatusServiceUnavailable, upstreamHealthResponse{
			Status:    "no_upstreams",
			Ready:     false,
			Upstreams: results,
		})
		return
	}

	status := "degraded"
	code := http.StatusServiceUnavailable
	if ready {
		status = "ok"
		code = http.StatusOK
	}
	g.writeJSON(w, code, upstreamHealthResponse{
		Status:    status,
		Ready:     ready,
		Upstreams: results,
	})
}

func (g *Gateway) handleProtocols(w http.ResponseWriter, r *http.Request) {
	g.ensureProtocols(r.Context())
	protocols := g.listProtocols()
	if len(protocols) == 0 {
		g.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "No upstream protocols available",
		})
		return
	}
	g.writeJSON(w, http.StatusOK, protocolListResponse{Protocols: protocols})
}

func (g *Gateway) handleProtocol(w http.ResponseWriter, r *http.Request) {
	protocolID := chi.URLParam(r, "id")
	upstream := g.findProtocolUpstream(r.Context(), protocolID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Protocol not found",
		})
		return
	}
	g.proxy(upstream, w, r)
}

func (g *Gateway) handleProtocolFlows(w http.ResponseWriter, r *http.Request) {
	protocolID := chi.URLParam(r, "id")
	upstream := g.findProtocolUpstream(r.Context(), protocolID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Protocol not found",
		})
		return
	}
	g.proxy(upstream, w, r)
}

func (g *Gateway) handleStartDemo(w http.ResponseWriter, r *http.Request) {
	protocolID := chi.URLParam(r, "id")
	upstream := g.findProtocolUpstream(r.Context(), protocolID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Protocol not found",
		})
		return
	}

	req, _, err := g.cloneRequest(r.Context(), r, upstream.BaseURL)
	if err != nil {
		g.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	resp, err := g.client.Do(req)
	if err != nil {
		g.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		copyResponse(w, resp)
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		g.writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Invalid upstream response"})
		return
	}

	if sessionID, ok := payload["session_id"].(string); ok && sessionID != "" {
		g.setSession(sessionID, upstream)
		payload["ws_endpoint"] = "/ws/lookingglass/" + sessionID
	}

	g.writeJSON(w, http.StatusOK, payload)
}

func (g *Gateway) handleDecodeToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		g.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	for _, upstream := range g.orderedUpstreams() {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.BaseURL+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header = r.Header.Clone()
		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusMethodNotAllowed {
			resp.Body.Close()
			continue
		}
		defer resp.Body.Close()
		copyResponse(w, resp)
		return
	}

	g.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
		"error": "No upstream decode endpoint available",
	})
}

func (g *Gateway) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := make([]map[string]interface{}, 0)

	for _, upstream := range g.orderedUpstreams() {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream.BaseURL+r.URL.Path, nil)
		if err != nil {
			continue
		}
		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}
		if resp.Body == nil {
			continue
		}

		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			continue
		}

		var payload sessionsResponse
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		for _, session := range payload.Sessions {
			if id, ok := session["id"].(string); ok && id != "" {
				g.setSession(id, upstream)
			}
			sessions = append(sessions, session)
		}
	}

	g.writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
	})
}

func (g *Gateway) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if upstream, ok := g.getSession(sessionID); ok {
		g.proxy(upstream, w, r)
		return
	}

	upstream := g.resolveSession(r.Context(), sessionID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{"error": "Session not found"})
		return
	}
	g.proxy(upstream, w, r)
}

func (g *Gateway) handleLookingGlassWS(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session")
	if upstream, ok := g.getSession(sessionID); ok {
		g.proxy(upstream, w, r)
		return
	}

	upstream := g.resolveSession(r.Context(), sessionID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{"error": "Session not found"})
		return
	}
	g.proxy(upstream, w, r)
}

func (g *Gateway) handleProtocolRoute(w http.ResponseWriter, r *http.Request) {
	protocolID := chi.URLParam(r, "protocolID")
	if protocolID == "" || strings.HasPrefix(protocolID, "api") || strings.HasPrefix(protocolID, "health") || strings.HasPrefix(protocolID, "ws") {
		http.NotFound(w, r)
		return
	}
	upstream := g.findProtocolUpstream(r.Context(), protocolID)
	if upstream == nil {
		g.writeJSON(w, http.StatusNotFound, map[string]string{"error": "Protocol not found"})
		return
	}
	g.proxy(upstream, w, r)
}

func (g *Gateway) findProtocolUpstream(ctx context.Context, protocolID string) *Upstream {
	if protocolID == "" {
		return nil
	}
	if upstream, ok := g.getProtocolService(protocolID); ok {
		return upstream
	}
	g.ensureProtocols(ctx)
	if upstream, ok := g.getProtocolService(protocolID); ok {
		return upstream
	}
	return nil
}

func (g *Gateway) resolveSession(ctx context.Context, sessionID string) *Upstream {
	if sessionID == "" {
		return nil
	}
	for _, upstream := range g.orderedUpstreams() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.BaseURL+"/api/lookingglass/sessions/"+sessionID, nil)
		if err != nil {
			continue
		}
		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}
		if resp.Body == nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		g.setSession(sessionID, upstream)
		return upstream
	}
	return nil
}

func (g *Gateway) orderedUpstreams() []*Upstream {
	ordered := make([]*Upstream, 0, len(g.order))
	for _, name := range g.order {
		if upstream, ok := g.upstreams[name]; ok {
			ordered = append(ordered, upstream)
		}
	}
	return ordered
}

func (g *Gateway) protocolCountForService(serviceName string) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, mapped := range g.protocolServices {
		if mapped == serviceName {
			count++
		}
	}
	return count
}

func (g *Gateway) isReady() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.protocols) > 0
}

func (g *Gateway) lastRefreshTime() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastRefresh
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Printf("Gateway response copy error: %v", err)
		}
	}
}
