package core

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/security-showcase/protocol-showcase/internal/crypto"
	"github.com/security-showcase/protocol-showcase/internal/lookingglass"
	"github.com/security-showcase/protocol-showcase/internal/plugin"
)

// Server is the main HTTP server for the protocol showcase
type Server struct {
	config       *Config
	registry     *plugin.Registry
	lookingGlass *lookingglass.Engine
	keySet       *crypto.KeySet
	router       chi.Router
}

// NewServer creates a new server instance
func NewServer(cfg *Config, registry *plugin.Registry, lg *lookingglass.Engine, ks *crypto.KeySet) *Server {
	s := &Server{
		config:       cfg,
		registry:     registry,
		lookingGlass: lg,
		keySet:       ks,
	}
	s.setupRouter()
	return s
}

// Router returns the configured router
func (s *Server) Router() chi.Router {
	return s.router
}

func (s *Server) setupRouter() {
	r := chi.NewRouter()

	// Global middleware
	r.Use(Recovery)
	r.Use(RequestLogger)
	r.Use(SecurityHeaders)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.config.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"Link", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Rate limiting for API endpoints
	rateLimiter := NewRateLimiter(100, time.Minute)
	r.Use(rateLimiter.Limit)

	// Health check
	r.Get("/health", s.handleHealth)

	// API routes
	r.Route("/api", func(r chi.Router) {
		// Protocol listing
		r.Get("/protocols", s.handleListProtocols)
		r.Get("/protocols/{id}", s.handleGetProtocol)
		r.Get("/protocols/{id}/flows", s.handleGetProtocolFlows)
		r.Post("/protocols/{id}/demo/{flow}", s.handleStartDemo)

		// Looking glass endpoints
		r.Route("/lookingglass", func(r chi.Router) {
			r.Post("/decode", s.handleDecodeToken)
			r.Get("/sessions", s.handleListSessions)
			r.Get("/sessions/{id}", s.handleGetSession)
		})

		// JWKS endpoint
		r.Get("/.well-known/jwks.json", s.handleJWKS)
	})

	// WebSocket routes
	r.Get("/ws/lookingglass/{session}", s.handleLookingGlassWS)

	// Mount protocol-specific routes
	for _, p := range s.registry.List() {
		info := p.Info()
		r.Route("/"+info.ID, func(r chi.Router) {
			p.RegisterRoutes(r)
		})
	}

	s.router = r
}

// Health check response
type HealthResponse struct {
	Status    string   `json:"status"`
	Version   string   `json:"version"`
	Protocols []string `json:"protocols"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	protocols := make([]string, 0)
	for _, p := range s.registry.List() {
		protocols = append(protocols, p.Info().ID)
	}

	resp := HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Protocols: protocols,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Protocol list response
type ProtocolListResponse struct {
	Protocols []ProtocolSummary `json:"protocols"`
}

type ProtocolSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

func (s *Server) handleListProtocols(w http.ResponseWriter, r *http.Request) {
	protocols := make([]ProtocolSummary, 0)
	for _, p := range s.registry.List() {
		info := p.Info()
		protocols = append(protocols, ProtocolSummary{
			ID:          info.ID,
			Name:        info.Name,
			Version:     info.Version,
			Description: info.Description,
			Tags:        info.Tags,
		})
	}

	writeJSON(w, http.StatusOK, ProtocolListResponse{Protocols: protocols})
}

func (s *Server) handleGetProtocol(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, exists := s.registry.Get(id)
	if !exists {
		writeError(w, http.StatusNotFound, "Protocol not found")
		return
	}

	info := p.Info()
	writeJSON(w, http.StatusOK, ProtocolSummary{
		ID:          info.ID,
		Name:        info.Name,
		Version:     info.Version,
		Description: info.Description,
		Tags:        info.Tags,
	})
}

type FlowListResponse struct {
	Flows []plugin.FlowDefinition `json:"flows"`
}

func (s *Server) handleGetProtocolFlows(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, exists := s.registry.Get(id)
	if !exists {
		writeError(w, http.StatusNotFound, "Protocol not found")
		return
	}

	definitions := p.GetFlowDefinitions()
	writeJSON(w, http.StatusOK, FlowListResponse{Flows: definitions})
}

func (s *Server) handleStartDemo(w http.ResponseWriter, r *http.Request) {
	protocolID := chi.URLParam(r, "id")
	flowID := chi.URLParam(r, "flow")

	p, exists := s.registry.Get(protocolID)
	if !exists {
		writeError(w, http.StatusNotFound, "Protocol not found")
		return
	}

	scenarios := p.GetDemoScenarios()
	for _, scenario := range scenarios {
		if scenario.ID == flowID {
			// Create a new looking glass session for this demo
			session := s.lookingGlass.CreateSession(protocolID, flowID)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"session_id":  session.ID,
				"protocol":    protocolID,
				"flow":        flowID,
				"ws_endpoint": "/ws/lookingglass/" + session.ID,
				"scenario":    scenario,
			})
			return
		}
	}

	writeError(w, http.StatusNotFound, "Flow not found")
}

type DecodeRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleDecodeToken(w http.ResponseWriter, r *http.Request) {
	var req DecodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	decoded, err := s.lookingGlass.DecodeToken(req.Token, s.keySet)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, decoded)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.lookingGlass.ListSessions()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	session, exists := s.lookingGlass.GetSession(id)
	if !exists {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := s.keySet.PublicJWKS()
	writeJSON(w, http.StatusOK, jwks)
}

func (s *Server) handleLookingGlassWS(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session")
	s.lookingGlass.HandleWebSocket(w, r, sessionID)
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

