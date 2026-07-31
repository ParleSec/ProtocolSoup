package core

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/palette"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// Server is the main HTTP server for the protocol showcase
type Server struct {
	config       *Config
	registry     *plugin.Registry
	lookingGlass *lookingglass.Engine
	keySet       *crypto.KeySet
	palette      *palette.Service
	router       chi.Router
}

// NewServer creates a new server instance. Pass nil for paletteSvc when the
// palette index is not loaded — the route is then omitted entirely.
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

// WithPalette mounts the palette query handler. Returns the server for
// fluent use during bootstrap. A nil service is a no-op.
func (s *Server) WithPalette(paletteSvc *palette.Service) *Server {
	if paletteSvc == nil {
		return s
	}
	s.palette = paletteSvc
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
	r.Use(s.redirectWWWToCanonical())
	r.Use(CaptureMiddleware(s.lookingGlass))
	r.Use(Recovery)
	r.Use(RequestLogger)
	r.Use(SecurityHeaders)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.config.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "X-Looking-Glass-Session", lookingglass.OwnerTokenHeader, "If-Match", "If-None-Match"},
		ExposedHeaders:   []string{"Link", "X-Request-ID", "ETag", "Location"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/health", s.handleHealth)

	// API routes
	rateLimiter := NewRateLimiter(100, time.Minute)
	r.With(rateLimiter.Limit).Get("/api", s.handleAPIIndex)
	r.Route("/api", func(r chi.Router) {
		r.Use(rateLimiter.Limit)
		r.Get("/", s.handleAPIIndex)

		// Protocol listing
		r.Get("/protocols", s.handleListProtocols)
		r.Get("/protocols/{id}", s.handleGetProtocol)
		r.Get("/protocols/{id}/flows", s.handleGetProtocolFlows)
		r.Post("/protocols/{id}/demo/{flow}", s.handleStartDemo)

		// Looking glass endpoints (optional)
		if s.lookingGlass != nil {
			r.Route("/lookingglass", func(r chi.Router) {
				r.Post("/decode", s.handleDecodeToken)
				r.Post("/decode/credential", s.handleDecodeCredential)
				r.Get("/sessions", s.handleListSessions)
				r.Get("/sessions/{id}", s.handleGetSession)
			})
		}

		// JWKS endpoint (optional)
		if s.keySet != nil {
			r.Get("/.well-known/jwks.json", s.handleJWKS)
		}

		// Palette query (optional). The handler is mounted only when an
		// index is loaded; otherwise the route is absent so clients can
		// detect availability via /api.
		if s.palette != nil {
			r.Post("/palette/query", s.palette.Handler())
		}
	})

	// WebSocket routes (optional)
	if s.lookingGlass != nil {
		r.With(rateLimiter.Limit).Get("/ws/lookingglass/{session}", s.handleLookingGlassWS)
	}

	// Mount protocol-specific routes
	for _, p := range s.registry.List() {
		info := p.Info()
		protocolRouter := chi.NewRouter()
		protocolRouter.Use(rateLimiter.Limit)
		p.RegisterRoutes(protocolRouter)
		r.Mount("/"+info.ID, protocolRouter)

		// OID4VCI metadata discovery must also be reachable at canonical well-known paths.
		if info.ID == "oid4vci" {
			// Non-root issuers must not serve metadata on the bare well-known path.
			r.Get("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			})
			r.Method(http.MethodGet, "/.well-known/openid-credential-issuer/*", protocolRouter)

			// RFC 8414 Section 3.1: the Authorization Server metadata document
			// for issuer https://{host}/oid4vci lives at the root well-known
			// path with the issuer's path component appended, not under
			// /oid4vci itself. A wallet resolving authorization_servers from
			// the credential issuer metadata needs this to find
			// authorization_endpoint.
			r.Get("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			})
			r.Method(http.MethodGet, "/.well-known/oauth-authorization-server/*", protocolRouter)
		}

		if info.ID == "oauth2" {
			// RFC 8414 Section 3.1 inserts the well-known suffix before the
			// path component of the OAuth issuer identifier.
			r.Method(http.MethodGet, "/.well-known/oauth-authorization-server/oauth2", protocolRouter)
		}

		// OpenID Connect Discovery 1.0 Section 4: a Relying Party derives the
		// configuration URL as {issuer}/.well-known/openid-configuration. The
		// OP issuer is the site root, so the discovery document MUST be served
		// at the root well-known path (Section 4.3 also requires the issuer in
		// the document to equal that prefix). The /oidc-prefixed route is kept
		// for backward compatibility; both delegate to the same handler.
		if info.ID == "oidc" {
			r.Method(http.MethodGet, "/.well-known/openid-configuration", protocolRouter)
		}
	}

	// Route web traffic to the Next.js runtime when configured.
	if s.config.FrontendOrigin != "" {
		s.setupFrontendProxy(r)
	}

	s.router = r
}

func (s *Server) redirectWWWToCanonical() func(http.Handler) http.Handler {
	baseURL := strings.TrimSpace(s.config.BaseURL)
	if baseURL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return func(next http.Handler) http.Handler { return next }
	}

	canonicalHost := strings.ToLower(parsedBase.Hostname())
	if canonicalHost == "" || strings.HasPrefix(canonicalHost, "www.") {
		return func(next http.Handler) http.Handler { return next }
	}

	canonicalScheme := parsedBase.Scheme
	if canonicalScheme == "" {
		canonicalScheme = "https"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqHost := strings.ToLower(r.Host)
			if host, _, err := net.SplitHostPort(reqHost); err == nil {
				reqHost = host
			}

			if reqHost == "www."+canonicalHost {
				target := *r.URL
				target.Scheme = canonicalScheme
				target.Host = canonicalHost
				http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// setupFrontendProxy routes web traffic to an external frontend runtime (Next.js standalone server).
func (s *Server) setupFrontendProxy(r chi.Router) {
	targetOrigin := strings.TrimSpace(s.config.FrontendOrigin)
	if targetOrigin == "" {
		return
	}

	targetURL, err := url.Parse(targetOrigin)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, _ error) {
		http.Error(w, "Frontend runtime unavailable", http.StatusBadGateway)
	}

	r.Handle("/*", proxy)
}

// Health check response
type HealthResponse struct {
	Status    string         `json:"status"`
	Version   string         `json:"version"`
	Protocols []string       `json:"protocols"`
	Palette   *palette.Stats `json:"palette,omitempty"`
}

// API index response
type APIIndexResponse struct {
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Protocols []string          `json:"protocols"`
	Endpoints map[string]string `json:"endpoints"`
}

func (s *Server) handleAPIIndex(w http.ResponseWriter, r *http.Request) {
	protocols := make([]string, 0)
	for _, p := range s.registry.List() {
		protocols = append(protocols, p.Info().ID)
	}

	endpoints := map[string]string{
		"protocols": "/api/protocols",
		"health":    "/health",
		"flows":     "/api/protocols/{id}/flows",
		"demo":      "/api/protocols/{id}/demo/{flow}",
	}
	if s.lookingGlass != nil {
		endpoints["lookingglass"] = "/api/lookingglass"
		endpoints["lookingglass_ws"] = "/ws/lookingglass/{session}"
	}
	if s.keySet != nil {
		endpoints["jwks"] = "/api/.well-known/jwks.json"
	}
	if s.palette != nil {
		endpoints["palette"] = "/api/palette/query"
	}

	writeJSON(w, http.StatusOK, APIIndexResponse{
		Service:   "protocol-lens",
		Version:   "1.0.0",
		Protocols: protocols,
		Endpoints: endpoints,
	})
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
	if s.palette != nil {
		stats := s.palette.Stats()
		resp.Palette = &stats
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
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}

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
			session, ownerToken, err := s.lookingGlass.CreateSession(protocolID, flowID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Unable to create Looking Glass session")
				return
			}

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"session_id":    session.ID,
				"session_token": ownerToken,
				"protocol":      protocolID,
				"flow":          flowID,
				"ws_endpoint":   "/ws/lookingglass/" + session.ID,
				"scenario":      scenario,
			})
			return
		}
	}

	// If not a demo scenario, allow direct flow sessions
	flowFound := false
	for _, flow := range p.GetFlowDefinitions() {
		if flow.ID == flowID {
			flowFound = true
			break
		}
	}
	if !flowFound {
		writeError(w, http.StatusNotFound, "Flow not found")
		return
	}

	session, ownerToken, err := s.lookingGlass.CreateSession(protocolID, flowID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Unable to create Looking Glass session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id":    session.ID,
		"session_token": ownerToken,
		"protocol":      protocolID,
		"flow":          flowID,
		"ws_endpoint":   "/ws/lookingglass/" + session.ID,
		"scenario":      nil,
	})
}

type DecodeRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleDecodeToken(w http.ResponseWriter, r *http.Request) {
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}
	if s.keySet == nil {
		writeError(w, http.StatusServiceUnavailable, "Key set is unavailable")
		return
	}

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

// maxCredentialDecodeBodyBytes caps the request body for
// POST /lookingglass/decode/credential, mirroring the external-import cap in
// cmd/walletharness/oid4vci_external.go. This is one of the two HTTP entry
// points the A2 hardening rule names: every path that accepts an
// externally-supplied credential gets a body cap enforced before the
// request is buffered, in addition to the CBOR-specific decode limits
// vc.MSOMdocFormat.ParseCredential applies unconditionally further down the
// call chain.
const maxCredentialDecodeBodyBytes = 64 * 1024

// DecodeCredentialRequest is the request body for
// POST /lookingglass/decode/credential.
type DecodeCredentialRequest struct {
	Credential string `json:"credential"`
}

// namespaceDisclosureCountsResponse is the wire form of
// vc.NamespaceDisclosureCounts.
type namespaceDisclosureCountsResponse struct {
	CommittedCount int `json:"committed_count"`
	PresentCount   int `json:"present_count"`
}

// selectiveDisclosureResponse is the wire form of vc.SelectiveDisclosureSummary.
type selectiveDisclosureResponse struct {
	Mechanism                       string                                       `json:"mechanism"`
	CommittedCount                  int                                          `json:"committed_count"`
	CommittedCountIsExact           bool                                         `json:"committed_count_is_exact"`
	PresentCount                    int                                          `json:"present_count"`
	LifecycleStage                  string                                       `json:"lifecycle_stage"`
	DigestAlgorithm                 string                                       `json:"digest_algorithm,omitempty"`
	PerNamespace                    map[string]namespaceDisclosureCountsResponse `json:"per_namespace,omitempty"`
	HasUnrepresentedDisclosureForms bool                                         `json:"has_unrepresented_disclosure_forms"`
}

// credentialAssuranceResponse is the wire form of vc.CredentialAssurance. It
// never collapses to a single validity flag: IssuerTrust is the tri-state
// string ("verified" / "failed" / "not_evaluated") from
// vc.IssuerTrustStatus.String(), and DigestsConsistentWithMSO is absent
// entirely (omitted, not false) for every format except mso_mdoc. Per
// vc.MdocDigestsConsistentWithMSO's doc comment, that field proves internal
// consistency between the presented items and the credential's own MSO, not
// authenticity of the MSO -- callers must not rename or relabel it as
// "verified" or "ok".
type credentialAssuranceResponse struct {
	IssuerTrust              string `json:"issuer_trust"`
	IssuerTrustDetail        string `json:"issuer_trust_detail,omitempty"`
	DigestsConsistentWithMSO *bool  `json:"digests_consistent_with_mso,omitempty"`
	DigestConsistencyDetail  string `json:"digest_consistency_detail,omitempty"`
}

// credentialEvidenceResponse is the wire form of vc.CredentialEvidence.
// IssuedAt/ExpiresAt are omitted entirely (not sent as a zero-value
// timestamp) when the source credential carried no corresponding claim --
// see vc.CredentialEvidence's doc comment on why this must never be
// back-filled.
type credentialEvidenceResponse struct {
	Format              string                       `json:"format,omitempty"`
	VCT                 string                       `json:"vct,omitempty"`
	Doctype             string                       `json:"doctype,omitempty"`
	CredentialTypes     []string                     `json:"credential_types,omitempty"`
	FullClaims          map[string]interface{}       `json:"full_claims,omitempty"`
	DisclosedClaims     map[string]interface{}       `json:"disclosed_claims,omitempty"`
	SelectiveDisclosure *selectiveDisclosureResponse `json:"selective_disclosure,omitempty"`
	IssuedAt            string                       `json:"issued_at,omitempty"`
	ExpiresAt           string                       `json:"expires_at,omitempty"`
}

// decodeCredentialResponse is the full response body for
// POST /lookingglass/decode/credential: the shared evidence plus the
// assurance envelope, kept as distinct top-level objects so a client cannot
// merge "what this artifact contains" and "what has been checked about it"
// into one register by accident.
type decodeCredentialResponse struct {
	Evidence  credentialEvidenceResponse  `json:"evidence"`
	Assurance credentialAssuranceResponse `json:"assurance"`
}

func newSelectiveDisclosureResponse(summary *vc.SelectiveDisclosureSummary) *selectiveDisclosureResponse {
	if summary == nil {
		return nil
	}
	var perNamespace map[string]namespaceDisclosureCountsResponse
	if len(summary.PerNamespace) > 0 {
		perNamespace = make(map[string]namespaceDisclosureCountsResponse, len(summary.PerNamespace))
		for ns, counts := range summary.PerNamespace {
			perNamespace[ns] = namespaceDisclosureCountsResponse{
				CommittedCount: counts.CommittedCount,
				PresentCount:   counts.PresentCount,
			}
		}
	}
	return &selectiveDisclosureResponse{
		Mechanism:                       summary.Mechanism,
		CommittedCount:                  summary.CommittedCount,
		CommittedCountIsExact:           summary.CommittedCountIsExact,
		PresentCount:                    summary.PresentCount,
		LifecycleStage:                  string(summary.LifecycleStage),
		DigestAlgorithm:                 summary.DigestAlgorithm,
		PerNamespace:                    perNamespace,
		HasUnrepresentedDisclosureForms: summary.HasUnrepresentedDisclosureForms,
	}
}

func formatCredentialTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func newDecodeCredentialResponse(result *vc.CredentialInspectionResult) decodeCredentialResponse {
	return decodeCredentialResponse{
		Evidence: credentialEvidenceResponse{
			Format:              result.Evidence.Format,
			VCT:                 result.Evidence.VCT,
			Doctype:             result.Evidence.Doctype,
			CredentialTypes:     result.Evidence.CredentialTypes,
			FullClaims:          result.Evidence.FullClaims,
			DisclosedClaims:     result.Evidence.DisclosedClaims,
			SelectiveDisclosure: newSelectiveDisclosureResponse(result.Evidence.SelectiveDisclosure),
			IssuedAt:            formatCredentialTimestamp(result.Evidence.IssuedAt),
			ExpiresAt:           formatCredentialTimestamp(result.Evidence.ExpiresAt),
		},
		Assurance: credentialAssuranceResponse{
			IssuerTrust:              result.Assurance.IssuerTrust.String(),
			IssuerTrustDetail:        result.Assurance.IssuerTrustDetail,
			DigestsConsistentWithMSO: result.Assurance.DigestsConsistentWithMSO,
			DigestConsistencyDetail:  result.Assurance.DigestConsistencyDetail,
		},
	}
}

// handleDecodeCredential is the sibling of handleDecodeToken for credentials
// rather than bearer/DPoP JWTs: it decodes a pasted credential of any
// registered vc.CredentialFormat (including mso_mdoc) into the same shared
// evidence shape BuildCredentialEvidence produces for issuance and
// verification, wrapped in an assurance envelope that reports issuer trust
// and (mdoc only) digest consistency honestly rather than as a blanket
// validity flag. See vc.InspectCredential.
func (s *Server) handleDecodeCredential(w http.ResponseWriter, r *http.Request) {
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}

	// This endpoint accepts a pasted credential from any issuer, so it is
	// one of the two externally-supplied-credential HTTP entry points the
	// A2 hardening rule covers (the other is walletharness's external
	// import). Cap the body before it is buffered at all.
	r.Body = http.MaxBytesReader(w, r.Body, maxCredentialDecodeBodyBytes)

	var req DecodeCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	credential := strings.TrimSpace(req.Credential)
	if credential == "" {
		writeError(w, http.StatusBadRequest, "credential is required")
		return
	}

	result, err := vc.InspectCredential(credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, newDecodeCredentialResponse(result))
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}

	sessions := s.lookingGlass.ListSessionSummaries()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}

	id := chi.URLParam(r, "id")
	if _, exists := s.lookingGlass.GetSession(id); !exists {
		writeError(w, http.StatusNotFound, "Session not found")
		return
	}
	session, authorized := s.lookingGlass.AuthorizedSessionSnapshot(
		id,
		r.Header.Get(lookingglass.OwnerTokenHeader),
	)
	if !authorized {
		writeError(w, http.StatusUnauthorized, "Looking Glass session owner capability required")
		return
	}
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if s.keySet == nil {
		writeError(w, http.StatusServiceUnavailable, "Key set is unavailable")
		return
	}

	jwks := s.keySet.PublicJWKS()
	writeJSON(w, http.StatusOK, jwks)
}

func (s *Server) handleLookingGlassWS(w http.ResponseWriter, r *http.Request) {
	if s.lookingGlass == nil {
		writeError(w, http.StatusServiceUnavailable, "Looking Glass is disabled")
		return
	}

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
