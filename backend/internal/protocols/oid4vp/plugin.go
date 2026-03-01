package oid4vp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
)

const (
	defaultVerifierClientID = "redirect_uri:https://verifier.protocolsoup.local/callback"
	requestObjectTTL        = 5 * time.Minute
)

var defaultDCQLQuery = map[string]interface{}{
	"credentials": []map[string]interface{}{
		{
			"id": "university_degree",
			"meta": map[string]interface{}{
				"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"},
			},
			"claims": []map[string]interface{}{
				{"path": []string{"degree"}},
				{"path": []string{"graduation_year"}},
			},
		},
	},
}

type requestSession struct {
	ID             string
	ClientID       string
	ClientIDScheme ClientIDScheme
	Nonce          string
	State          string
	ResponseMode   string
	ResponseURI    string
	RedirectURI    string
	ScopeAlias     string
	DCQLQuery      string
	RequestJWT     string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Result         *models.OID4VPVerificationResult
}

// Plugin implements OpenID for Verifiable Presentations with DCQL-first semantics.
type Plugin struct {
	*plugin.BasePlugin

	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
	walletStore  *vc.WalletCredentialStore

	trustResolver            TrustResolver
	supportedClientIDSchemes map[ClientIDScheme]struct{}
	didWebAllowedHosts       []string

	mu              sync.RWMutex
	requests        map[string]*requestSession
	requestsByState map[string]string
	requestDataPath string
}

// NewPlugin creates a new OID4VP plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "oid4vp",
			Name:        "OpenID4VP",
			Version:     "0.1.0",
			Description: "OpenID for Verifiable Presentations with DCQL-first request contracts",
			Tags:        []string{"vc", "oid4vp", "presentation", "dcql"},
			RFCs:        []string{"OpenID4VP 1.0", "OAuth 2.0", "JOSE"},
		}),
		supportedClientIDSchemes: DefaultMVPClientIDSchemeSet(),
		requests:                 make(map[string]*requestSession),
		requestsByState:          make(map[string]string),
	}
}

// Initialize wires shared services used by OID4VP.
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	_ = ctx

	p.SetConfig(config)
	p.baseURL = strings.TrimRight(config.BaseURL, "/")
	if p.baseURL == "" {
		p.baseURL = "http://localhost:8080"
	}
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}
	p.walletStore = vc.DefaultWalletCredentialStore()
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		storePath := filepath.Join(dataDir, "vc", "wallet_credentials.json")
		if err := p.walletStore.EnablePersistence(storePath); err != nil {
			return fmt.Errorf("initialize wallet credential store persistence: %w", err)
		}
	}
	p.didWebAllowedHosts = p.allowedDIDWebHosts()
	p.trustResolver = NewDIDWebResolver(p.didWebAllowedHosts)
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		requestPath := filepath.Join(dataDir, "vc", "oid4vp_request_sessions.json")
		if err := p.loadRequestState(requestPath); err != nil {
			return fmt.Errorf("load oid4vp request state: %w", err)
		}
		p.requestDataPath = requestPath
	}
	return nil
}

// Shutdown closes plugin lifecycle resources.
func (p *Plugin) Shutdown(ctx context.Context) error {
	_ = ctx
	return nil
}

// RegisterRoutes registers OID4VP verifier endpoints.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	router.Post("/request/create", p.handleCreateAuthorizationRequest)
	router.Get("/request/{requestID}", p.handleGetAuthorizationRequest)
	router.Post("/request/{requestID}", p.handlePostAuthorizationRequest)
	router.Post("/response", p.handleWalletResponse)
	router.Get("/result/{requestID}", p.handleGetVerificationResult)
}

// GetInspectors returns OID4VP-specific inspectors.
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "oid4vp-request-inspector",
			Name:        "OID4VP Request Inspector",
			Description: "Inspect request objects, direct_post transport payloads, and policy decisions",
			Type:        "request",
		},
	}
}

// GetFlowDefinitions returns executable OID4VP flow definitions.
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "oid4vp-direct-post",
			Name:        "OID4VP DCQL + direct_post",
			Description: "Verifier creates a DCQL request object and wallet submits vp_token to response_uri using direct_post.",
			Executable:  true,
			Category:    "verification",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create Authorization Request",
					Description: "Verifier builds a request object with dcql_query xor scope alias and binds nonce/state.",
					From:        "Verifier",
					To:          "Wallet",
					Type:        "request",
					Parameters: map[string]string{
						"client_id":     "Verifier identifier with supported scheme",
						"dcql_query":    "Credential query object",
						"response_mode": "direct_post",
						"response_uri":  "Wallet submission endpoint",
						"nonce":         "Replay protection nonce",
						"state":         "Session correlation value",
					},
					Security: []string{
						"Request must include exactly one of dcql_query or scope alias",
						"response_uri required and redirect_uri forbidden for direct_post",
					},
				},
				{
					Order:       2,
					Name:        "Wallet Presentation Submission",
					Description: "Wallet posts vp_token and state to verifier response_uri.",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
				},
				{
					Order:       3,
					Name:        "Verifier Validation + Policy",
					Description: "Verifier validates nonce, audience, expiry, and holder-binding before policy decision.",
					From:        "Verifier",
					To:          "Verifier",
					Type:        "internal",
				},
			},
		},
		{
			ID:          "oid4vp-direct-post-jwt",
			Name:        "OID4VP DCQL + direct_post.jwt",
			Description: "Wallet wraps presentation response in encrypted direct_post.jwt payload to verifier response_uri.",
			Executable:  true,
			Category:    "verification",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create Signed Request Object",
					Description: "Verifier creates typ=oauth-authz-req+jwt request object and publishes request_uri.",
					From:        "Verifier",
					To:          "Wallet",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "Wallet Encrypted Response",
					Description: "Wallet submits encrypted direct_post.jwt response containing vp_token and state.",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
				},
				{
					Order:       3,
					Name:        "Decrypt + Verify",
					Description: "Verifier decrypts response JWT, validates request binding, and applies policy.",
					From:        "Verifier",
					To:          "Verifier",
					Type:        "internal",
				},
			},
		},
	}
}

// GetDemoScenarios returns flow scenarios for OID4VP.
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "oid4vp-direct-post",
			Name:        "DCQL direct_post",
			Description: "Create a verifier request, then submit wallet presentation through direct_post",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create Request", Description: "Build request object with DCQL + nonce", Auto: true},
				{Order: 2, Name: "Wallet Submit", Description: "External wallet posts vp_token + state to response_uri", Auto: false},
				{Order: 3, Name: "Inspect Result", Description: "Review verification result and policy decision", Auto: true},
			},
		},
		{
			ID:          "oid4vp-direct-post-jwt",
			Name:        "DCQL direct_post.jwt",
			Description: "Create a verifier request and submit encrypted wallet response as direct_post.jwt",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create JWT Request", Description: "Issue typ=oauth-authz-req+jwt request", Auto: true},
				{Order: 2, Name: "Encrypted Wallet Post", Description: "External wallet submits JWE response to response_uri", Auto: false},
				{Order: 3, Name: "Decrypt + Evaluate", Description: "Inspect verifier validation outcome", Auto: true},
			},
		},
	}
}

func (p *Plugin) getSessionFromRequest(r *http.Request) string {
	if sessionID := r.Header.Get("X-Looking-Glass-Session"); sessionID != "" {
		return sessionID
	}
	return r.URL.Query().Get("lg_session")
}

func (p *Plugin) emitEvent(sessionID string, eventType lookingglass.EventType, title string, data map[string]interface{}, annotations ...lookingglass.Annotation) {
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	p.lookingGlass.NewEventBroadcaster(sessionID).Emit(eventType, title, data, annotations...)
}

func (p *Plugin) vpAnnotation(key string) []lookingglass.Annotation {
	annotationSet := lookingglass.NewAnnotationLibrary().OID4VPAnnotations()
	if items, ok := annotationSet[key]; ok {
		return items
	}
	return nil
}

func (p *Plugin) verifierBaseURL() string {
	return p.baseURL + "/oid4vp"
}

func (p *Plugin) allowedDIDWebHosts() []string {
	hosts := []string{
		"localhost",
		"127.0.0.1",
		"protocolsoup.com",
		"www.protocolsoup.com",
	}
	parsed, err := url.Parse(p.baseURL)
	if err == nil {
		host := strings.TrimSpace(parsed.Hostname())
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	unique := make(map[string]struct{}, len(hosts))
	normalizedHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if normalized == "" {
			continue
		}
		if _, exists := unique[normalized]; exists {
			continue
		}
		unique[normalized] = struct{}{}
		normalizedHosts = append(normalizedHosts, normalized)
	}
	sort.Strings(normalizedHosts)
	return normalizedHosts
}

type requestStateSnapshot struct {
	Requests  map[string]*requestSession `json:"requests"`
	UpdatedAt time.Time                  `json:"updated_at"`
}

func (p *Plugin) trustMode() string {
	if len(p.didWebAllowedHosts) == 0 {
		return "interop_mode"
	}
	return "controlled_trust_mode"
}

func (p *Plugin) loadRequestState(path string) error {
	normalized := strings.TrimSpace(path)
	if normalized == "" {
		return nil
	}
	normalized = filepath.Clean(normalized)
	if err := os.MkdirAll(filepath.Dir(normalized), 0o755); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.requestDataPath = normalized

	raw, err := os.ReadFile(normalized)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var snapshot requestStateSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Requests != nil {
		p.requests = snapshot.Requests
	}
	p.requestsByState = make(map[string]string, len(p.requests))
	for requestID, session := range p.requests {
		if session == nil {
			continue
		}
		state := strings.TrimSpace(session.State)
		if state == "" {
			continue
		}
		p.requestsByState[state] = requestID
	}
	return nil
}

func (p *Plugin) persistRequestStateLocked() error {
	if strings.TrimSpace(p.requestDataPath) == "" {
		return nil
	}
	snapshot := requestStateSnapshot{
		Requests:  p.requests,
		UpdatedAt: time.Now().UTC(),
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tempPath := p.requestDataPath + ".tmp"
	if err := os.WriteFile(tempPath, serialized, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, p.requestDataPath)
}

func (p *Plugin) randomValue(size int) string {
	if size <= 0 {
		size = 24
	}
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)[:size]
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOID4VPError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeServerError(w http.ResponseWriter, action string, err error) {
	writeOID4VPError(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%s: %v", action, err))
}
