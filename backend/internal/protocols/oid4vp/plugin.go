package oid4vp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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
	requestObjectTTL = 5 * time.Minute
)

// defaultDCQLQuery is the canonical presentation request used when a verifier
// creates an authorization request without an explicit dcql_query or scope. As
// The default targets the ISO/IEC 18013-5 mobile driving licence
// (mso_mdoc). SD-JWT VC and the W3C formats remain fully selectable by sending
// an explicit dcql_query (or scope) that names them.
var defaultDCQLQuery = map[string]interface{}{
	"credentials": []map[string]interface{}{
		{
			"id":     "mdl",
			"format": "mso_mdoc",
			"meta": map[string]interface{}{
				"doctype_values": []string{"org.iso.18013.5.1.mDL"},
			},
			"claims": []map[string]interface{}{
				{"path": []string{"org.iso.18013.5.1", "family_name"}},
				{"path": []string{"org.iso.18013.5.1", "document_number"}},
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
	// MdocHandover is an optional pre-encoded CBOR Handover override for the
	// shared mdoc SessionTranscript ([null, null, Handover]). The
	// production path reconstructs the real OID4VP 1.0 OpenID4VPHandover from the
	// session parameters (client_id, nonce, response_uri) plus the response
	// encryption key thumbprint via reconstructSessionHandover, so this field is
	// normally empty and is retained only so tests can pin an exact handover.
	MdocHandover []byte
	// ResponseEncryptionJWK is the verifier's ephemeral EC response-encryption
	// key for the mso_mdoc OID4VP online profile (direct_post.jwt). It carries
	// the private d so the verifier can decrypt the JWE response, and its RFC
	// 7638 thumbprint is bound into the OpenID4VPHandover. Presence of this key
	// marks an mdoc online-profile session and routes the encrypted response to
	// the ECDH-ES path rather than the SD-JWT RSA-OAEP path. It is persisted with
	// the short-lived (requestObjectTTL) request session under 0600 and never
	// leaves the verifier.
	ResponseEncryptionJWK *crypto.JWK `json:",omitempty"`
	// Profile narrows the allowed option set when set to "haip". In
	// HAIP mode the verifier requires DCQL, an encrypted response mode, ES256,
	// and (for signed requests) the x509_hash Client Identifier Prefix, and
	// rejects out-of-profile choices. Empty means the general (non-HAIP) profile,
	// which keeps every existing option available and unchanged.
	Profile string `json:",omitempty"`
	// Origin is the Verifier's Web Origin for the W3C Digital Credentials API
	// path (response_mode dc_api / dc_api.jwt). It is the value bound into the
	// OpenID4VPDCAPIHandover (OID4VP 1.0 Appendix B.2.6.2, NOT prefixed with
	// "origin:") and, with the "origin:" prefix, is the response audience
	// (Appendix A.4). Empty for the redirect path.
	Origin string `json:",omitempty"`
	// ExpectedOrigins is the expected_origins request parameter for signed DC API
	// requests (OID4VP 1.0 Appendix A.2); retained for evidence/inspection.
	ExpectedOrigins []string `json:",omitempty"`
	// ResponseEncEnc records the JWE content-encryption algorithm advertised for
	// this session (A128GCM or, under HAIP, A256GCM). Empty defaults to A128GCM.
	ResponseEncEnc string `json:",omitempty"`
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Result         *models.OID4VPVerificationResult
}

// isDCAPI reports whether this session uses the W3C Digital Credentials API
// invocation path (response_mode dc_api or dc_api.jwt), which selects the
// OpenID4VPDCAPIHandover transcript variant and the origin-bound response
// audience instead of the redirect handover and client_id audience.
func (s *requestSession) isDCAPI() bool {
	return isDCAPIResponseMode(s.ResponseMode)
}

// expectedResponseAudience returns the audience the wallet must bind the
// response to: for the DC API path it is the Origin prefixed with "origin:"
// (OID4VP 1.0 Appendix A.4); otherwise it is the Verifier's client_id.
func (s *requestSession) expectedResponseAudience() string {
	if s.isDCAPI() && strings.TrimSpace(s.Origin) != "" {
		return dcAPIAudience(s.Origin)
	}
	return s.ClientID
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
	verifierAttestation      *verifierAttestationIssuer
	x509SANDNSSigner         *x509RequestSigner

	// mdocTrustAnchors is the ISO/IEC 18013-5 IACA root pool the verifier chains
	// presented mso_mdoc document-signer certificates to (issuer PKI).
	// The trust anchor is the IACA root, never the DS certificate.
	mdocTrustAnchors *x509.CertPool
	// mdocTrustAnchorCerts retains the same IACA root(s) in parsed form so the
	// verifier can read each root's SubjectKeyIdentifier for the HAIP mso_mdoc
	// Authority Key Identifier Trusted Authorities Query (HAIP 1.0 Section 5).
	mdocTrustAnchorCerts []*x509.Certificate

	// dataDir is the configured persistence root. When set, the auto-generated
	// x509_hash request-signing certificate is persisted under it so the
	// HAIP-mandated x509_hash Client Identifier (the SHA-256 of the leaf) stays
	// stable across restarts rather than churning every process start.
	dataDir string

	mu              sync.RWMutex
	requests        map[string]*requestSession
	requestsByState map[string]string
	requestDataPath string

	stopPruning chan struct{}
}

// NewPlugin creates a new OID4VP plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "oid4vp",
			Name:        "OpenID4VP",
			Version:     "1.0.0",
			Description: "OpenID for Verifiable Presentations with DCQL-first request contracts",
			Tags:        []string{"vc", "oid4vp", "presentation", "dcql"},
			RFCs:        []string{"OpenID4VP 1.0", "OAuth 2.0", "JOSE"},
		}),
		supportedClientIDSchemes: DefaultClientIDSchemeSet(),
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
	p.dataDir = strings.TrimSpace(config.DataDir)
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}
	p.walletStore = vc.DefaultWalletCredentialStore()
	p.walletStore.SetEncryptionKey(strings.TrimSpace(os.Getenv("WALLET_PERSISTENCE_KEY")))
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		storePath := filepath.Join(dataDir, "vc", "wallet_credentials.json")
		if err := p.walletStore.EnablePersistence(storePath); err != nil {
			return fmt.Errorf("initialize wallet credential store persistence: %w", err)
		}
	}
	p.didWebAllowedHosts = p.allowedDIDWebHosts()
	p.trustResolver = NewDIDWebResolver(p.didWebAllowedHosts)
	if err := p.configureVerifierIdentities(); err != nil {
		return fmt.Errorf("configure verifier identities: %w", err)
	}
	if err := p.initMdocTrustAnchors(strings.TrimSpace(config.DataDir)); err != nil {
		return fmt.Errorf("configure mso_mdoc trust anchors: %w", err)
	}
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		requestPath := filepath.Join(dataDir, "vc", "oid4vp_request_sessions.json")
		if err := p.loadRequestState(requestPath); err != nil {
			return fmt.Errorf("load oid4vp request state: %w", err)
		}
		p.requestDataPath = requestPath
	}
	p.stopPruning = make(chan struct{})
	go p.pruneExpiredSessions()
	return nil
}

// Shutdown closes plugin lifecycle resources.
func (p *Plugin) Shutdown(ctx context.Context) error {
	_ = ctx
	if p.stopPruning != nil {
		close(p.stopPruning)
	}
	return nil
}

func (p *Plugin) pruneExpiredSessions() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopPruning:
			return
		case <-ticker.C:
			p.evictExpiredSessions()
		}
	}
}

func (p *Plugin) evictExpiredSessions() {
	now := time.Now().UTC()
	grace := 2 * requestObjectTTL

	p.mu.Lock()
	defer p.mu.Unlock()

	var evicted int
	for id, session := range p.requests {
		if now.After(session.ExpiresAt.Add(grace)) {
			delete(p.requests, id)
			if session.State != "" {
				delete(p.requestsByState, session.State)
			}
			evicted++
		}
	}
	if evicted > 0 {
		_ = p.persistRequestStateLocked()
	}
}

// RegisterRoutes registers OID4VP verifier endpoints.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	router.Post("/request/create", p.handleCreateAuthorizationRequest)
	router.Get("/request/{requestID}", p.handleGetAuthorizationRequest)
	router.Post("/request/{requestID}", p.handlePostAuthorizationRequest)
	router.Get("/verifier-attestation/.well-known/openid-configuration", p.handleVerifierAttestationOpenIDConfiguration)
	router.Get("/verifier-attestation/.well-known/oauth-authorization-server", p.handleVerifierAttestationAuthorizationServerMetadata)
	router.Get("/verifier-attestation/jwks", p.handleVerifierAttestationJWKS)
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
			Description: "Verifier creates a signed authorization request object with DCQL query and publishes a request_uri. Wallet fetches the request, evaluates the query, and posts vp_token to response_uri using direct_post (OID4VP §5, §8.2).",
			Executable:  true,
			Category:    "verification",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create Authorization Request",
					Description: "Verifier builds a signed request object (typ=oauth-authz-req+jwt) containing DCQL query or scope alias, binds a fresh nonce and state, and publishes it at a request_uri (OID4VP §5.1).",
					From:        "Verifier",
					To:          "Wallet",
					Type:        "request",
					Parameters: map[string]string{
						"client_id":     "Verifier identifier with supported client_id scheme prefix (REQUIRED)",
						"response_type": "vp_token (REQUIRED)",
						"response_mode": "direct_post (REQUIRED)",
						"response_uri":  "Verifier endpoint for wallet callback (REQUIRED for direct_post)",
						"dcql_query":    "Credential query object (XOR with scope — exactly one REQUIRED)",
						"nonce":         "Cryptographically random replay protection nonce (REQUIRED)",
						"state":         "Session correlation value for request-response binding (REQUIRED)",
						"exp":           "Request object expiration timestamp",
					},
					Security: []string{
						"Request object is signed as JWT with typ=oauth-authz-req+jwt",
						"Exactly one of dcql_query or scope alias must be present (XOR contract)",
						"response_uri is required and redirect_uri must be absent for direct_post mode",
						"client_id scheme must follow OpenID4VP client identification rules and be verifiable by wallet and verifier",
						"Nonce must be cryptographically random and unique per request",
					},
				},
				{
					Order:       2,
					Name:        "Fetch Request Object",
					Description: "Wallet fetches the signed authorization request object from the Verifier's request_uri endpoint via GET or POST (OID4VP §5.2).",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
					Parameters: map[string]string{
						"request_uri": "URI referencing the authorization request object (REQUIRED)",
					},
					Security: []string{
						"Wallet must validate request object JWT signature before processing",
						"Wallet must verify typ header is oauth-authz-req+jwt",
						"Request object must not be expired (exp claim check)",
					},
				},
				{
					Order:       3,
					Name:        "Wallet Presentation Submission",
					Description: "Wallet evaluates the DCQL query, selects matching credentials, creates a signed vp_token (typ=vp+jwt), and posts vp_token + state to the Verifier's response_uri (OID4VP §8.2).",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
					Parameters: map[string]string{
						"vp_token": "Signed VP token JWT containing presented credential (REQUIRED)",
						"state":    "State value from original authorization request (REQUIRED)",
					},
					Security: []string{
						"VP token header typ must be vp+jwt",
						"VP token must include nonce matching the request's nonce",
						"VP token audience must match the Verifier's client_id",
						"VP token must include holder binding via iss/sub and cnf.jkt (key thumbprint)",
						"Presented credential must satisfy DCQL required claim paths",
					},
				},
				{
					Order:       4,
					Name:        "Verifier Validation + Policy Decision",
					Description: "Verifier resolves the request session by state, validates the VP token signature and claims, verifies credential evidence, and evaluates the verifier policy (OID4VP §6).",
					From:        "Verifier",
					To:          "Verifier",
					Type:        "internal",
					Parameters: map[string]string{
						"nonce_binding":       "VP token nonce must match request nonce",
						"audience_binding":    "VP token audience must include client_id",
						"expiry_check":        "VP token must not be expired",
						"holder_binding":      "iss/sub must match wallet identity, cnf.jkt must match key thumbprint",
						"credential_evidence": "Presented credential issuer, signature, subject, and disclosed claims must satisfy verifier trust policy",
						"dcql_claims":         "All required claim paths from DCQL query must be present in disclosed claims",
					},
					Security: []string{
						"Policy decision is stored as allowed/denied with reason codes",
						"All checks must pass for policy to return allowed",
						"Credential signature and issuer trust must be verified before policy allow",
					},
				},
			},
		},
		{
			ID:          "oid4vp-direct-post-jwt",
			Name:        "OID4VP DCQL + direct_post.jwt",
			Description: "Verifier creates a signed authorization request and publishes request_uri. Wallet fetches it, creates an encrypted JWE response containing a signed inner JWT (typ=oauth-authz-resp+jwt) with vp_token, and posts to response_uri. Verifier decrypts and validates (OID4VP §5, §8.3.1).",
			Executable:  true,
			Category:    "verification",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Create Signed Request Object",
					Description: "Verifier creates a signed authorization request object (typ=oauth-authz-req+jwt) with DCQL query, response_mode=direct_post.jwt, and publishes it at a request_uri (OID4VP §5.1).",
					From:        "Verifier",
					To:          "Wallet",
					Type:        "request",
					Parameters: map[string]string{
						"client_id":     "Verifier identifier with supported client_id scheme prefix (REQUIRED)",
						"response_type": "vp_token (REQUIRED)",
						"response_mode": "direct_post.jwt (REQUIRED)",
						"response_uri":  "Verifier endpoint for encrypted wallet callback (REQUIRED)",
						"dcql_query":    "Credential query object (XOR with scope)",
						"nonce":         "Cryptographically random replay protection nonce (REQUIRED)",
						"state":         "Session correlation value (REQUIRED)",
					},
					Security: []string{
						"Request object is signed as JWT with typ=oauth-authz-req+jwt",
						"response_uri is required and redirect_uri must be absent for direct_post.jwt",
						"Wallet encrypts response using verifier-published key material and supported JWE parameters",
					},
				},
				{
					Order:       2,
					Name:        "Fetch Request Object",
					Description: "Wallet fetches the signed authorization request object from the Verifier's request_uri via GET or POST (OID4VP §5.2).",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
					Parameters: map[string]string{
						"request_uri": "URI referencing the authorization request object (REQUIRED)",
					},
					Security: []string{
						"Wallet must validate request object JWT signature",
						"Wallet must verify typ header is oauth-authz-req+jwt",
						"Request must not be expired",
					},
				},
				{
					Order:       3,
					Name:        "Wallet Encrypted Response",
					Description: "Wallet creates a signed inner response JWT (typ=oauth-authz-resp+jwt) containing vp_token and state, encrypts it as a JWE using verifier-supported alg/enc parameters, and posts the encrypted response to response_uri (OID4VP §8.3.1).",
					From:        "Wallet",
					To:          "Verifier",
					Type:        "request",
					Parameters: map[string]string{
						"response": "Compact JWE containing signed inner response JWT (REQUIRED)",
						"state":    "State value from original authorization request (REQUIRED)",
					},
					Security: []string{
						"Inner response JWT typ must be oauth-authz-resp+jwt",
						"Inner JWT audience must match the Verifier's response_uri",
						"Inner JWT must include iss/sub matching wallet identity",
						"JWE alg/enc must match verifier-published response encryption metadata",
						"VP token within inner JWT must have typ=vp+jwt with nonce and audience binding",
					},
				},
				{
					Order:       4,
					Name:        "Decrypt + Validate + Policy Decision",
					Description: "Verifier decrypts the JWE response, validates the inner JWT signature/type/audience/subject/expiry, extracts vp_token, verifies credential evidence, and evaluates verifier policy (OID4VP §6, §8.3.1).",
					From:        "Verifier",
					To:          "Verifier",
					Type:        "internal",
					Parameters: map[string]string{
						"jwe_decryption":    "Decrypt response JWE using verifier private key and negotiated alg/enc",
						"inner_jwt_typ":     "Must be oauth-authz-resp+jwt",
						"inner_jwt_aud":     "Must match response_uri",
						"state_consistency": "State in inner JWT must match state from request",
						"vp_token_checks":   "nonce binding, audience binding, expiry, holder binding, credential lineage",
					},
					Security: []string{
						"Decryption failure rejects the entire response",
						"Inner JWT subject must be bound to wallet identity (iss/sub match)",
						"All VP token validation checks from direct_post apply after decryption",
						"Policy decision is stored as allowed/denied with reason codes",
					},
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
