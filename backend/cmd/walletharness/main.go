package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type walletHarnessServer struct {
	httpClient  *http.Client
	jwksFetcher *intcrypto.JWKSFetcher

	targetBaseURL     string
	targetHost        string
	targetResponseURI string
	issuerBaseURL     string
	allowExternal     bool
	appTitle          string

	defaultWalletSubject              string
	walletDIDMethod                   string
	trustedVerifierAttestationIssuers map[string]struct{}
	oid4vciClientID                   string
	oid4vciClientSecret               string
	walletSessionTTL                  time.Duration
	strictIsolation                   bool
	allowedCORSOrigins                map[string]struct{}

	mu                sync.Mutex
	wallets           map[string]*walletMaterial
	oid4vciAuthStates map[string]*pendingOID4VCIAuthState
}

type walletMaterial struct {
	ScopeKey                  string
	Subject                   string
	DIDMethod                 string
	KeySet                    *intcrypto.KeySet
	SigningAlgorithm          string
	CredentialJWT             string
	CredentialID              string
	CredentialFormat          string
	CredentialConfigurationID string
	Credentials               map[string]walletCredentialMaterial
	CreatedAt                 time.Time
	LastAccess                time.Time
}

type walletCredentialMaterial struct {
	CredentialID              string
	CredentialJWT             string
	Format                    string
	CredentialConfigurationID string
	VCT                       string
	Doctype                   string
	IssuedAt                  time.Time
	UpdatedAt                 time.Time
}

type walletRequestMatchSummary struct {
	QueryType               string   `json:"query_type,omitempty"`
	Matched                 bool     `json:"matched"`
	MatchedCredentialIDs    []string `json:"matched_credential_ids,omitempty"`
	MatchedCredentialCount  int      `json:"matched_credential_count"`
	RecommendedCredentialID string   `json:"recommended_credential_id,omitempty"`
	Reasons                 []string `json:"reasons,omitempty"`
}

type walletSubmitRequest struct {
	RequestID             string   `json:"request_id"`
	Request               string   `json:"request,omitempty"`
	WalletSubject         string   `json:"wallet_subject,omitempty"`
	Subject               string   `json:"subject,omitempty"`
	CredentialJWT         string   `json:"credential_jwt,omitempty"`
	CredentialID          string   `json:"credential_id,omitempty"`
	CredentialIDs         []string `json:"credential_ids,omitempty"`
	CredentialFormat      string   `json:"credential_format,omitempty"`
	CredentialConfigID    string   `json:"credential_configuration_id,omitempty"`
	Mode                  string   `json:"mode,omitempty"`
	Step                  string   `json:"step,omitempty"`
	ApproveExternalTrust  bool     `json:"approve_external_trust,omitempty"`
	VPToken               string   `json:"vp_token,omitempty"`
	DisclosureClaims      []string `json:"disclosure_claims,omitempty"`
	LookingGlassSessionID string   `json:"looking_glass_session_id,omitempty"`
}

type resolvedRequestContext struct {
	RequestID              string
	State                  string
	Nonce                  string
	ClientID               string
	ResponseMode           string
	ResponseURI            string
	Trusted                bool
	PresentationDefinition map[string]interface{}
}

type resolvedRequestEnvelope struct {
	RequestJWT       string
	RequestURI       string
	RequestID        string
	URIClientID      string
	DecodedHeader    map[string]interface{}
	DecodedPayload   map[string]interface{}
	RequestURISource string
}

type apiResolveRequest struct {
	RequestURI  string `json:"request_uri,omitempty"`
	OpenID4VP   string `json:"openid4vp_uri,omitempty"`
	RequestJWT  string `json:"request,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	TrustAccept bool   `json:"approve_external_trust,omitempty"`
}

type apiWalletRequest struct {
	WalletSubject         string   `json:"wallet_subject,omitempty"`
	CredentialJWT         string   `json:"credential_jwt,omitempty"`
	CredentialID          string   `json:"credential_id,omitempty"`
	CredentialIDs         []string `json:"credential_ids,omitempty"`
	CredentialFormat      string   `json:"credential_format,omitempty"`
	CredentialConfigID    string   `json:"credential_configuration_id,omitempty"`
	DisclosureClaims      []string `json:"disclosure_claims,omitempty"`
	RequestURI            string   `json:"request_uri,omitempty"`
	OpenID4VP             string   `json:"openid4vp_uri,omitempty"`
	RequestJWT            string   `json:"request,omitempty"`
	RequestID             string   `json:"request_id,omitempty"`
	ApproveExternalTrust  bool     `json:"approve_external_trust,omitempty"`
	LookingGlassSessionID string   `json:"looking_glass_session_id,omitempty"`
	ForceIssue            bool     `json:"force_issue,omitempty"`
}

type credentialSelectionOptions struct {
	ProvidedCredentialJWT string
	CredentialID          string
	CredentialFormat      string
	CredentialConfigID    string
	LookingGlassSessionID string
}

type issuedWalletCredential struct {
	CredentialJWT      string
	CredentialFormat   string
	CredentialConfigID string
}

type didWebResolutionResult struct {
	DidDocumentURL string                 `json:"did_document_url,omitempty"`
	Resolved       bool                   `json:"resolved"`
	DocumentID     string                 `json:"document_id,omitempty"`
	IDMatches      bool                   `json:"id_matches,omitempty"`
	MethodsFound   bool                   `json:"methods_found,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Document       map[string]interface{} `json:"document,omitempty"`
}

type trustEvaluation struct {
	TrustedTarget             bool                             `json:"trusted_target"`
	RequiresExternalAccept    bool                             `json:"requires_external_approval"`
	AllowExternalVerifiers    bool                             `json:"allow_external_verifiers"`
	ClientIDScheme            string                           `json:"client_id_scheme,omitempty"`
	DidWeb                    *didWebResolutionResult          `json:"did_web,omitempty"`
	RequestObjectVerification *requestObjectVerificationResult `json:"request_object_verification,omitempty"`
}

type requestObjectVerificationResult struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
	KeyType  string `json:"key_type,omitempty"`
}

type walletLifecycleEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Title     string                 `json:"title"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

func newWalletEvent(eventType, title string, data map[string]interface{}) walletLifecycleEvent {
	return walletLifecycleEvent{
		ID:        randomValue(12),
		Type:      eventType,
		Title:     title,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data:      data,
	}
}

type credentialSummary struct {
	Subject          string                 `json:"subject,omitempty"`
	ExpiresAt        string                 `json:"expires_at,omitempty"`
	IsSDJWT          bool                   `json:"is_sd_jwt"`
	Format           string                 `json:"format,omitempty"`
	VCT              string                 `json:"vct,omitempty"`
	Doctype          string                 `json:"doctype,omitempty"`
	CredentialTypes  []string               `json:"credential_types,omitempty"`
	DisclosureClaims []string               `json:"disclosure_claims,omitempty"`
	DisclosureCount  int                    `json:"disclosure_count,omitempty"`
	KeyBindingJWT    bool                   `json:"key_binding_jwt,omitempty"`
	Claims           map[string]interface{} `json:"claims,omitempty"`
}

//go:embed static/*
var walletStaticFS embed.FS

func main() {
	listenAddr := envOrDefault("WALLET_LISTEN_ADDR", ":8080")
	targetBaseURL := strings.TrimRight(strings.TrimSpace(envOrDefault("WALLET_TARGET_BASE_URL", "https://protocolsoup.com")), "/")
	issuerBaseURL := strings.TrimRight(strings.TrimSpace(envOrDefault("WALLET_ISSUER_BASE_URL", targetBaseURL)), "/")
	appTitle := strings.TrimSpace(envOrDefault("WALLET_APP_TITLE", "Protocol Soup Wallet"))
	defaultWalletSubject := strings.TrimSpace(envOrDefault("WALLET_DEFAULT_SUBJECT", "did:example:wallet:alice"))
	walletDIDMethod, err := resolveWalletDIDMethod(envOrDefault("WALLET_DID_METHOD", "key"))
	if err != nil {
		log.Fatalf("invalid WALLET_DID_METHOD: %v", err)
	}
	oid4vciClientID := strings.TrimSpace(envOrDefault("WALLET_OID4VCI_CLIENT_ID", "public-app"))
	oid4vciClientSecret := strings.TrimSpace(os.Getenv("WALLET_OID4VCI_CLIENT_SECRET"))
	walletSessionTTL := 20 * time.Minute
	if ttlRaw := strings.TrimSpace(os.Getenv("WALLET_SESSION_TTL")); ttlRaw != "" {
		ttl, err := time.ParseDuration(ttlRaw)
		if err != nil {
			log.Fatalf("invalid WALLET_SESSION_TTL %q: %v", ttlRaw, err)
		}
		walletSessionTTL = ttl
	}
	strictIsolation := parseBoolEnv("WALLET_STRICT_SESSION_ISOLATION", true)
	allowExternal := parseBoolEnv("WALLET_ALLOW_EXTERNAL_VERIFIERS", true)
	allowedCORSOrigins := parseOriginAllowList(envOrDefault("WALLET_ALLOWED_CORS_ORIGINS", "https://protocolsoup.com,https://www.protocolsoup.com,https://protocolsoup.fly.dev"))
	trustedVerifierAttestationIssuers := parseURLAllowList(os.Getenv("WALLET_TRUSTED_VERIFIER_ATTESTATION_ISSUERS"))

	parsedBaseURL, err := url.ParseRequestURI(targetBaseURL)
	if err != nil {
		log.Fatalf("invalid WALLET_TARGET_BASE_URL %q: %v", targetBaseURL, err)
	}
	if parsedBaseURL.Scheme != "http" && parsedBaseURL.Scheme != "https" {
		log.Fatalf("invalid WALLET_TARGET_BASE_URL %q: scheme must be http or https", targetBaseURL)
	}
	targetHost := strings.ToLower(strings.TrimSpace(parsedBaseURL.Host))
	if targetHost == "" {
		log.Fatalf("invalid WALLET_TARGET_BASE_URL %q: host is required", targetBaseURL)
	}
	parsedIssuerURL, err := url.ParseRequestURI(issuerBaseURL)
	if err != nil {
		log.Fatalf("invalid WALLET_ISSUER_BASE_URL %q: %v", issuerBaseURL, err)
	}
	if parsedIssuerURL.Scheme != "http" && parsedIssuerURL.Scheme != "https" {
		log.Fatalf("invalid WALLET_ISSUER_BASE_URL %q: scheme must be http or https", issuerBaseURL)
	}

	clientTimeout := 15 * time.Second
	if timeoutRaw := strings.TrimSpace(os.Getenv("WALLET_HTTP_TIMEOUT")); timeoutRaw != "" {
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			log.Fatalf("invalid WALLET_HTTP_TIMEOUT %q: %v", timeoutRaw, err)
		}
		clientTimeout = timeout
	}

	server := &walletHarnessServer{
		httpClient: &http.Client{
			Timeout: clientTimeout,
		},
		jwksFetcher:                       intcrypto.NewJWKSFetcher(5 * time.Minute),
		targetBaseURL:                     targetBaseURL,
		targetHost:                        targetHost,
		targetResponseURI:                 targetBaseURL + "/oid4vp/response",
		issuerBaseURL:                     issuerBaseURL,
		allowExternal:                     allowExternal,
		appTitle:                          appTitle,
		defaultWalletSubject:              defaultWalletSubject,
		walletDIDMethod:                   walletDIDMethod,
		trustedVerifierAttestationIssuers: trustedVerifierAttestationIssuers,
		oid4vciClientID:                   oid4vciClientID,
		oid4vciClientSecret:               oid4vciClientSecret,
		walletSessionTTL:                  walletSessionTTL,
		strictIsolation:                   strictIsolation,
		allowedCORSOrigins:                allowedCORSOrigins,
		wallets:                           make(map[string]*walletMaterial),
		oid4vciAuthStates:                 make(map[string]*pendingOID4VCIAuthState),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/submit", server.handleSubmit)
	mux.HandleFunc("/api/resolve", server.handleAPIResolve)
	mux.HandleFunc("/api/session", server.handleAPISession)
	mux.HandleFunc("/api/issue", server.handleAPIIssue)
	mux.HandleFunc("/api/import", server.handleAPIImport)
	mux.HandleFunc("/api/oid4vci/callback", server.handleAPIOID4VCICallback)
	mux.HandleFunc("/api/preview", server.handleAPIPreview)
	mux.HandleFunc("/api/present", server.handleAPIPresent)
	mux.HandleFunc("/.well-known/did.json", server.handleWalletDIDDocument)
	mux.HandleFunc("/wallet/", server.handleWalletDIDDocument)
	mux.HandleFunc("/", server.handleWalletApp)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           withNoStoreHeaders(withCORS(mux, server.allowedCORSOrigins)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("wallet harness listening on %s", listenAddr)
	log.Printf("wallet harness target base URL: %s", targetBaseURL)
	log.Printf("wallet harness issuer base URL: %s", issuerBaseURL)
	log.Printf("wallet harness external verifier support: %t", allowExternal)
	log.Printf("wallet harness app title: %s", appTitle)
	log.Printf("wallet harness did method: %s", walletDIDMethod)
	log.Printf("wallet harness strict session isolation: %t", strictIsolation)
	log.Printf("wallet harness wallet session ttl: %s", walletSessionTTL)
	log.Printf("wallet harness CORS origins: %d configured", len(allowedCORSOrigins))
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("wallet harness server failed: %v", err)
	}
}

func (s *walletHarnessServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *walletHarnessServer) handleWalletApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	staticFS, err := fs.Sub(walletStaticFS, "static")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "wallet static bundle is unavailable",
		})
		return
	}

	cleanPath := path.Clean("/" + strings.TrimSpace(r.URL.Path))
	relativePath := strings.TrimPrefix(cleanPath, "/")
	if relativePath == "." {
		relativePath = ""
	}

	serveIndex := func() {
		indexBytes, readErr := fs.ReadFile(staticFS, "index.html")
		if readErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "server_error",
				"error_description": "wallet index is unavailable",
			})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexBytes)
	}

	if relativePath == "" {
		serveIndex()
		return
	}
	if strings.HasPrefix(relativePath, "api/") || relativePath == "submit" || relativePath == "health" {
		http.NotFound(w, r)
		return
	}
	if strings.Contains(path.Base(relativePath), ".") {
		if _, statErr := fs.Stat(staticFS, relativePath); statErr == nil {
			http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	serveIndex()
}

func (s *walletHarnessServer) handleWalletDIDDocument(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	requestSubject, err := walletDIDSubjectFromDocumentRequest(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.pruneExpiredWalletsLocked(now)
	var wallet *walletMaterial
	for _, candidate := range s.wallets {
		if candidate == nil {
			continue
		}
		if strings.TrimSpace(candidate.Subject) == strings.TrimSpace(requestSubject) {
			candidate.LastAccess = now
			wallet = candidate
			break
		}
	}
	s.mu.Unlock()
	if wallet == nil {
		http.NotFound(w, r)
		return
	}

	document, err := buildWalletDIDDocument(wallet)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(document)
}

func (s *walletHarnessServer) handleAPIResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req apiResolveRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), apiWalletRequest{
		RequestURI: req.RequestURI,
		OpenID4VP:  req.OpenID4VP,
		RequestJWT: req.RequestJWT,
		RequestID:  req.RequestID,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	matchSummary := walletRequestMatchSummary{}
	if scopeKey, _, scopeErr := s.resolveAPIScopeKey(w, r); scopeErr == nil {
		subject := scopedWalletSubject(s.defaultWalletSubject, scopeKey)
		if wallet, walletErr := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r)); walletErr == nil {
			matchSummary = summarizeWalletRequestMatches(wallet, envelope, requestContext)
		}
	}

	var lgEvents []walletLifecycleEvent
	lgEvents = append(lgEvents, newWalletEvent("request_object_fetch", "Request Object Fetched", map[string]interface{}{
		"source":        envelope.RequestURISource,
		"request_uri":   envelope.RequestURI,
		"response_mode": requestContext.ResponseMode,
		"client_id":     requestContext.ClientID,
	}))
	lgEvents = append(lgEvents, newWalletEvent("trust_evaluation", "Trust Evaluation", map[string]interface{}{
		"client_id_scheme":            trust.ClientIDScheme,
		"trusted_target":              trust.TrustedTarget,
		"did_web":                     trust.DidWeb,
		"request_object_verification": trust.RequestObjectVerification,
	}))
	if matchSummary.QueryType != "" {
		lgEvents = append(lgEvents, newWalletEvent("credential_matching", "Credential Matching", map[string]interface{}{
			"query_type":                matchSummary.QueryType,
			"matched":                   matchSummary.Matched,
			"matched_credential_count":  matchSummary.MatchedCredentialCount,
			"recommended_credential_id": matchSummary.RecommendedCredentialID,
			"reasons":                   matchSummary.Reasons,
		}))
	}

	resolveResponse := map[string]interface{}{
		"request_id":            requestContext.RequestID,
		"request_uri":           envelope.RequestURI,
		"request":               envelope.RequestJWT,
		"request_uri_source":    envelope.RequestURISource,
		"response_mode":         requestContext.ResponseMode,
		"response_uri":          requestContext.ResponseURI,
		"client_id":             requestContext.ClientID,
		"state":                 requestContext.State,
		"nonce":                 requestContext.Nonce,
		"scope":                 asString(envelope.DecodedPayload["scope"]),
		"dcql_query":            envelope.DecodedPayload["dcql_query"],
		"credential_matches":    matchSummary,
		"request_header":        envelope.DecodedHeader,
		"request_payload":       envelope.DecodedPayload,
		"trust":                 trust,
		"_looking_glass_events": lgEvents,
	}
	if inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope); inferredFormat != "" {
		resolveResponse["inferred_credential_format"] = inferredFormat
		resolveResponse["inferred_credential_configuration_id"] = inferredConfigID
	}
	writeJSON(w, http.StatusOK, resolveResponse)
}

func (s *walletHarnessServer) handleAPISession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	scopeKey, sessionID, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	subject := scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}
	var walletKeyID string
	var keyThumbprint string
	if pubJWK, tp, jwkErr := walletActiveJWK(wallet); jwkErr == nil {
		walletKeyID = pubJWK.Kid
		keyThumbprint = tp
	}
	expiresInSeconds := 0
	if s.walletSessionTTL > 0 {
		remaining := int(time.Until(wallet.LastAccess.Add(s.walletSessionTTL)).Seconds())
		if remaining > 0 {
			expiresInSeconds = remaining
		}
	}
	credentialEntries := walletCredentialEntries(wallet)
	activeCredentialSummary := summarizeCredential(wallet.CredentialJWT)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"app_title":                   s.appTitle,
		"wallet_session_id":           sessionID,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"wallet_did_method":           wallet.DIDMethod,
		"wallet_signing_algorithm":    wallet.SigningAlgorithm,
		"wallet_key_id":               walletKeyID,
		"wallet_key_thumbprint":       keyThumbprint,
		"wallet_session_ttl_seconds":  int(s.walletSessionTTL.Seconds()),
		"wallet_session_expires_in":   expiresInSeconds,
		"credential_present":          strings.TrimSpace(wallet.CredentialJWT) != "",
		"credential_id":               strings.TrimSpace(wallet.CredentialID),
		"credential_format":           strings.TrimSpace(wallet.CredentialFormat),
		"credential_configuration_id": strings.TrimSpace(wallet.CredentialConfigurationID),
		"credential_summary":          activeCredentialSummary,
		"credentials":                 credentialEntries,
	})
}

func (s *walletHarnessServer) handleAPIIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req apiWalletRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	scopeKey, _, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	subject := strings.TrimSpace(req.WalletSubject)
	if subject == "" {
		subject = scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	}
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	options := credentialSelectionOptions{
		ProvidedCredentialJWT: strings.TrimSpace(req.CredentialJWT),
		CredentialID:          strings.TrimSpace(req.CredentialID),
		CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
		CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
		LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
	}
	credentialSource := ""
	if req.ForceIssue {
		issuedCredential, issueErr := s.issueCredentialForWallet(r.Context(), wallet, options)
		if issueErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": issueErr.Error(),
			})
			return
		}
		if bindErr := s.bindCredential(wallet, issuedCredential.CredentialJWT, issuedCredential.CredentialConfigID, issuedCredential.CredentialFormat); bindErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": bindErr.Error(),
			})
			return
		}
		credentialSource = "forced_oid4vci"
	} else {
		credentialSource, err = s.ensureWalletCredential(r.Context(), wallet, options)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"credential_jwt":              wallet.CredentialJWT,
		"credential_summary":          summarizeCredential(wallet.CredentialJWT),
		"credentials":                 walletCredentialEntries(wallet),
	})
}

func (s *walletHarnessServer) handleAPIPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req apiWalletRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	req.DisclosureClaims = normalizeDisclosureClaims(req.DisclosureClaims)

	scopeKey, _, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	subject := strings.TrimSpace(req.WalletSubject)
	if subject == "" {
		subject = scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	}
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	if err := s.ensurePresentationRequestTrust(trust, false, false); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	credOpts := credentialSelectionOptions{
		ProvidedCredentialJWT: strings.TrimSpace(req.CredentialJWT),
		CredentialID:          strings.TrimSpace(req.CredentialID),
		CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
		CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
		LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
	}
	if credOpts.CredentialFormat == "" && credOpts.CredentialConfigID == "" {
		inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope)
		if inferredFormat != "" {
			credOpts.CredentialFormat = inferredFormat
			credOpts.CredentialConfigID = inferredConfigID
		}
	}
	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credOpts)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}

	matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, requestContext)
	if matchSummary.QueryType != "" && !matchSummary.Matched {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet does not have a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}
	if matchSummary.QueryType != "" && !matchedActiveCredential {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet could not activate a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}

	presentedCredential, disclosureClaims, err := filterSDJWTDisclosures(wallet.CredentialJWT, req.DisclosureClaims)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	vpToken, vpFormat, err := s.createVPToken(wallet, requestContext, presentedCredential)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("create vp_token: %v", err),
		})
		return
	}
	var lgEvents []walletLifecycleEvent
	lgEvents = append(lgEvents, newWalletEvent("trust_evaluation", "Trust Evaluation", map[string]interface{}{
		"client_id_scheme":            trust.ClientIDScheme,
		"trusted_target":              trust.TrustedTarget,
		"request_object_verification": trust.RequestObjectVerification,
	}))
	if matchSummary.QueryType != "" {
		lgEvents = append(lgEvents, newWalletEvent("credential_matching", "Credential Matching", map[string]interface{}{
			"query_type":                matchSummary.QueryType,
			"matched":                   matchSummary.Matched,
			"matched_credential_count":  matchSummary.MatchedCredentialCount,
			"recommended_credential_id": matchSummary.RecommendedCredentialID,
			"matched_credential_ids":    matchSummary.MatchedCredentialIDs,
		}))
	}
	if len(disclosureClaims) > 0 {
		lgEvents = append(lgEvents, newWalletEvent("sd_jwt_disclosure", "SD-JWT Disclosure Selection", map[string]interface{}{
			"selected_claims": disclosureClaims,
			"claim_count":     len(disclosureClaims),
		}))
	}
	lgEvents = append(lgEvents, newWalletEvent("vp_token_construction", "VP Token Constructed", map[string]interface{}{
		"format":         vpFormat,
		"algorithm":      wallet.SigningAlgorithm,
		"credential_id":  wallet.CredentialID,
		"holder_binding": wallet.Subject,
	}))

	previewResponse := map[string]interface{}{
		"mode":                        "preview",
		"request_id":                  requestContext.RequestID,
		"request_uri":                 envelope.RequestURI,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_matches":          matchSummary,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"vp_token":                    vpToken,
		"vp_format":                   vpFormat,
		"request_header":              envelope.DecodedHeader,
		"request_payload":             envelope.DecodedPayload,
		"trust":                       trust,
		"_looking_glass_events":       lgEvents,
	}
	if vpFormat == "dc+sd-jwt" {
		if sdEnvelope, parseErr := vc.ParseSDJWTEnvelope(vpToken); parseErr == nil {
			previewResponse["vp_sd_jwt_envelope"] = sdEnvelope
		}
	} else if strings.HasPrefix(strings.TrimSpace(vpToken), "{") {
		var vpDocument map[string]interface{}
		if parseErr := json.Unmarshal([]byte(vpToken), &vpDocument); parseErr == nil {
			vpProof, _ := vpDocument["proof"].(map[string]interface{})
			previewResponse["vp_document"] = vpDocument
			previewResponse["vp_proof"] = vpProof
		}
	} else {
		vpHeader := map[string]interface{}{}
		vpPayload := map[string]interface{}{}
		if decodedVP, decodeErr := intcrypto.DecodeTokenWithoutValidation(vpToken); decodeErr == nil && decodedVP != nil {
			vpHeader = decodedVP.Header
			vpPayload = decodedVP.Payload
		}
		previewResponse["vp_header"] = vpHeader
		previewResponse["vp_payload"] = vpPayload
	}
	writeJSON(w, http.StatusOK, previewResponse)
}

func (s *walletHarnessServer) handleAPIPresent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req apiWalletRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	req.DisclosureClaims = normalizeDisclosureClaims(req.DisclosureClaims)

	scopeKey, _, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	subject := strings.TrimSpace(req.WalletSubject)
	if subject == "" {
		subject = scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	}
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	if err := s.ensurePresentationRequestTrust(trust, true, req.ApproveExternalTrust); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	credOpts := credentialSelectionOptions{
		ProvidedCredentialJWT: strings.TrimSpace(req.CredentialJWT),
		CredentialID:          strings.TrimSpace(req.CredentialID),
		CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
		CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
		LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
	}
	if credOpts.CredentialFormat == "" && credOpts.CredentialConfigID == "" {
		inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope)
		if inferredFormat != "" {
			credOpts.CredentialFormat = inferredFormat
			credOpts.CredentialConfigID = inferredConfigID
		}
	}
	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credOpts)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}

	matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, requestContext)
	if matchSummary.QueryType != "" && !matchSummary.Matched {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet does not have a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}
	if matchSummary.QueryType != "" && !matchedActiveCredential {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet could not activate a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}

	presentedCredential, disclosureClaims, err := filterSDJWTDisclosures(wallet.CredentialJWT, req.DisclosureClaims)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	vpToken, _, err := s.createVPToken(wallet, requestContext, presentedCredential)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("create vp_token: %v", err),
		})
		return
	}
	var lgEvents []walletLifecycleEvent
	lgEvents = append(lgEvents, newWalletEvent("trust_evaluation", "Trust Evaluation", map[string]interface{}{
		"client_id_scheme":            trust.ClientIDScheme,
		"trusted_target":              trust.TrustedTarget,
		"request_object_verification": trust.RequestObjectVerification,
	}))
	if matchSummary.QueryType != "" {
		lgEvents = append(lgEvents, newWalletEvent("credential_matching", "Credential Matching", map[string]interface{}{
			"query_type":                matchSummary.QueryType,
			"matched":                   matchSummary.Matched,
			"matched_credential_count":  matchSummary.MatchedCredentialCount,
			"recommended_credential_id": matchSummary.RecommendedCredentialID,
			"matched_credential_ids":    matchSummary.MatchedCredentialIDs,
		}))
	}
	lgEvents = append(lgEvents, newWalletEvent("vp_token_construction", "VP Token Constructed", map[string]interface{}{
		"format":         wallet.CredentialFormat,
		"algorithm":      wallet.SigningAlgorithm,
		"credential_id":  wallet.CredentialID,
		"holder_binding": wallet.Subject,
	}))

	upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, strings.TrimSpace(req.LookingGlassSessionID))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}
	lgEvents = append(lgEvents, newWalletEvent("submission_result", "Submitted to Verifier", map[string]interface{}{
		"upstream_status": upstreamStatus,
		"response_uri":    requestContext.ResponseURI,
		"response_mode":   requestContext.ResponseMode,
	}))

	writeJSON(w, upstreamStatus, map[string]interface{}{
		"mode":                        "present",
		"request_id":                  requestContext.RequestID,
		"request_uri":                 envelope.RequestURI,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_matches":          matchSummary,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"upstream_status":             upstreamStatus,
		"upstream_body":               upstreamBody,
		"external_trust_approved":     req.ApproveExternalTrust,
		"trust":                       trust,
		"_looking_glass_events":       lgEvents,
	})
}

func (s *walletHarnessServer) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	var req walletSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": fmt.Sprintf("invalid JSON body: %v", err),
		})
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.Request = strings.TrimSpace(req.Request)
	req.WalletSubject = strings.TrimSpace(req.WalletSubject)
	req.Subject = strings.TrimSpace(req.Subject)
	req.CredentialJWT = strings.TrimSpace(req.CredentialJWT)
	req.CredentialID = strings.TrimSpace(req.CredentialID)
	req.CredentialFormat = strings.TrimSpace(req.CredentialFormat)
	req.CredentialConfigID = strings.TrimSpace(req.CredentialConfigID)
	for idx := range req.CredentialIDs {
		req.CredentialIDs[idx] = strings.TrimSpace(req.CredentialIDs[idx])
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	req.Step = strings.ToLower(strings.TrimSpace(req.Step))
	req.VPToken = strings.TrimSpace(req.VPToken)
	req.LookingGlassSessionID = strings.TrimSpace(req.LookingGlassSessionID)
	req.DisclosureClaims = normalizeDisclosureClaims(req.DisclosureClaims)
	if req.Mode == "" {
		req.Mode = "one_click"
	}

	scopeKey, err := s.resolveWalletScopeKey(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	subject := req.WalletSubject
	if subject == "" {
		subject = req.Subject
	}
	if subject == "" {
		subject = scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	}
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}
	switch req.Mode {
	case "stepwise":
		s.handleStepwiseSubmit(w, r, req, wallet)
		return
	case "one_click":
		// continue to one-click mode below
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": fmt.Sprintf("unsupported mode %q", req.Mode),
		})
		return
	}

	if req.RequestID == "" || req.Request == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request_id and request are required for one_click mode",
		})
		return
	}

	envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), apiWalletRequest{
		RequestID:  req.RequestID,
		RequestJWT: req.Request,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	if err := s.ensurePresentationRequestTrust(trust, true, req.ApproveExternalTrust); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	credOpts := credentialSelectionOptions{
		ProvidedCredentialJWT: req.CredentialJWT,
		CredentialID:          req.CredentialID,
		CredentialFormat:      req.CredentialFormat,
		CredentialConfigID:    req.CredentialConfigID,
		LookingGlassSessionID: req.LookingGlassSessionID,
	}
	if credOpts.CredentialFormat == "" && credOpts.CredentialConfigID == "" {
		inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope)
		if inferredFormat != "" {
			credOpts.CredentialFormat = inferredFormat
			credOpts.CredentialConfigID = inferredConfigID
		}
	}
	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credOpts)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}

	matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, requestContext)
	if matchSummary.QueryType != "" && !matchSummary.Matched {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet does not have a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}
	if matchSummary.QueryType != "" && !matchedActiveCredential {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":              "invalid_request",
			"error_description":  "wallet could not activate a credential that satisfies the presentation request",
			"credential_matches": matchSummary,
		})
		return
	}

	vpToken := req.VPToken
	disclosureClaims := req.DisclosureClaims
	if vpToken == "" {
		presentedCredential, selectedDisclosureClaims, err := filterSDJWTDisclosures(wallet.CredentialJWT, req.DisclosureClaims)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		disclosureClaims = selectedDisclosureClaims
		vpToken, _, err = s.createVPToken(wallet, requestContext, presentedCredential)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("create vp_token: %v", err),
			})
			return
		}
	}

	var lgEvents []walletLifecycleEvent
	lgEvents = append(lgEvents, newWalletEvent("vp_token_construction", "VP Token Constructed", map[string]interface{}{
		"format":         wallet.CredentialFormat,
		"algorithm":      wallet.SigningAlgorithm,
		"credential_id":  wallet.CredentialID,
		"holder_binding": wallet.Subject,
	}))

	upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, req.LookingGlassSessionID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}
	lgEvents = append(lgEvents, newWalletEvent("submission_result", "Submitted to Verifier", map[string]interface{}{
		"upstream_status": upstreamStatus,
		"response_uri":    requestContext.ResponseURI,
		"response_mode":   requestContext.ResponseMode,
	}))

	writeJSON(w, upstreamStatus, map[string]interface{}{
		"mode":                        "one_click",
		"request_id":                  requestContext.RequestID,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_matches":          matchSummary,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"upstream_status":             upstreamStatus,
		"upstream_body":               upstreamBody,
		"external_trust_approved":     req.ApproveExternalTrust,
		"trust":                       trust,
		"wallet_stepwise_hint":        "use mode=stepwise for keygen/issuance/presentation ceremony controls",
		"_looking_glass_events":       lgEvents,
	})
}

func decodeJSONBody(r *http.Request, target interface{}) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("request body is required")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("request body must contain a single JSON object")
	}
	return nil
}

func (s *walletHarnessServer) resolveAPIScopeKey(w http.ResponseWriter, r *http.Request) (string, string, error) {
	sessionID := strings.TrimSpace(r.Header.Get("X-Wallet-Session"))
	if sessionID == "" {
		sessionID = strings.TrimSpace(r.URL.Query().Get("wallet_session"))
	}
	if sessionID == "" {
		if cookie, err := r.Cookie("ps_wallet_session"); err == nil {
			sessionID = strings.TrimSpace(cookie.Value)
		}
	}
	if sessionID == "" {
		sessionID = randomValue(24)
	}
	if !isSafeSessionToken(sessionID) {
		return "", "", fmt.Errorf("wallet session id contains unsupported characters")
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ps_wallet_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.walletSessionTTL.Seconds()),
	})
	return "web:" + sessionID, sessionID, nil
}

func isSafeSessionToken(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if len(trimmed) > 128 {
		return false
	}
	for _, ch := range trimmed {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func (s *walletHarnessServer) resolveWalletPresentationContext(
	ctx context.Context,
	req apiWalletRequest,
) (*resolvedRequestEnvelope, *resolvedRequestContext, trustEvaluation, error) {
	envelope, err := s.resolveRequestEnvelope(ctx, apiResolveRequest{
		RequestURI: req.RequestURI,
		OpenID4VP:  req.OpenID4VP,
		RequestJWT: req.RequestJWT,
		RequestID:  req.RequestID,
	})
	if err != nil {
		return nil, nil, trustEvaluation{}, err
	}
	requestContext, err := s.resolveRequestContextWithOptions(envelope.RequestID, envelope.RequestJWT, true, envelope.URIClientID)
	if err != nil {
		return nil, nil, trustEvaluation{}, err
	}
	trust := s.evaluateTrust(requestContext, envelope.DecodedPayload)
	keyType, err := s.verifyRequestObjectSignature(ctx, envelope, requestContext, trust)
	if err != nil {
		trust.RequestObjectVerification = &requestObjectVerificationResult{
			Verified: false,
			Error:    err.Error(),
		}
		log.Printf("request object signature verification: %v", err)
	} else if keyType != "" {
		trust.RequestObjectVerification = &requestObjectVerificationResult{Verified: true, KeyType: keyType}
	}
	return envelope, requestContext, trust, nil
}

func (s *walletHarnessServer) ensurePresentationRequestTrust(
	trust trustEvaluation,
	requireExternalApproval bool,
	externalApproval bool,
) error {
	if requiresRequestObjectVerification(trust.ClientIDScheme) {
		if trust.RequestObjectVerification == nil {
			return fmt.Errorf("request object verification is required for client_id_scheme %q", trust.ClientIDScheme)
		}
		if !trust.RequestObjectVerification.Verified {
			if errDescription := strings.TrimSpace(trust.RequestObjectVerification.Error); errDescription != "" {
				return fmt.Errorf("request object verification failed: %s", errDescription)
			}
			return fmt.Errorf("request object verification failed for client_id_scheme %q", trust.ClientIDScheme)
		}
	}
	if !trust.TrustedTarget {
		if !s.allowExternal {
			return fmt.Errorf("external verifier requests are disabled by wallet configuration")
		}
		if requireExternalApproval && trust.RequiresExternalAccept && !externalApproval {
			return fmt.Errorf("external verifier trust approval is required")
		}
	}
	return nil
}

func requiresRequestObjectVerification(clientIDScheme string) bool {
	switch strings.TrimSpace(clientIDScheme) {
	case "decentralized_identifier", "verifier_attestation", "x509_san_dns", "x509_hash", "openid_federation":
		return true
	default:
		return false
	}
}

func (s *walletHarnessServer) resolveRequestEnvelope(ctx context.Context, req apiResolveRequest) (*resolvedRequestEnvelope, error) {
	requestURI := strings.TrimSpace(req.RequestURI)
	openID4VPURI := strings.TrimSpace(req.OpenID4VP)
	requestJWT := strings.TrimSpace(req.RequestJWT)
	requestID := strings.TrimSpace(req.RequestID)
	requestSource := ""

	uriClientID := ""
	if openID4VPURI != "" {
		uriRequestURI, uriRequestJWT, parsedClientID, err := parseOpenID4VPURI(openID4VPURI)
		if err != nil {
			return nil, err
		}
		uriClientID = parsedClientID
		if requestURI == "" && uriRequestURI != "" {
			requestURI = uriRequestURI
			requestSource = "openid4vp_uri"
		}
		if requestJWT == "" && uriRequestJWT != "" {
			requestJWT = uriRequestJWT
			if requestSource == "" {
				requestSource = "openid4vp_uri"
			}
		}
	}
	if requestJWT == "" && requestURI == "" {
		return nil, fmt.Errorf("openid4vp_uri or request_uri or request is required")
	}
	if requestJWT == "" {
		normalizedRequestURI, err := s.validateExternalURL(requestURI)
		if err != nil {
			return nil, fmt.Errorf("request_uri is not allowed: %w", err)
		}
		requestURI = normalizedRequestURI
		fetchedRequestJWT, fetchedRequestID, err := s.fetchRequestObject(ctx, requestURI)
		if err != nil {
			return nil, err
		}
		requestJWT = fetchedRequestJWT
		if requestID == "" {
			requestID = fetchedRequestID
		}
		if requestSource == "" {
			requestSource = "request_uri"
		}
	}
	if requestSource == "" {
		requestSource = "request"
	}

	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		return nil, fmt.Errorf("decode request object jwt: %w", err)
	}
	// OID4VP Section 5.9.3/5.10.1: request objects MUST use typ "oauth-authz-req+jwt"
	if typHeader := strings.TrimSpace(asString(decodedRequest.Header["typ"])); typHeader != "oauth-authz-req+jwt" {
		return nil, fmt.Errorf("request object typ header must be oauth-authz-req+jwt, got %q", typHeader)
	}
	if requestID == "" {
		requestID = strings.TrimSpace(asString(decodedRequest.Payload["jti"]))
	}
	if requestID == "" {
		sum := sha256.Sum256([]byte(requestJWT))
		requestID = "ext-" + hex.EncodeToString(sum[:12])
	}
	header := make(map[string]interface{}, len(decodedRequest.Header))
	for key, value := range decodedRequest.Header {
		header[key] = value
	}
	payload := make(map[string]interface{}, len(decodedRequest.Payload))
	for key, value := range decodedRequest.Payload {
		payload[key] = value
	}
	return &resolvedRequestEnvelope{
		RequestJWT:       requestJWT,
		RequestURI:       requestURI,
		RequestID:        requestID,
		URIClientID:      uriClientID,
		DecodedHeader:    header,
		DecodedPayload:   payload,
		RequestURISource: requestSource,
	}, nil
}

func parseOpenID4VPURI(raw string) (requestURI string, requestJWT string, clientID string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", "", fmt.Errorf("openid4vp_uri is required")
	}
	parsedURI, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("invalid openid4vp_uri: %w", parseErr)
	}
	if !strings.EqualFold(parsedURI.Scheme, "openid4vp") {
		return "", "", "", fmt.Errorf("unsupported URI scheme %q expected openid4vp", parsedURI.Scheme)
	}
	query := parsedURI.Query()
	requestURI = strings.TrimSpace(query.Get("request_uri"))
	requestJWT = strings.TrimSpace(query.Get("request"))
	clientID = strings.TrimSpace(query.Get("client_id"))
	if requestURI == "" && requestJWT == "" {
		return "", "", "", fmt.Errorf("openid4vp_uri must include request_uri or request parameter")
	}
	return requestURI, requestJWT, clientID, nil
}

func (s *walletHarnessServer) validateExternalURL(raw string) (string, error) {
	normalized := strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not allowed")
	}
	hostWithPort := strings.ToLower(strings.TrimSpace(parsed.Host))
	if hostWithPort == "" {
		return "", fmt.Errorf("URL host is required")
	}
	if hostWithPort == s.targetHost {
		return parsed.String(), nil
	}
	if !s.allowExternal {
		return "", fmt.Errorf("URL host %q is not allowed", hostWithPort)
	}

	hostName := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if hostName == "" {
		return "", fmt.Errorf("URL hostname is required")
	}
	if parsed.Scheme != "https" {
		isLocalDevHost := hostName == "localhost" || strings.HasPrefix(hostName, "127.")
		if !isLocalDevHost {
			return "", fmt.Errorf("external URL scheme %q is not allowed", parsed.Scheme)
		}
	}
	if hostName == "localhost" || strings.HasSuffix(hostName, ".local") || strings.HasSuffix(hostName, ".internal") {
		return "", fmt.Errorf("external URL host %q is not allowed", hostName)
	}
	if parsedIP := net.ParseIP(hostName); parsedIP != nil {
		if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() || parsedIP.IsMulticast() || parsedIP.IsUnspecified() {
			return "", fmt.Errorf("external URL host %q is not allowed", hostName)
		}
	}
	return parsed.String(), nil
}

func (s *walletHarnessServer) fetchRequestObject(ctx context.Context, requestURI string) (string, string, error) {
	methods := []string{http.MethodGet, http.MethodPost}
	var methodErrors []string
	for _, method := range methods {
		var bodyReader io.Reader
		if method == http.MethodPost {
			bodyReader = strings.NewReader(url.Values{}.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, requestURI, bodyReader)
		if err != nil {
			methodErrors = append(methodErrors, fmt.Sprintf("%s: build failed: %v", method, err))
			continue
		}
		req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, application/json, */*")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			methodErrors = append(methodErrors, fmt.Sprintf("%s: fetch failed: %v", method, err))
			continue
		}
		responseBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			methodErrors = append(methodErrors, fmt.Sprintf("%s: %d %s", method, resp.StatusCode, oneLine(string(responseBytes))))
			continue
		}
		trimmedBody := strings.TrimSpace(string(responseBytes))
		if trimmedBody == "" {
			methodErrors = append(methodErrors, fmt.Sprintf("%s: empty response body", method))
			continue
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(responseBytes, &payload); err == nil {
			if parsedRequest := strings.TrimSpace(asString(payload["request"])); parsedRequest != "" {
				return parsedRequest, strings.TrimSpace(asString(payload["request_id"])), nil
			}
		}
		var directJWT string
		if err := json.Unmarshal(responseBytes, &directJWT); err == nil {
			directJWT = strings.TrimSpace(directJWT)
			if directJWT != "" {
				return directJWT, "", nil
			}
		}
		if strings.Count(trimmedBody, ".") >= 2 {
			return trimmedBody, "", nil
		}
		methodErrors = append(methodErrors, fmt.Sprintf("%s: response did not contain a request object JWT", method))
	}
	return "", "", fmt.Errorf("request_uri fetch failed: %s", strings.Join(methodErrors, "; "))
}

func (s *walletHarnessServer) evaluateTrust(requestContext *resolvedRequestContext, requestPayload map[string]interface{}) trustEvaluation {
	clientIDScheme := inferClientIDScheme(requestContext.ClientID, requestPayload)
	trust := trustEvaluation{
		TrustedTarget:          requestContext.Trusted,
		RequiresExternalAccept: !requestContext.Trusted && s.allowExternal,
		AllowExternalVerifiers: s.allowExternal,
		ClientIDScheme:         clientIDScheme,
	}
	didWebID := extractDidWebIdentifier(requestContext.ClientID)
	if didWebID != "" {
		resolution := s.resolveDIDWeb(context.Background(), didWebID)
		trust.DidWeb = &resolution
	}
	return trust
}

func inferClientIDScheme(clientID string, requestPayload map[string]interface{}) string {
	claimedScheme := strings.TrimSpace(asString(requestPayload["client_id_scheme"]))
	if claimedScheme != "" {
		return claimedScheme
	}
	normalizedClientID := strings.TrimSpace(clientID)
	switch {
	case strings.HasPrefix(normalizedClientID, "verifier_attestation:"):
		return "verifier_attestation"
	case strings.HasPrefix(normalizedClientID, "x509_san_dns:"):
		return "x509_san_dns"
	case strings.HasPrefix(normalizedClientID, "x509_hash:"):
		return "x509_hash"
	case strings.HasPrefix(normalizedClientID, "openid_federation:"):
		return "openid_federation"
	case strings.HasPrefix(normalizedClientID, "decentralized_identifier:"):
		return "decentralized_identifier"
	case strings.HasPrefix(normalizedClientID, "did:"):
		return "decentralized_identifier"
	case strings.HasPrefix(normalizedClientID, "redirect_uri:"):
		return "redirect_uri"
	default:
		return "redirect_uri"
	}
}

func extractDidWebIdentifier(clientID string) string {
	normalizedClientID := strings.TrimSpace(clientID)
	if strings.HasPrefix(normalizedClientID, "decentralized_identifier:") {
		normalizedClientID = strings.TrimSpace(strings.TrimPrefix(normalizedClientID, "decentralized_identifier:"))
	}
	if strings.HasPrefix(normalizedClientID, "did:web:") {
		return normalizedClientID
	}
	return ""
}

func didWebDocumentURL(did string) (string, error) {
	normalized := strings.TrimSpace(did)
	if !strings.HasPrefix(normalized, "did:web:") {
		return "", fmt.Errorf("unsupported DID %q expected did:web", did)
	}
	identifier := strings.TrimPrefix(normalized, "did:web:")
	if identifier == "" {
		return "", fmt.Errorf("did:web identifier is empty")
	}
	segments := strings.Split(identifier, ":")
	hostSegment, err := url.PathUnescape(strings.TrimSpace(segments[0]))
	if err != nil {
		return "", fmt.Errorf("decode did:web host: %w", err)
	}
	if hostSegment == "" {
		return "", fmt.Errorf("did:web host is empty")
	}
	pathSegments := make([]string, 0, len(segments)-1)
	for _, segment := range segments[1:] {
		decodedSegment, err := url.PathUnescape(strings.TrimSpace(segment))
		if err != nil {
			return "", fmt.Errorf("decode did:web path segment: %w", err)
		}
		if decodedSegment == "" {
			continue
		}
		pathSegments = append(pathSegments, decodedSegment)
	}
	if len(pathSegments) == 0 {
		return "https://" + hostSegment + "/.well-known/did.json", nil
	}
	return "https://" + hostSegment + "/" + strings.Join(pathSegments, "/") + "/did.json", nil
}

func (s *walletHarnessServer) resolveDIDWeb(ctx context.Context, did string) didWebResolutionResult {
	result := didWebResolutionResult{}
	documentURL, err := didWebDocumentURL(did)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	normalizedDocumentURL, err := s.validateExternalURL(documentURL)
	if err != nil {
		result.Error = fmt.Sprintf("validate did:web document URL: %v", err)
		return result
	}
	result.DidDocumentURL = normalizedDocumentURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedDocumentURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("build did:web request: %v", err)
		return result
	}
	req.Header.Set("Accept", "application/did+json, application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("fetch did:web document: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("did:web document returned %d: %s", resp.StatusCode, oneLine(string(body)))
		return result
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		result.Error = fmt.Sprintf("decode did:web document: %v", err)
		return result
	}
	result.Resolved = true
	result.Document = payload
	result.DocumentID = strings.TrimSpace(asString(payload["id"]))
	result.IDMatches = result.DocumentID == strings.TrimSpace(did)
	authenticationMethods, hasAuth := payload["authentication"].([]interface{})
	assertionMethods, hasAssertion := payload["assertionMethod"].([]interface{})
	verificationMethods, hasVerification := payload["verificationMethod"].([]interface{})
	result.MethodsFound = (hasAuth && len(authenticationMethods) > 0) || (hasAssertion && len(assertionMethods) > 0) || (hasVerification && len(verificationMethods) > 0)
	return result
}

func (s *walletHarnessServer) verifyRequestObjectSignature(
	ctx context.Context,
	envelope *resolvedRequestEnvelope,
	requestContext *resolvedRequestContext,
	trust trustEvaluation,
) (string, error) {
	switch trust.ClientIDScheme {
	case "", "redirect_uri":
		return "", nil
	case "x509_san_dns":
		return s.verifyX509SANDNSRequestObjectSignature(envelope, requestContext)
	case "verifier_attestation":
		return s.verifyVerifierAttestationRequestObjectSignature(ctx, envelope, requestContext)
	case "x509_hash", "openid_federation":
		return "", fmt.Errorf("client_id_scheme %q is not yet supported by the wallet", trust.ClientIDScheme)
	case "decentralized_identifier":
		// Proceed with DID-based verification below
	default:
		return "", fmt.Errorf("unsupported client_id_scheme %q", trust.ClientIDScheme)
	}
	if trust.DidWeb == nil || !trust.DidWeb.Resolved || trust.DidWeb.Document == nil {
		return "", fmt.Errorf("verifier DID document could not be resolved for signature verification")
	}
	candidates := extractVerificationKeysFromDIDDocument(trust.DidWeb.Document, envelope.DecodedHeader)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no usable verification keys found in verifier DID document")
	}
	var lastErr error
	for _, candidate := range candidates {
		if err := verifyCompactJWTSignature(envelope.RequestJWT, candidate); err == nil {
			return describePublicKeyType(candidate), nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("request object signature verification failed: %w", lastErr)
}

func (s *walletHarnessServer) verifyX509SANDNSRequestObjectSignature(
	envelope *resolvedRequestEnvelope,
	requestContext *resolvedRequestContext,
) (string, error) {
	certificates, err := intcrypto.ParseX5CCertificateChain(envelope.DecodedHeader["x5c"])
	if err != nil {
		return "", fmt.Errorf("parse request object x5c header: %w", err)
	}
	leaf, err := intcrypto.ValidateCertificateChain(certificates, time.Now())
	if err != nil {
		return "", fmt.Errorf("validate request object x5c chain: %w", err)
	}
	clientDNSName := stripClientIDSchemePrefix(requestContext.ClientID, "x509_san_dns")
	if clientDNSName == "" {
		return "", fmt.Errorf("x509_san_dns client_id is invalid")
	}
	if strings.Contains(clientDNSName, "/") || strings.Contains(clientDNSName, ":") {
		return "", fmt.Errorf("x509_san_dns client_id %q must be a DNS name", clientDNSName)
	}
	if parsedIP := net.ParseIP(clientDNSName); parsedIP != nil {
		return "", fmt.Errorf("x509_san_dns client_id %q must be a DNS name", clientDNSName)
	}
	if err := leaf.VerifyHostname(clientDNSName); err != nil {
		return "", fmt.Errorf("leaf certificate SAN does not match x509_san_dns client_id %q: %w", clientDNSName, err)
	}
	parsedResponseURI, err := url.Parse(requestContext.ResponseURI)
	if err != nil {
		return "", fmt.Errorf("parse request object response_uri: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(parsedResponseURI.Hostname()), clientDNSName) {
		return "", fmt.Errorf("response_uri host %q does not match x509_san_dns client_id %q", parsedResponseURI.Hostname(), clientDNSName)
	}
	if err := verifyCompactJWTSignature(envelope.RequestJWT, leaf.PublicKey); err != nil {
		return "", fmt.Errorf("request object signature verification failed: %w", err)
	}
	return describePublicKeyType(leaf.PublicKey), nil
}

func (s *walletHarnessServer) verifyVerifierAttestationRequestObjectSignature(
	ctx context.Context,
	envelope *resolvedRequestEnvelope,
	requestContext *resolvedRequestContext,
) (string, error) {
	attestationJWT := strings.TrimSpace(asString(envelope.DecodedHeader["jwt"]))
	if attestationJWT == "" {
		return "", fmt.Errorf("verifier_attestation request objects must include a jwt JOSE header")
	}
	decodedAttestation, err := intcrypto.DecodeTokenWithoutValidation(attestationJWT)
	if err != nil {
		return "", fmt.Errorf("decode verifier attestation jwt: %w", err)
	}
	if strings.TrimSpace(asString(decodedAttestation.Header["typ"])) != "verifier-attestation+jwt" {
		return "", fmt.Errorf("verifier attestation typ must be verifier-attestation+jwt")
	}
	issuer := strings.TrimSpace(asString(decodedAttestation.Payload["iss"]))
	if issuer == "" {
		return "", fmt.Errorf("verifier attestation iss claim is required")
	}
	if !s.isTrustedVerifierAttestationIssuer(issuer) {
		return "", fmt.Errorf("verifier attestation issuer %q is not trusted", issuer)
	}
	expVal, expPresent := decodedAttestation.Payload["exp"]
	if !expPresent {
		return "", fmt.Errorf("verifier attestation exp claim is required")
	}
	expFloat, ok := expVal.(float64)
	if !ok {
		return "", fmt.Errorf("verifier attestation exp claim is not a valid number")
	}
	const attestationClockSkew = 30 * time.Second
	if time.Unix(int64(expFloat), 0).Before(time.Now().Add(-attestationClockSkew)) {
		return "", fmt.Errorf("verifier attestation has expired (exp=%d)", int64(expFloat))
	}
	originalClientID := stripClientIDSchemePrefix(requestContext.ClientID, "verifier_attestation")
	if originalClientID == "" {
		return "", fmt.Errorf("verifier_attestation client_id is invalid")
	}
	if strings.TrimSpace(asString(decodedAttestation.Payload["sub"])) != originalClientID {
		return "", fmt.Errorf("verifier attestation sub %q does not match client_id %q", asString(decodedAttestation.Payload["sub"]), originalClientID)
	}
	if err := s.verifyVerifierAttestationJWT(ctx, attestationJWT, decodedAttestation, issuer); err != nil {
		return "", err
	}
	redirectURIs := stringSliceFromValue(decodedAttestation.Payload["redirect_uris"])
	if len(redirectURIs) > 0 && !containsExactString(redirectURIs, requestContext.ResponseURI) {
		return "", fmt.Errorf("request response_uri %q is not authorized by verifier attestation redirect_uris", requestContext.ResponseURI)
	}
	requestPublicKey, err := publicKeyFromConfirmationClaim(decodedAttestation.Payload["cnf"])
	if err != nil {
		return "", fmt.Errorf("resolve verifier attestation cnf key: %w", err)
	}
	if err := verifyCompactJWTSignature(envelope.RequestJWT, requestPublicKey); err != nil {
		return "", fmt.Errorf("request object signature verification failed: %w", err)
	}
	return describePublicKeyType(requestPublicKey), nil
}

func (s *walletHarnessServer) verifyVerifierAttestationJWT(
	ctx context.Context,
	attestationJWT string,
	decodedAttestation *intcrypto.DecodedToken,
	issuer string,
) error {
	if leaf, hasX5C, err := x5CPublicKeyFromHeader(decodedAttestation.Header); err != nil {
		return fmt.Errorf("parse verifier attestation x5c header: %w", err)
	} else if hasX5C {
		if err := verifyCompactJWTSignature(attestationJWT, leaf); err != nil {
			return fmt.Errorf("verifier attestation signature verification failed: %w", err)
		}
		return nil
	}
	candidates, err := s.resolveVerifierAttestationIssuerKeys(ctx, issuer, decodedAttestation.Header)
	if err != nil {
		return fmt.Errorf("resolve verifier attestation issuer keys: %w", err)
	}
	var lastErr error
	for _, candidate := range candidates {
		if err := verifyCompactJWTSignature(attestationJWT, candidate); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		return fmt.Errorf("verifier attestation signature verification failed")
	}
	return fmt.Errorf("verifier attestation signature verification failed: %w", lastErr)
}

func (s *walletHarnessServer) resolveVerifierAttestationIssuerKeys(
	ctx context.Context,
	issuer string,
	jwtHeader map[string]interface{},
) ([]interface{}, error) {
	jwks, err := s.resolveVerifierAttestationIssuerJWKS(ctx, issuer)
	if err != nil {
		return nil, err
	}
	candidates := publicKeysFromJWKS(jwks, jwtHeader)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("trusted verifier attestation issuer jwks did not contain a matching verification key")
	}
	return candidates, nil
}

func (s *walletHarnessServer) resolveVerifierAttestationIssuerJWKS(ctx context.Context, issuer string) (*intcrypto.JWKS, error) {
	normalizedIssuer := strings.TrimSpace(issuer)
	if normalizedIssuer == "" {
		return nil, fmt.Errorf("verifier attestation issuer is required")
	}
	if !isHTTPSURL(normalizedIssuer) {
		return nil, fmt.Errorf("trusted verifier attestation issuer %q is not an HTTP(S) URL", issuer)
	}
	candidateJWKSURIs := make([]string, 0, 4)
	for _, wellKnownName := range []string{"oauth-authorization-server", "openid-configuration"} {
		candidateMetadataURLs, err := wellKnownMetadataURLCandidates(normalizedIssuer, wellKnownName)
		if err != nil {
			continue
		}
		for _, candidateMetadataURL := range candidateMetadataURLs {
			normalizedMetadataURL, err := s.validateExternalURL(candidateMetadataURL)
			if err != nil {
				continue
			}
			payload, err := s.fetchJSONDocument(ctx, normalizedMetadataURL, "application/json", "")
			if err != nil {
				continue
			}
			metadataIssuer := firstNonEmpty(asString(payload["issuer"]), asString(payload["authorization_server"]))
			if metadataIssuer != "" && !sameURLIdentifier(metadataIssuer, normalizedIssuer) {
				continue
			}
			if jwksURI := strings.TrimSpace(asString(payload["jwks_uri"])); jwksURI != "" {
				candidateJWKSURIs = append(candidateJWKSURIs, jwksURI)
			}
		}
	}
	candidateJWKSURIs = append(candidateJWKSURIs, defaultJWKSURLCandidates(normalizedIssuer)...)
	candidateJWKSURIs = dedupeStringList(candidateJWKSURIs)
	if len(candidateJWKSURIs) == 0 {
		return nil, fmt.Errorf("no jwks candidates found for verifier attestation issuer %q", issuer)
	}
	var attemptErrors []string
	for _, candidateJWKSURI := range candidateJWKSURIs {
		normalizedJWKSURI, err := s.validateExternalURL(candidateJWKSURI)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidateJWKSURI, err))
			continue
		}
		jwks, err := s.fetchJWKS(ctx, normalizedJWKSURI, "")
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", normalizedJWKSURI, err))
			continue
		}
		if jwks != nil && len(jwks.Keys) > 0 {
			return jwks, nil
		}
		attemptErrors = append(attemptErrors, fmt.Sprintf("%s: empty jwks", normalizedJWKSURI))
	}
	return nil, fmt.Errorf("resolve verifier attestation issuer jwks: %s", strings.Join(attemptErrors, "; "))
}

func (s *walletHarnessServer) isTrustedVerifierAttestationIssuer(issuer string) bool {
	normalizedIssuer := strings.TrimSpace(issuer)
	if normalizedIssuer == "" {
		return false
	}
	for candidate := range s.trustedVerifierAttestationIssuers {
		if sameURLIdentifier(candidate, normalizedIssuer) {
			return true
		}
	}
	return false
}

func x5CPublicKeyFromHeader(jwtHeader map[string]interface{}) (interface{}, bool, error) {
	if _, ok := jwtHeader["x5c"]; !ok {
		return nil, false, nil
	}
	certificates, err := intcrypto.ParseX5CCertificateChain(jwtHeader["x5c"])
	if err != nil {
		return nil, true, err
	}
	leaf, err := intcrypto.ValidateCertificateChain(certificates, time.Now())
	if err != nil {
		return nil, true, err
	}
	return leaf.PublicKey, true, nil
}

func publicKeyFromConfirmationClaim(raw interface{}) (interface{}, error) {
	confirmation, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cnf claim is required")
	}
	jwkRaw, ok := confirmation["jwk"]
	if !ok {
		return nil, fmt.Errorf("cnf.jwk is required")
	}
	publicJWK, err := jwkFromValue(jwkRaw)
	if err != nil {
		return nil, err
	}
	publicKey, err := publicJWK.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("convert cnf.jwk to public key: %w", err)
	}
	return publicKey, nil
}

func jwkFromValue(raw interface{}) (*intcrypto.JWK, error) {
	jwkBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal jwk: %w", err)
	}
	var publicJWK intcrypto.JWK
	if err := json.Unmarshal(jwkBytes, &publicJWK); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	if strings.TrimSpace(publicJWK.Kty) == "" {
		return nil, fmt.Errorf("jwk kty is required")
	}
	return &publicJWK, nil
}

func publicKeysFromJWKS(jwks *intcrypto.JWKS, jwtHeader map[string]interface{}) []interface{} {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil
	}
	kid := strings.TrimSpace(asString(jwtHeader["kid"]))
	alg := strings.TrimSpace(asString(jwtHeader["alg"]))
	keys := make([]interface{}, 0, len(jwks.Keys))
	for _, candidate := range jwks.Keys {
		if kid != "" && strings.TrimSpace(candidate.Kid) != kid {
			continue
		}
		if alg != "" && strings.TrimSpace(candidate.Alg) != "" && !strings.EqualFold(strings.TrimSpace(candidate.Alg), alg) {
			continue
		}
		publicKey, err := candidate.ToPublicKey()
		if err != nil {
			continue
		}
		keys = append(keys, publicKey)
	}
	return keys
}

func verifyCompactJWTSignature(tokenString string, key interface{}) error {
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	return err
}

func describePublicKeyType(key interface{}) string {
	switch key.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "EC"
	case ed25519.PublicKey:
		return "OKP"
	default:
		return ""
	}
}

func stripClientIDSchemePrefix(clientID string, scheme string) string {
	prefix := strings.TrimSpace(scheme)
	normalizedClientID := strings.TrimSpace(clientID)
	if prefix == "" {
		return normalizedClientID
	}
	if !strings.HasPrefix(normalizedClientID, prefix+":") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(normalizedClientID, prefix+":"))
}

func containsExactString(values []string, target string) bool {
	normalizedTarget := strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == normalizedTarget {
			return true
		}
	}
	return false
}

func extractVerificationKeysFromDIDDocument(didDocument map[string]interface{}, jwtHeader map[string]interface{}) []interface{} {
	kid, _ := jwtHeader["kid"].(string)
	kid = strings.TrimSpace(kid)

	var methodRefs []interface{}
	if authMethods, ok := didDocument["authentication"].([]interface{}); ok {
		methodRefs = append(methodRefs, authMethods...)
	}
	if assertionMethods, ok := didDocument["assertionMethod"].([]interface{}); ok {
		methodRefs = append(methodRefs, assertionMethods...)
	}
	if verificationMethods, ok := didDocument["verificationMethod"].([]interface{}); ok {
		methodRefs = append(methodRefs, verificationMethods...)
	}

	var keys []interface{}
	for _, methodRef := range methodRefs {
		methodObj, ok := methodRef.(map[string]interface{})
		if !ok {
			if ref, ok := methodRef.(string); ok {
				methodObj = resolveVerificationMethodByID(didDocument, ref)
				if methodObj == nil {
					continue
				}
			} else {
				continue
			}
		}
		methodID := strings.TrimSpace(asString(methodObj["id"]))
		if kid != "" && methodID != "" && methodID != kid && !strings.HasSuffix(methodID, "#"+kid) {
			continue
		}
		key := extractPublicKeyFromMethod(methodObj)
		if key != nil {
			keys = append(keys, key)
		}
	}
	return keys
}

func resolveVerificationMethodByID(didDocument map[string]interface{}, id string) map[string]interface{} {
	methods, _ := didDocument["verificationMethod"].([]interface{})
	for _, method := range methods {
		methodObj, ok := method.(map[string]interface{})
		if !ok {
			continue
		}
		if strings.TrimSpace(asString(methodObj["id"])) == strings.TrimSpace(id) {
			return methodObj
		}
	}
	return nil
}

func extractPublicKeyFromMethod(method map[string]interface{}) interface{} {
	if jwkRaw, ok := method["publicKeyJwk"]; ok {
		jwkBytes, err := json.Marshal(jwkRaw)
		if err != nil {
			return nil
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
			return nil
		}
		key, err := jwk.ToPublicKey()
		if err != nil {
			return nil
		}
		return key
	}
	if multibaseRaw, ok := method["publicKeyMultibase"].(string); ok && strings.TrimSpace(multibaseRaw) != "" {
		key, kty, err := vc.DecodeMultibaseMulticodecKey(strings.TrimSpace(multibaseRaw))
		if err != nil {
			log.Printf("publicKeyMultibase decode: %v", err)
			return nil
		}
		_ = kty
		return key
	}
	return nil
}

func summarizeCredential(rawCredential string) *credentialSummary {
	normalized := strings.TrimSpace(rawCredential)
	if normalized == "" {
		return nil
	}
	parsed, err := vc.DefaultCredentialFormatRegistry().ParseAnyCredential(normalized)
	if err != nil {
		summary := &credentialSummary{}
		if envelope, parseErr := vc.ParseSDJWTEnvelope(normalized); parseErr == nil {
			summary.IsSDJWT = true
			summary.Format = "dc+sd-jwt"
			summary.DisclosureCount = len(envelope.Disclosures)
			summary.KeyBindingJWT = strings.TrimSpace(envelope.KeyBindingJWT) != ""
		}
		return summary
	}

	claims := parsed.Claims
	if evidence, evidenceErr := vc.BuildCredentialEvidence(normalized); evidenceErr == nil && evidence != nil && evidence.FullClaims != nil {
		claims = evidence.FullClaims
	}

	summary := &credentialSummary{
		Subject:          parsed.Subject,
		IsSDJWT:          parsed.IsSDJWT,
		Format:           parsed.Format,
		VCT:              parsed.VCT,
		Doctype:          parsed.Doctype,
		CredentialTypes:  append([]string{}, parsed.CredentialTypes...),
		DisclosureClaims: append([]string{}, parsed.DisclosureClaims...),
		DisclosureCount:  parsed.DisclosureCount,
		KeyBindingJWT:    parsed.HasKeyBindingJWT,
		Claims:           claims,
	}
	if !parsed.ExpiresAt.IsZero() {
		summary.ExpiresAt = parsed.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return summary
}

func walletCredentialEntries(wallet *walletMaterial) []map[string]interface{} {
	if wallet == nil {
		return nil
	}
	entries := make([]map[string]interface{}, 0)
	if wallet.Credentials == nil {
		return entries
	}
	credentialIDs := make([]string, 0, len(wallet.Credentials))
	for credentialID := range wallet.Credentials {
		credentialIDs = append(credentialIDs, credentialID)
	}
	sort.Strings(credentialIDs)
	for _, credentialID := range credentialIDs {
		record := wallet.Credentials[credentialID]
		summary := summarizeCredential(record.CredentialJWT)
		entry := map[string]interface{}{
			"credential_id":               record.CredentialID,
			"credential_format":           firstNonEmpty(record.Format, summaryFormat(summary)),
			"credential_configuration_id": record.CredentialConfigurationID,
			"vct":                         firstNonEmpty(record.VCT, summaryVCT(summary)),
			"doctype":                     firstNonEmpty(record.Doctype, summaryDoctype(summary)),
			"issued_at":                   record.IssuedAt.UTC().Format(time.RFC3339),
			"updated_at":                  record.UpdatedAt.UTC().Format(time.RFC3339),
			"is_active":                   strings.TrimSpace(wallet.CredentialID) == strings.TrimSpace(record.CredentialID),
			"credential_summary":          summary,
		}
		entries = append(entries, entry)
	}
	return entries
}

func walletActiveCredential(wallet *walletMaterial, presentedCredential string) walletCredentialMaterial {
	if wallet == nil || wallet.Credentials == nil {
		return walletCredentialMaterial{}
	}
	normalizedPresentedCredential := strings.TrimSpace(presentedCredential)
	if normalizedPresentedCredential != "" {
		for _, record := range wallet.Credentials {
			if strings.TrimSpace(record.CredentialJWT) == normalizedPresentedCredential {
				return record
			}
		}
	}
	if normalizedCredentialID := strings.TrimSpace(wallet.CredentialID); normalizedCredentialID != "" {
		if record, ok := wallet.Credentials[normalizedCredentialID]; ok {
			return record
		}
	}
	var (
		selected walletCredentialMaterial
		found    bool
	)
	for _, record := range wallet.Credentials {
		if !found || record.UpdatedAt.After(selected.UpdatedAt) {
			selected = record
			found = true
		}
	}
	return selected
}

func summaryFormat(summary *credentialSummary) string {
	if summary == nil {
		return ""
	}
	return strings.TrimSpace(summary.Format)
}

func summaryVCT(summary *credentialSummary) string {
	if summary == nil {
		return ""
	}
	return strings.TrimSpace(summary.VCT)
}

func summaryDoctype(summary *credentialSummary) string {
	if summary == nil {
		return ""
	}
	return strings.TrimSpace(summary.Doctype)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized != "" {
			return normalized
		}
	}
	return ""
}

func dedupeStringList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	deduped := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		deduped = append(deduped, normalized)
	}
	return deduped
}

func normalizeDisclosureClaims(raw []string) []string {
	unique := make(map[string]struct{}, len(raw))
	claims := make([]string, 0, len(raw))
	for _, item := range raw {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := unique[normalized]; exists {
			continue
		}
		unique[normalized] = struct{}{}
		claims = append(claims, normalized)
	}
	sort.Strings(claims)
	return claims
}

func (s *walletHarnessServer) handleStepwiseSubmit(w http.ResponseWriter, r *http.Request, req walletSubmitRequest, wallet *walletMaterial) {
	step := strings.TrimSpace(req.Step)
	if step == "" {
		step = "bootstrap"
	}

	switch step {
	case "bootstrap":
		walletKeyID := ""
		if kid, err := walletActiveKeyID(wallet); err == nil {
			walletKeyID = kid
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "bootstrap",
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"wallet_key_id":               walletKeyID,
			"credential_cached":           strings.TrimSpace(wallet.CredentialJWT) != "",
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
		})
		return

	case "issue_credential":
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credentialSelectionOptions{
			ProvidedCredentialJWT: req.CredentialJWT,
			CredentialID:          req.CredentialID,
			CredentialFormat:      req.CredentialFormat,
			CredentialConfigID:    req.CredentialConfigID,
			LookingGlassSessionID: req.LookingGlassSessionID,
		})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "issue_credential",
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"credential_source":           credentialSource,
			"credential_cached":           strings.TrimSpace(wallet.CredentialJWT) != "",
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
		})
		return

	case "build_presentation":
		if req.RequestID == "" || req.Request == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "request_id and request are required for build_presentation",
			})
			return
		}
		envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), apiWalletRequest{
			RequestID:  req.RequestID,
			RequestJWT: req.Request,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		if err := s.ensurePresentationRequestTrust(trust, false, false); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		buildCredOpts := credentialSelectionOptions{
			ProvidedCredentialJWT: req.CredentialJWT,
			CredentialID:          req.CredentialID,
			CredentialFormat:      req.CredentialFormat,
			CredentialConfigID:    req.CredentialConfigID,
			LookingGlassSessionID: req.LookingGlassSessionID,
		}
		if buildCredOpts.CredentialFormat == "" && buildCredOpts.CredentialConfigID == "" {
			inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope)
			if inferredFormat != "" {
				buildCredOpts.CredentialFormat = inferredFormat
				buildCredOpts.CredentialConfigID = inferredConfigID
			}
		}
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, buildCredOpts)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, requestContext)
		if matchSummary.QueryType != "" && !matchSummary.Matched {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":              "invalid_request",
				"error_description":  "wallet does not have a credential that satisfies the presentation request",
				"credential_matches": matchSummary,
			})
			return
		}
		if matchSummary.QueryType != "" && !matchedActiveCredential {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":              "invalid_request",
				"error_description":  "wallet could not activate a credential that satisfies the presentation request",
				"credential_matches": matchSummary,
			})
			return
		}
		presentedCredential, disclosureClaims, err := filterSDJWTDisclosures(wallet.CredentialJWT, req.DisclosureClaims)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		vpToken, vpFormat, err := s.createVPToken(wallet, requestContext, presentedCredential)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("create vp_token: %v", err),
			})
			return
		}
		var stepLGEvents []walletLifecycleEvent
		if len(disclosureClaims) > 0 {
			stepLGEvents = append(stepLGEvents, newWalletEvent("sd_jwt_disclosure", "SD-JWT Disclosure Selection", map[string]interface{}{
				"selected_claims": disclosureClaims,
				"claim_count":     len(disclosureClaims),
			}))
		}
		stepLGEvents = append(stepLGEvents, newWalletEvent("vp_token_construction", "VP Token Constructed", map[string]interface{}{
			"format":         vpFormat,
			"algorithm":      wallet.SigningAlgorithm,
			"credential_id":  wallet.CredentialID,
			"holder_binding": wallet.Subject,
		}))
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "build_presentation",
			"request_id":                  requestContext.RequestID,
			"response_mode":               requestContext.ResponseMode,
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"credential_source":           credentialSource,
			"credential_matches":          matchSummary,
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
			"disclosure_claims":           disclosureClaims,
			"vp_token":                    vpToken,
			"trust":                       trust,
			"_looking_glass_events":       stepLGEvents,
		})
		return

	case "submit_response":
		if req.RequestID == "" || req.Request == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "request_id and request are required for submit_response",
			})
			return
		}
		envelope, requestContext, trust, err := s.resolveWalletPresentationContext(r.Context(), apiWalletRequest{
			RequestID:  req.RequestID,
			RequestJWT: req.Request,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		if err := s.ensurePresentationRequestTrust(trust, true, req.ApproveExternalTrust); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		submitCredOpts := credentialSelectionOptions{
			ProvidedCredentialJWT: req.CredentialJWT,
			CredentialID:          req.CredentialID,
			CredentialFormat:      req.CredentialFormat,
			CredentialConfigID:    req.CredentialConfigID,
			LookingGlassSessionID: req.LookingGlassSessionID,
		}
		if submitCredOpts.CredentialFormat == "" && submitCredOpts.CredentialConfigID == "" {
			inferredFormat, inferredConfigID := inferCredentialFormatFromVPRequest(envelope)
			if inferredFormat != "" {
				submitCredOpts.CredentialFormat = inferredFormat
				submitCredOpts.CredentialConfigID = inferredConfigID
			}
		}
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, submitCredOpts)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, requestContext)
		if matchSummary.QueryType != "" && !matchSummary.Matched {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":              "invalid_request",
				"error_description":  "wallet does not have a credential that satisfies the presentation request",
				"credential_matches": matchSummary,
			})
			return
		}
		if matchSummary.QueryType != "" && !matchedActiveCredential {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":              "invalid_request",
				"error_description":  "wallet could not activate a credential that satisfies the presentation request",
				"credential_matches": matchSummary,
			})
			return
		}
		vpToken := strings.TrimSpace(req.VPToken)
		disclosureClaims := req.DisclosureClaims
		if vpToken == "" {
			presentedCredential, selectedClaims, err := filterSDJWTDisclosures(wallet.CredentialJWT, req.DisclosureClaims)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":             "invalid_request",
					"error_description": err.Error(),
				})
				return
			}
			disclosureClaims = selectedClaims
			vpToken, _, err = s.createVPToken(wallet, requestContext, presentedCredential)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error":             "wallet_submission_failed",
					"error_description": fmt.Sprintf("create vp_token: %v", err),
				})
				return
			}
		}
		var submitLGEvents []walletLifecycleEvent
		upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, req.LookingGlassSessionID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		submitLGEvents = append(submitLGEvents, newWalletEvent("submission_result", "Submitted to Verifier", map[string]interface{}{
			"upstream_status": upstreamStatus,
			"response_uri":    requestContext.ResponseURI,
			"response_mode":   requestContext.ResponseMode,
		}))
		writeJSON(w, upstreamStatus, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "submit_response",
			"request_id":                  requestContext.RequestID,
			"response_mode":               requestContext.ResponseMode,
			"response_uri":                requestContext.ResponseURI,
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"credential_source":           credentialSource,
			"credential_matches":          matchSummary,
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
			"disclosure_claims":           disclosureClaims,
			"upstream_status":             upstreamStatus,
			"upstream_body":               upstreamBody,
			"external_trust_approved":     req.ApproveExternalTrust,
			"trust":                       trust,
			"_looking_glass_events":       submitLGEvents,
		})
		return

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": fmt.Sprintf("unsupported step %q", step),
		})
		return
	}
}

func (s *walletHarnessServer) ensureWalletCredential(
	ctx context.Context,
	wallet *walletMaterial,
	options credentialSelectionOptions,
) (string, error) {
	if wallet == nil {
		return "", fmt.Errorf("wallet context is required")
	}
	if wallet.Credentials == nil {
		wallet.Credentials = make(map[string]walletCredentialMaterial)
	}

	credentialSource := ""
	if strings.TrimSpace(options.ProvidedCredentialJWT) != "" {
		if err := s.bindCredential(wallet, options.ProvidedCredentialJWT, options.CredentialConfigID, options.CredentialFormat); err != nil {
			return "", fmt.Errorf("bind provided credential_jwt: %w", err)
		}
		credentialSource = "provided"
	}
	if normalizedCredentialID := strings.TrimSpace(options.CredentialID); normalizedCredentialID != "" {
		if selectedCredential, ok := wallet.Credentials[normalizedCredentialID]; ok {
			activateWalletCredential(wallet, selectedCredential)
		}
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" || strings.TrimSpace(options.CredentialID) == "" {
		if selectedCredential, ok := selectWalletCredential(wallet, options.CredentialConfigID, options.CredentialFormat); ok {
			activateWalletCredential(wallet, selectedCredential)
		}
	}

	selectionMismatch := false
	if credentialSource != "provided" {
		selectionMismatch = walletCredentialSelectionMismatch(wallet, options.CredentialConfigID, options.CredentialFormat)
	}
	needsCredentialBootstrap := strings.TrimSpace(wallet.CredentialJWT) == "" || selectionMismatch
	needsCredentialRefresh := false
	if !needsCredentialBootstrap {
		refreshRequired, err := credentialRefreshRequired(wallet.CredentialJWT, 90*time.Second)
		if err != nil {
			needsCredentialRefresh = true
			log.Printf("wallet harness: credential pre-check failed for subject %q, refreshing via oid4vci (%v)", wallet.Subject, err)
		} else if refreshRequired {
			needsCredentialRefresh = true
		}
	}

	if needsCredentialBootstrap || needsCredentialRefresh {
		autoIssuedCredential, err := s.issueCredentialForWallet(ctx, wallet, options)
		if err != nil {
			return "", fmt.Errorf("issue credential via oid4vci: %w", err)
		}
		if err := s.bindCredential(wallet, autoIssuedCredential.CredentialJWT, autoIssuedCredential.CredentialConfigID, autoIssuedCredential.CredentialFormat); err != nil {
			return "", fmt.Errorf("bind auto-issued credential: %w", err)
		}
		if needsCredentialBootstrap {
			credentialSource = "auto_issued_oid4vci"
		} else {
			credentialSource = "auto_refreshed_oid4vci"
		}
	}
	if credentialSource == "" {
		credentialSource = "cached_wallet_store"
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		return "", fmt.Errorf("wallet credential is unavailable after bootstrap")
	}
	return credentialSource, nil
}

func walletCredentialSelectionMismatch(wallet *walletMaterial, credentialConfigID string, credentialFormat string) bool {
	if wallet == nil {
		return false
	}
	expectedCredentialConfigID := strings.TrimSpace(credentialConfigID)
	expectedCredentialFormat := strings.TrimSpace(credentialFormat)
	if expectedCredentialConfigID == "" && expectedCredentialFormat == "" {
		return false
	}
	activeCredentialJWT := strings.TrimSpace(wallet.CredentialJWT)
	if activeCredentialJWT == "" {
		return true
	}
	activeCredentialConfigID := strings.TrimSpace(wallet.CredentialConfigurationID)
	activeCredentialFormat := strings.TrimSpace(wallet.CredentialFormat)
	if activeCredentialFormat == "" {
		activeCredentialFormat = summaryFormat(summarizeCredential(activeCredentialJWT))
	}
	if expectedCredentialConfigID != "" && activeCredentialConfigID != expectedCredentialConfigID {
		return true
	}
	if expectedCredentialFormat != "" && activeCredentialFormat != expectedCredentialFormat {
		return true
	}
	return false
}

func selectWalletCredential(wallet *walletMaterial, credentialConfigID string, credentialFormat string) (walletCredentialMaterial, bool) {
	if wallet == nil || wallet.Credentials == nil {
		return walletCredentialMaterial{}, false
	}
	normalizedConfigID := strings.TrimSpace(credentialConfigID)
	normalizedFormat := strings.TrimSpace(credentialFormat)
	if normalizedConfigID == "" && normalizedFormat == "" {
		return walletCredentialMaterial{}, false
	}
	var (
		selected walletCredentialMaterial
		found    bool
	)
	for _, record := range wallet.Credentials {
		if normalizedConfigID != "" && strings.TrimSpace(record.CredentialConfigurationID) != normalizedConfigID {
			continue
		}
		if normalizedFormat != "" && strings.TrimSpace(record.Format) != normalizedFormat {
			continue
		}
		if !found || record.UpdatedAt.After(selected.UpdatedAt) {
			selected = record
			found = true
		}
	}
	return selected, found
}

func activateWalletCredential(wallet *walletMaterial, selected walletCredentialMaterial) {
	if wallet == nil {
		return
	}
	wallet.CredentialJWT = strings.TrimSpace(selected.CredentialJWT)
	wallet.CredentialID = strings.TrimSpace(selected.CredentialID)
	wallet.CredentialFormat = strings.TrimSpace(selected.Format)
	wallet.CredentialConfigurationID = strings.TrimSpace(selected.CredentialConfigurationID)
}

func filterSDJWTDisclosures(rawCredential string, requestedClaims []string) (string, []string, error) {
	normalized := strings.TrimSpace(rawCredential)
	if normalized == "" {
		return "", nil, fmt.Errorf("wallet credential is required")
	}
	envelope, err := vc.ParseSDJWTEnvelope(normalized)
	if err != nil {
		// Non SD-JWT formats are presented as-is.
		return normalized, nil, nil
	}
	if len(envelope.Disclosures) == 0 {
		return normalized, nil, nil
	}

	selectedDisclosures := make([]string, 0, len(envelope.Disclosures))
	selectedClaims := make([]string, 0, len(envelope.Disclosures))
	requestedSet := make(map[string]struct{}, len(requestedClaims))
	for _, claimName := range normalizeDisclosureClaims(requestedClaims) {
		requestedSet[claimName] = struct{}{}
	}

	for _, disclosure := range envelope.Disclosures {
		decodedDisclosure, err := vc.DecodeSDJWTDisclosure(disclosure)
		if err != nil {
			return "", nil, fmt.Errorf("decode sd-jwt disclosure: %w", err)
		}
		claimName := strings.TrimSpace(decodedDisclosure.ClaimName)
		if len(requestedSet) > 0 {
			if _, ok := requestedSet[claimName]; !ok {
				continue
			}
		}
		selectedDisclosures = append(selectedDisclosures, strings.TrimSpace(disclosure))
		selectedClaims = append(selectedClaims, claimName)
	}
	if len(requestedSet) > 0 && len(selectedDisclosures) == 0 {
		return "", nil, fmt.Errorf("none of the requested disclosure_claims are available in the credential")
	}
	sort.Strings(selectedClaims)
	return vc.BuildSDJWTSerialization(envelope.IssuerSignedJWT, selectedDisclosures, envelope.KeyBindingJWT), selectedClaims, nil
}

// inferCredentialFormatFromVPRequest extracts the expected credential format and configuration ID from a resolved VP request envelope.
// It examines the DCQL query for an explicit format constraint, and falls back to vp_formats_supported in client_metadata to pick the most specific match.
func inferCredentialFormatFromVPRequest(envelope *resolvedRequestEnvelope) (format string, configID string) {
	if envelope == nil || envelope.DecodedPayload == nil {
		return "", ""
	}

	if rawQuery := envelope.DecodedPayload["dcql_query"]; rawQuery != nil {
		queryBytes, err := json.Marshal(rawQuery)
		if err == nil {
			requirements := vc.ParseDCQLCredentialRequirements(string(queryBytes))
			for _, req := range requirements {
				if req.Format != "" {
					return req.Format, formatToDefaultConfigurationID(req.Format)
				}
			}
		}
	}

	if clientMetadata, ok := envelope.DecodedPayload["client_metadata"].(map[string]interface{}); ok {
		if vpFormats, ok := clientMetadata["vp_formats_supported"].(map[string]interface{}); ok {
			for _, candidate := range []string{"dc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"} {
				if _, supported := vpFormats[candidate]; supported {
					return candidate, formatToDefaultConfigurationID(candidate)
				}
			}
		}
	}
	return "", ""
}

func formatToDefaultConfigurationID(format string) string {
	switch format {
	case "dc+sd-jwt":
		return "UniversityDegreeCredential"
	case "jwt_vc_json":
		return "UniversityDegreeCredentialJWT"
	case "jwt_vc_json-ld":
		return "UniversityDegreeCredentialJWTLD"
	case "ldp_vc":
		return "UniversityDegreeCredentialLDP"
	default:
		return ""
	}
}

func matchWalletCredentialsToDCQL(credentials map[string]walletCredentialMaterial, dcqlQueryRaw string) ([]walletCredentialMaterial, []string) {
	requirements := vc.ParseDCQLCredentialRequirements(dcqlQueryRaw)
	if len(requirements) == 0 {
		return nil, nil
	}
	var matched []walletCredentialMaterial
	var reasons []string
	for credID, cred := range credentials {
		evidence, err := vc.BuildCredentialEvidence(cred.CredentialJWT)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("credential %s: %v", credID, err))
			continue
		}
		if normalizedFormat := strings.TrimSpace(cred.Format); normalizedFormat != "" {
			evidence.Format = normalizedFormat
		}
		if normalizedVCT := strings.TrimSpace(cred.VCT); normalizedVCT != "" {
			evidence.VCT = normalizedVCT
		}
		if normalizedDoctype := strings.TrimSpace(cred.Doctype); normalizedDoctype != "" {
			evidence.Doctype = normalizedDoctype
		}
		if len(evidence.CredentialTypes) == 0 {
			summary := summarizeCredential(cred.CredentialJWT)
			if summary != nil {
				evidence.CredentialTypes = append([]string{}, summary.CredentialTypes...)
			}
		}
		anyMatch := false
		for _, req := range requirements {
			ok, _, reason := vc.RequirementMatchesEvidence(req, *evidence)
			if ok {
				anyMatch = true
				break
			}
			reasons = append(reasons, fmt.Sprintf("credential %s: %s", credID, reason))
		}
		if anyMatch {
			matched = append(matched, cred)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].UpdatedAt.After(matched[j].UpdatedAt)
	})
	return matched, reasons
}

func matchWalletCredentialsToPresentationDefinition(credentials map[string]walletCredentialMaterial, presentationDefinition map[string]interface{}) ([]walletCredentialMaterial, []string) {
	definition, err := vc.ParsePresentationDefinition(presentationDefinition)
	if err != nil {
		return nil, []string{err.Error()}
	}
	if definition == nil || len(definition.InputDescriptors) == 0 {
		return nil, nil
	}

	var matched []walletCredentialMaterial
	var reasons []string
	for credentialID, credential := range credentials {
		evidence, err := vc.BuildCredentialEvidence(credential.CredentialJWT)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("credential %s: %v", credentialID, err))
			continue
		}
		candidate := vc.PresentationCandidate{
			CredentialFormats: []string{strings.TrimSpace(credential.Format)},
			Evidence:          *evidence,
		}
		anyMatch := false
		for _, descriptor := range definition.InputDescriptors {
			if _, err := vc.MatchCredentialToDescriptor(descriptor, candidate); err == nil {
				anyMatch = true
				break
			} else {
				reasons = append(reasons, fmt.Sprintf("credential %s: %v", credentialID, err))
			}
		}
		if anyMatch {
			matched = append(matched, credential)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].UpdatedAt.After(matched[j].UpdatedAt)
	})
	return matched, reasons
}

func summarizeWalletRequestMatches(wallet *walletMaterial, envelope *resolvedRequestEnvelope, requestContext *resolvedRequestContext) walletRequestMatchSummary {
	summary := walletRequestMatchSummary{
		Matched:              true,
		MatchedCredentialIDs: []string{},
		Reasons:              []string{},
	}
	if wallet == nil || wallet.Credentials == nil {
		summary.Matched = false
		return summary
	}

	var (
		matchedCredentials []walletCredentialMaterial
		reasons            []string
	)
	switch {
	case envelope != nil && envelope.DecodedPayload["dcql_query"] != nil:
		rawQuery, err := json.Marshal(envelope.DecodedPayload["dcql_query"])
		if err != nil {
			summary.Matched = false
			summary.QueryType = "dcql"
			summary.Reasons = []string{fmt.Sprintf("serialize dcql_query: %v", err)}
			return summary
		}
		summary.QueryType = "dcql"
		matchedCredentials, reasons = matchWalletCredentialsToDCQL(wallet.Credentials, string(rawQuery))
	case requestContext != nil && requestContext.PresentationDefinition != nil:
		summary.QueryType = "presentation_exchange"
		matchedCredentials, reasons = matchWalletCredentialsToPresentationDefinition(wallet.Credentials, requestContext.PresentationDefinition)
	default:
		return summary
	}

	summary.Reasons = append(summary.Reasons, reasons...)
	for _, credential := range matchedCredentials {
		credentialID := strings.TrimSpace(credential.CredentialID)
		if credentialID == "" {
			continue
		}
		summary.MatchedCredentialIDs = append(summary.MatchedCredentialIDs, credentialID)
	}
	sort.Strings(summary.MatchedCredentialIDs)
	summary.MatchedCredentialCount = len(summary.MatchedCredentialIDs)
	summary.Matched = summary.MatchedCredentialCount > 0
	if len(matchedCredentials) > 0 {
		summary.RecommendedCredentialID = strings.TrimSpace(matchedCredentials[0].CredentialID)
	}
	return summary
}

func ensureWalletMatchesPresentationRequest(wallet *walletMaterial, envelope *resolvedRequestEnvelope, requestContext *resolvedRequestContext) (walletRequestMatchSummary, bool) {
	summary := summarizeWalletRequestMatches(wallet, envelope, requestContext)
	if summary.QueryType == "" {
		return summary, false
	}
	if !summary.Matched {
		return summary, false
	}
	if wallet == nil || wallet.Credentials == nil {
		return summary, false
	}
	activeCredentialID := strings.TrimSpace(wallet.CredentialID)
	for _, matchedCredentialID := range summary.MatchedCredentialIDs {
		if matchedCredentialID == activeCredentialID {
			return summary, true
		}
	}
	if recommendedCredentialID := strings.TrimSpace(summary.RecommendedCredentialID); recommendedCredentialID != "" {
		if credential, ok := wallet.Credentials[recommendedCredentialID]; ok {
			activateWalletCredential(wallet, credential)
			return summary, true
		}
	}
	return summary, false
}

func (s *walletHarnessServer) submitToVerifier(
	ctx context.Context,
	wallet *walletMaterial,
	requestContext *resolvedRequestContext,
	vpToken string,
	lookingGlassSessionID string,
) (int, interface{}, error) {
	if requestContext == nil {
		return 0, nil, fmt.Errorf("request context is required")
	}
	normalizedVPToken := strings.TrimSpace(vpToken)
	if normalizedVPToken == "" {
		return 0, nil, fmt.Errorf("vp_token is required")
	}

	form := url.Values{}
	if requestContext.State != "" {
		form.Set("state", requestContext.State)
	}
	if requestContext.ResponseMode == "direct_post.jwt" {
		if !requestContext.Trusted {
			return 0, nil, fmt.Errorf("direct_post.jwt is only supported for trusted verifier callbacks")
		}
		responseJWT, err := s.createDirectPostResponseJWT(wallet, requestContext, normalizedVPToken)
		if err != nil {
			return 0, nil, fmt.Errorf("create direct_post.jwt response: %w", err)
		}
		encryptedResponse, err := s.encryptForVerifier(responseJWT)
		if err != nil {
			return 0, nil, fmt.Errorf("encrypt direct_post.jwt response: %w", err)
		}
		form.Set("response", encryptedResponse)
	} else {
		form.Set("vp_token", normalizedVPToken)
		ps, err := buildPresentationSubmission(requestContext.PresentationDefinition, normalizedVPToken)
		if err != nil {
			return 0, nil, fmt.Errorf("build presentation_submission: %w", err)
		}
		if ps != "" {
			form.Set("presentation_submission", ps)
		}
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, requestContext.ResponseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("build upstream request: %w", err)
	}
	upstreamReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	upstreamReq.Header.Set("Accept", "application/json")
	if lookingGlassSessionID != "" {
		upstreamReq.Header.Set("X-Looking-Glass-Session", lookingGlassSessionID)
	}

	upstreamResp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		return 0, nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer upstreamResp.Body.Close()
	upstreamBody, _ := io.ReadAll(upstreamResp.Body)
	var decodedBody interface{}
	if len(strings.TrimSpace(string(upstreamBody))) > 0 {
		if err := json.Unmarshal(upstreamBody, &decodedBody); err != nil {
			decodedBody = string(upstreamBody)
		}
	}
	return upstreamResp.StatusCode, decodedBody, nil
}

func (s *walletHarnessServer) resolveRequestContextWithOptions(requestID string, requestJWT string, allowExternal bool, uriClientID ...string) (*resolvedRequestContext, error) {
	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		return nil, fmt.Errorf("decode request object jwt: %w", err)
	}
	normalizedRequestID := strings.TrimSpace(requestID)
	requestObjectID := strings.TrimSpace(asString(decodedRequest.Payload["jti"]))
	if requestObjectID == "" {
		sum := sha256.Sum256([]byte(requestJWT))
		requestObjectID = "ext-" + hex.EncodeToString(sum[:12])
	}
	if normalizedRequestID == "" {
		normalizedRequestID = requestObjectID
	}
	if normalizedRequestID != requestObjectID && strings.TrimSpace(asString(decodedRequest.Payload["jti"])) != "" {
		return nil, fmt.Errorf("request_id does not match request object jti")
	}

	responseMode := strings.TrimSpace(asString(decodedRequest.Payload["response_mode"]))
	if responseMode == "" {
		responseMode = "direct_post"
	}
	if responseMode != "direct_post" && responseMode != "direct_post.jwt" {
		return nil, fmt.Errorf("unsupported response_mode %q", responseMode)
	}
	responseURI := strings.TrimSpace(asString(decodedRequest.Payload["response_uri"]))
	if responseURI == "" {
		responseURI = strings.TrimSpace(asString(decodedRequest.Payload["redirect_uri"]))
	}
	clientID := strings.TrimSpace(asString(decodedRequest.Payload["client_id"]))
	if responseURI == "" {
		return nil, fmt.Errorf("request object is missing response_uri")
	}
	parsedResponseURI, err := url.ParseRequestURI(responseURI)
	if err != nil {
		return nil, fmt.Errorf("request object response_uri is invalid: %w", err)
	}
	if parsedResponseURI.Scheme != "http" && parsedResponseURI.Scheme != "https" {
		return nil, fmt.Errorf("request object response_uri uses unsupported scheme %q", parsedResponseURI.Scheme)
	}
	if parsedResponseURI.User != nil {
		return nil, fmt.Errorf("request object response_uri includes userinfo")
	}
	responseURI = parsedResponseURI.String()
	expectedResponseURI, err := s.validateAllowedURL(s.targetResponseURI)
	if err != nil {
		return nil, fmt.Errorf("validate target response URI: %w", err)
	}
	trusted := responseURI == expectedResponseURI
	if !trusted {
		if !allowExternal {
			return nil, fmt.Errorf("request object response_uri %q does not match trusted verifier callback", responseURI)
		}
		if _, err := s.validateExternalURL(responseURI); err != nil {
			return nil, fmt.Errorf("request object response_uri is not allowed: %w", err)
		}
	}
	state := strings.TrimSpace(asString(decodedRequest.Payload["state"]))
	nonce := strings.TrimSpace(asString(decodedRequest.Payload["nonce"]))
	if clientID == "" {
		return nil, fmt.Errorf("request object is missing client_id")
	}
	// OID4VP Section 5.10: URI client_id and request object client_id MUST be identical
	if len(uriClientID) > 0 && uriClientID[0] != "" {
		if uriClientID[0] != clientID {
			return nil, fmt.Errorf("request object client_id %q does not match URI client_id %q", clientID, uriClientID[0])
		}
	}
	if nonce == "" {
		return nil, fmt.Errorf("request object is missing nonce")
	}

	// OID4VP Section 5.2: validate request object exp/iat temporal claims
	const requestClockSkew = 60 * time.Second
	if expVal, ok := decodedRequest.Payload["exp"]; ok {
		if expFloat, fok := expVal.(float64); fok {
			if time.Unix(int64(expFloat), 0).Before(time.Now().Add(-requestClockSkew)) {
				return nil, fmt.Errorf("request object has expired (exp=%d)", int64(expFloat))
			}
		}
	}
	if iatVal, ok := decodedRequest.Payload["iat"]; ok {
		if iatFloat, fok := iatVal.(float64); fok {
			if time.Unix(int64(iatFloat), 0).After(time.Now().Add(requestClockSkew)) {
				return nil, fmt.Errorf("request object iat is in the future (iat=%d)", int64(iatFloat))
			}
		}
	}

	var presDef map[string]interface{}
	if pd, ok := decodedRequest.Payload["presentation_definition"].(map[string]interface{}); ok {
		presDef = pd
	}

	return &resolvedRequestContext{
		RequestID:              normalizedRequestID,
		State:                  state,
		Nonce:                  nonce,
		ClientID:               clientID,
		ResponseMode:           responseMode,
		ResponseURI:            responseURI,
		Trusted:                trusted,
		PresentationDefinition: presDef,
	}, nil
}

func resolveWalletSigningAlgorithm(raw string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "", "ES256":
		return "ES256", nil
	case "RS256":
		return "RS256", nil
	case "EDDSA":
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported wallet signing algorithm %q", raw)
	}
}

func resolveWalletDIDMethod(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "key":
		return "key", nil
	case "jwk":
		return "jwk", nil
	case "web":
		return "web", nil
	default:
		return "", fmt.Errorf("unsupported did method %q", raw)
	}
}

func walletActiveKeyID(wallet *walletMaterial) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	switch wallet.SigningAlgorithm {
	case "ES256":
		return wallet.KeySet.ECKeyID(), nil
	case "RS256":
		return wallet.KeySet.RSAKeyID(), nil
	case "EdDSA":
		return wallet.KeySet.Ed25519KeyID(), nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", wallet.SigningAlgorithm)
	}
}

func walletSignToken(wallet *walletMaterial, claims jwt.MapClaims, headerOverrides map[string]interface{}) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	var signingMethod jwt.SigningMethod
	var signingKey interface{}
	var kid string
	switch wallet.SigningAlgorithm {
	case "ES256":
		signingMethod = jwt.SigningMethodES256
		signingKey = wallet.KeySet.ECPrivateKey()
		kid = wallet.KeySet.ECKeyID()
	case "EdDSA":
		signingMethod = jwt.SigningMethodEdDSA
		signingKey = wallet.KeySet.Ed25519PrivateKey()
		kid = wallet.KeySet.Ed25519KeyID()
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		signingKey = wallet.KeySet.RSAPrivateKey()
		kid = wallet.KeySet.RSAKeyID()
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", wallet.SigningAlgorithm)
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = kid
	for key, value := range headerOverrides {
		token.Header[key] = value
	}
	return token.SignedString(signingKey)
}

func walletActiveJWK(wallet *walletMaterial) (intcrypto.JWK, string, error) {
	kid, err := walletActiveKeyID(wallet)
	if err != nil {
		return intcrypto.JWK{}, "", err
	}
	pubJWK, found := wallet.KeySet.GetJWKByID(kid)
	if !found {
		return intcrypto.JWK{}, "", fmt.Errorf("wallet public jwk is unavailable for algorithm %s", wallet.SigningAlgorithm)
	}
	thumbprint := strings.TrimSpace(pubJWK.Thumbprint())
	if thumbprint == "" {
		return intcrypto.JWK{}, "", fmt.Errorf("wallet jwk thumbprint is unavailable")
	}
	return pubJWK, thumbprint, nil
}

func walletVerificationMethodID(wallet *walletMaterial) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	publicJWK, err := activeJWKForKeyMaterial(wallet.KeySet, wallet.SigningAlgorithm)
	if err != nil {
		return "", err
	}
	subject := strings.TrimSpace(wallet.Subject)
	if subject == "" {
		return "", fmt.Errorf("wallet subject is required")
	}
	switch {
	case strings.HasPrefix(subject, "did:web:") && strings.TrimSpace(publicJWK.Kid) != "":
		return subject + "#" + strings.TrimSpace(publicJWK.Kid), nil
	default:
		methodID := strings.TrimSpace(vc.DefaultVerificationMethodID(subject))
		if methodID != "" {
			return methodID, nil
		}
		if strings.TrimSpace(publicJWK.Kid) != "" {
			return subject + "#" + strings.TrimSpace(publicJWK.Kid), nil
		}
		return "", fmt.Errorf("wallet verification method is unavailable")
	}
}

func walletSignBytes(wallet *walletMaterial, payload []byte) ([]byte, error) {
	if wallet == nil || wallet.KeySet == nil {
		return nil, fmt.Errorf("wallet key material is unavailable")
	}
	switch wallet.SigningAlgorithm {
	case "EdDSA":
		return ed25519.Sign(wallet.KeySet.Ed25519PrivateKey(), payload), nil
	case "ES256":
		digest := sha256.Sum256(payload)
		rValue, sValue, err := ecdsa.Sign(rand.Reader, wallet.KeySet.ECPrivateKey(), digest[:])
		if err != nil {
			return nil, err
		}
		componentSize := 32
		signature := make([]byte, componentSize*2)
		rBytes := rValue.Bytes()
		sBytes := sValue.Bytes()
		copy(signature[componentSize-len(rBytes):componentSize], rBytes)
		copy(signature[len(signature)-len(sBytes):], sBytes)
		return signature, nil
	default:
		return nil, fmt.Errorf("wallet signing algorithm %q does not support Data Integrity proof generation", wallet.SigningAlgorithm)
	}
}

func (s *walletHarnessServer) createVPToken(wallet *walletMaterial, requestContext *resolvedRequestContext, presentedCredentialJWT string) (string, string, error) {
	pubJWK, thumbprint, err := walletActiveJWK(wallet)
	if err != nil {
		return "", "", err
	}
	holderVerificationMethod, err := walletVerificationMethodID(wallet)
	if err != nil {
		return "", "", err
	}

	presentedCredential := strings.TrimSpace(presentedCredentialJWT)
	if presentedCredential == "" {
		presentedCredential = strings.TrimSpace(wallet.CredentialJWT)
	}
	activeCredential := walletActiveCredential(wallet, presentedCredential)
	registry := vc.DefaultCredentialFormatRegistry()
	parsedCredential, _ := registry.ParseAnyCredential(presentedCredential)
	credentialFormat := ""
	if parsedCredential != nil {
		credentialFormat = strings.TrimSpace(parsedCredential.Format)
	}
	credentialFormat = firstNonEmpty(credentialFormat, activeCredential.Format)
	if credentialFormat == "" {
		credentialFormat = "jwt_vc_json"
	}
	formatHandler, ok := registry.Lookup(credentialFormat)
	if !ok {
		return "", "", fmt.Errorf("unsupported credential format %q", credentialFormat)
	}
	if !formatHandler.CanPresent() {
		return "", "", fmt.Errorf("credential format %q cannot be presented by this wallet", credentialFormat)
	}
	vpResult, err := formatHandler.BuildPresentation(vc.PresentationBuildInput{
		Credential:               presentedCredential,
		ParsedCredential:         parsedCredential,
		Holder:                   wallet.Subject,
		HolderPublicJWK:          pubJWK,
		HolderJWKThumbprint:      thumbprint,
		HolderVerificationMethod: holderVerificationMethod,
		Audience:                 requestContext.ClientID,
		Nonce:                    requestContext.Nonce,
		PresentationDefinition:   requestContext.PresentationDefinition,
		Signer: func(claims map[string]interface{}, headerOverrides map[string]interface{}) (string, error) {
			jwtClaims := jwt.MapClaims{}
			for key, value := range claims {
				jwtClaims[key] = value
			}
			return walletSignToken(wallet, jwtClaims, headerOverrides)
		},
		ProofSigner: func(data []byte) ([]byte, error) {
			return walletSignBytes(wallet, data)
		},
	})
	if err != nil {
		return "", "", err
	}
	return vpResult.VPToken, firstNonEmpty(vpResult.CredentialFormat, credentialFormat), nil
}

func (s *walletHarnessServer) issueCredentialForWallet(ctx context.Context, wallet *walletMaterial, options credentialSelectionOptions) (*issuedWalletCredential, error) {
	if wallet == nil || wallet.KeySet == nil {
		return nil, fmt.Errorf("wallet key material is unavailable")
	}
	credentialConfigID, err := s.resolveCredentialConfigurationForIssue(ctx, strings.TrimSpace(options.CredentialConfigID), strings.TrimSpace(options.CredentialFormat), strings.TrimSpace(options.LookingGlassSessionID))
	if err != nil {
		return nil, err
	}

	offerPayload, err := func() (map[string]interface{}, error) {
		offerURL := s.issuerBaseURL + "/oid4vci/offers/pre-authorized"
		offerBody := map[string]interface{}{
			"wallet_user_id": walletUserIDFromSubject(wallet.Subject),
		}
		if credentialConfigID != "" {
			offerBody["credential_configuration_ids"] = []string{credentialConfigID}
		}
		rawBody, err := json.Marshal(offerBody)
		if err != nil {
			return nil, fmt.Errorf("marshal offer request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, offerURL, strings.NewReader(string(rawBody)))
		if err != nil {
			return nil, fmt.Errorf("build offer request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		if strings.TrimSpace(options.LookingGlassSessionID) != "" {
			req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(options.LookingGlassSessionID))
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("offer request failed: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			return nil, fmt.Errorf("offer request returned %d: %s", resp.StatusCode, oneLine(string(body)))
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("decode offer response: %w", err)
		}
		return payload, nil
	}()
	if err != nil {
		return nil, err
	}

	preAuthorizedCode := asString(offerPayload["pre_authorized_code"])
	if preAuthorizedCode == "" {
		return nil, fmt.Errorf("offer response missing pre_authorized_code")
	}
	offerWalletSubject := asString(offerPayload["wallet_subject"])
	if offerWalletSubject == "" {
		return nil, fmt.Errorf("offer response missing wallet_subject")
	}
	if credentialConfigID == "" {
		if offeredIDs, ok := offerPayload["credential_configuration_ids"].([]interface{}); ok {
			for _, offeredID := range offeredIDs {
				candidateID := strings.TrimSpace(asString(offeredID))
				if candidateID == "" {
					continue
				}
				credentialConfigID = candidateID
				break
			}
		}
	}
	if credentialConfigID == "" {
		credentialConfigID = "UniversityDegreeCredential"
	}

	tokenPayload, err := func() (map[string]interface{}, error) {
		tokenURL := s.issuerBaseURL + "/oid4vci/token"
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
		form.Set("pre-authorized_code", preAuthorizedCode)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("build token request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if strings.TrimSpace(options.LookingGlassSessionID) != "" {
			req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(options.LookingGlassSessionID))
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("token request failed: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("token request returned %d: %s", resp.StatusCode, oneLine(string(body)))
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("decode token response: %w", err)
		}
		return payload, nil
	}()
	if err != nil {
		return nil, err
	}

	accessToken := asString(tokenPayload["access_token"])
	cNonce := asString(tokenPayload["c_nonce"])
	if accessToken == "" || cNonce == "" {
		return nil, fmt.Errorf("token response missing access_token or c_nonce")
	}

	proofJWT, err := s.createCredentialProofJWT(wallet, offerWalletSubject, cNonce, s.issuerBaseURL+"/oid4vci")
	if err != nil {
		return nil, err
	}

	credentialURL := s.issuerBaseURL + "/oid4vci/credential"
	credentialRequestBody := map[string]interface{}{
		"credential_configuration_id": credentialConfigID,
		"format":                      strings.TrimSpace(options.CredentialFormat),
		"proofs": []map[string]interface{}{
			{
				"proof_type": "jwt",
				"jwt":        proofJWT,
			},
		},
	}
	rawCredentialBody, err := json.Marshal(credentialRequestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}
	credentialReq, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialURL, strings.NewReader(string(rawCredentialBody)))
	if err != nil {
		return nil, fmt.Errorf("build credential request: %w", err)
	}
	credentialReq.Header.Set("Accept", "application/json")
	credentialReq.Header.Set("Content-Type", "application/json")
	credentialReq.Header.Set("Authorization", "Bearer "+accessToken)
	if strings.TrimSpace(options.LookingGlassSessionID) != "" {
		credentialReq.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(options.LookingGlassSessionID))
	}
	credentialResp, err := s.httpClient.Do(credentialReq)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer credentialResp.Body.Close()
	credentialBody, _ := io.ReadAll(credentialResp.Body)
	if credentialResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential request returned %d: %s", credentialResp.StatusCode, oneLine(string(credentialBody)))
	}
	var credentialPayload map[string]interface{}
	if err := json.Unmarshal(credentialBody, &credentialPayload); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}

	if txID := strings.TrimSpace(asString(credentialPayload["transaction_id"])); txID != "" {
		deferredPayload, err := s.pollDeferredCredential(ctx, accessToken, txID, options.LookingGlassSessionID)
		if err != nil {
			return nil, fmt.Errorf("deferred credential polling failed: %w", err)
		}
		credentialPayload = deferredPayload
	}

	credentialJWT, err := credentialPayloadToString(credentialPayload["credential"])
	if err != nil {
		return nil, err
	}
	if credentialJWT == "" {
		return nil, fmt.Errorf("credential response missing credential")
	}
	credentialFormat := strings.TrimSpace(asString(credentialPayload["format"]))
	if credentialFormat == "" {
		credentialFormat = strings.TrimSpace(options.CredentialFormat)
	}
	if credentialFormat == "" {
		credentialFormat = summaryFormat(summarizeCredential(credentialJWT))
	}
	return &issuedWalletCredential{
		CredentialJWT:      credentialJWT,
		CredentialFormat:   credentialFormat,
		CredentialConfigID: credentialConfigID,
	}, nil
}

const deferredMaxRetries = 10
const deferredDefaultBackoff = 5 * time.Second

func (s *walletHarnessServer) pollDeferredCredential(
	ctx context.Context,
	accessToken string,
	transactionID string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	deferredURL := s.issuerBaseURL + "/oid4vci/deferred_credential"

	for attempt := 0; attempt < deferredMaxRetries; attempt++ {
		backoff := deferredDefaultBackoff
		reqBody, _ := json.Marshal(map[string]string{"transaction_id": transactionID})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, deferredURL, strings.NewReader(string(reqBody)))
		if err != nil {
			return nil, fmt.Errorf("build deferred request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		if strings.TrimSpace(lookingGlassSessionID) != "" {
			req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("deferred credential request failed: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var payload map[string]interface{}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, fmt.Errorf("decode deferred credential response: %w", err)
			}
			return payload, nil
		}

		if resp.StatusCode == http.StatusAccepted {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, err := strconv.Atoi(ra); err == nil && seconds > 0 {
					backoff = time.Duration(seconds) * time.Second
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}

		return nil, fmt.Errorf("deferred credential returned %d: %s", resp.StatusCode, oneLine(string(body)))
	}
	return nil, fmt.Errorf("deferred credential not ready after %d retries", deferredMaxRetries)
}

func (s *walletHarnessServer) resolveCredentialConfigurationForIssue(
	ctx context.Context,
	requestedCredentialConfigID string,
	requestedCredentialFormat string,
	lookingGlassSessionID string,
) (string, error) {
	normalizedCredentialConfigID := strings.TrimSpace(requestedCredentialConfigID)
	normalizedCredentialFormat := strings.TrimSpace(requestedCredentialFormat)
	if normalizedCredentialConfigID != "" {
		return normalizedCredentialConfigID, nil
	}
	if normalizedCredentialFormat == "" {
		return "UniversityDegreeCredential", nil
	}

	metadataURL := s.issuerBaseURL + "/oid4vci/.well-known/openid-credential-issuer"
	metadataReq, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("build issuer metadata request: %w", err)
	}
	metadataReq.Header.Set("Accept", "application/json")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		metadataReq.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}
	metadataResp, err := s.httpClient.Do(metadataReq)
	if err != nil {
		return "", fmt.Errorf("issuer metadata request failed: %w", err)
	}
	defer metadataResp.Body.Close()
	metadataBody, _ := io.ReadAll(metadataResp.Body)
	if metadataResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("issuer metadata request returned %d: %s", metadataResp.StatusCode, oneLine(string(metadataBody)))
	}
	var metadataPayload map[string]interface{}
	if err := json.Unmarshal(metadataBody, &metadataPayload); err != nil {
		return "", fmt.Errorf("decode issuer metadata response: %w", err)
	}
	rawSupportedConfigurations, _ := metadataPayload["credential_configurations_supported"].(map[string]interface{})
	if len(rawSupportedConfigurations) == 0 {
		return "", fmt.Errorf("issuer metadata missing credential_configurations_supported")
	}
	configurationIDs := make([]string, 0, len(rawSupportedConfigurations))
	for configurationID := range rawSupportedConfigurations {
		configurationIDs = append(configurationIDs, configurationID)
	}
	sort.Strings(configurationIDs)
	for _, configurationID := range configurationIDs {
		rawConfiguration, _ := rawSupportedConfigurations[configurationID].(map[string]interface{})
		if strings.TrimSpace(asString(rawConfiguration["format"])) != normalizedCredentialFormat {
			continue
		}
		return configurationID, nil
	}
	return "", fmt.Errorf("no credential configuration supports requested format %q", normalizedCredentialFormat)
}

func credentialPayloadToString(raw interface{}) (string, error) {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed), nil
	case map[string]interface{}, []interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			return "", fmt.Errorf("serialize credential payload: %w", err)
		}
		return strings.TrimSpace(string(serialized)), nil
	default:
		if raw == nil {
			return "", nil
		}
		serialized, err := json.Marshal(raw)
		if err != nil {
			return "", fmt.Errorf("serialize credential payload: %w", err)
		}
		return strings.TrimSpace(string(serialized)), nil
	}
}

func (s *walletHarnessServer) createCredentialProofJWT(wallet *walletMaterial, walletSubject string, cNonce string, audience string) (string, error) {
	subject := strings.TrimSpace(wallet.Subject)
	if subject == "" {
		subject = strings.TrimSpace(walletSubject)
	}
	if subject == "" {
		return "", fmt.Errorf("wallet subject is required for proof")
	}
	if strings.TrimSpace(cNonce) == "" {
		return "", fmt.Errorf("c_nonce is required for proof")
	}
	pubJWK, _, err := walletActiveJWK(wallet)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   firstNonEmpty(strings.TrimSpace(audience), s.issuerBaseURL+"/oid4vci"),
		"nonce": cNonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   randomValue(20),
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
		},
	}
	return walletSignToken(wallet, claims, map[string]interface{}{"typ": "openid4vci-proof+jwt"})
}

func (s *walletHarnessServer) createDirectPostResponseJWT(wallet *walletMaterial, requestContext *resolvedRequestContext, vpToken string) (string, error) {
	pubJWK, thumbprint, err := walletActiveJWK(wallet)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":      wallet.Subject,
		"sub":      wallet.Subject,
		"aud":      requestContext.ResponseURI,
		"state":    requestContext.State,
		"vp_token": vpToken,
		"iat":      now.Unix(),
		"exp":      now.Add(3 * time.Minute).Unix(),
		"jti":      randomValue(20),
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": thumbprint,
		},
	}
	return walletSignToken(wallet, claims, map[string]interface{}{"typ": "oauth-authz-resp+jwt"})
}

func (s *walletHarnessServer) encryptForVerifier(innerJWT string) (string, error) {
	verifierJWK, err := s.fetchVerifierRSAJWK(context.Background())
	if err != nil {
		return "", err
	}
	verifierPublicKey, err := intcrypto.ParseRSAPublicKeyFromJWK(verifierJWK)
	if err != nil {
		return "", fmt.Errorf("parse verifier rsa jwk: %w", err)
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       verifierPublicKey,
			KeyID:     verifierJWK.Kid,
		},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("create response encrypter: %w", err)
	}
	object, err := encrypter.Encrypt([]byte(innerJWT))
	if err != nil {
		return "", fmt.Errorf("encrypt response jwt: %w", err)
	}
	return object.CompactSerialize()
}

func (s *walletHarnessServer) fetchVerifierRSAJWK(ctx context.Context) (intcrypto.JWK, error) {
	jwksURL := s.targetBaseURL + "/api/.well-known/jwks.json"
	if _, err := s.validateAllowedURL(jwksURL); err != nil {
		return intcrypto.JWK{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return intcrypto.JWK{}, fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return intcrypto.JWK{}, fmt.Errorf("fetch verifier jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return intcrypto.JWK{}, fmt.Errorf("verifier jwks returned %d: %s", resp.StatusCode, oneLine(string(body)))
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return intcrypto.JWK{}, fmt.Errorf("decode verifier jwks: %w", err)
	}
	keys, ok := payload["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return intcrypto.JWK{}, fmt.Errorf("verifier jwks response is missing keys")
	}
	for _, keyRaw := range keys {
		keyBytes, err := json.Marshal(keyRaw)
		if err != nil {
			continue
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(keyBytes, &jwk); err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(jwk.Kty), "RSA") {
			return jwk, nil
		}
	}
	return intcrypto.JWK{}, fmt.Errorf("verifier jwks does not contain an RSA key")
}

func (s *walletHarnessServer) resolveWalletScopeKey(req walletSubmitRequest) (string, error) {
	lookingGlassSessionID := strings.TrimSpace(req.LookingGlassSessionID)
	if lookingGlassSessionID != "" {
		return "lg:" + lookingGlassSessionID, nil
	}

	requestID := strings.TrimSpace(req.RequestID)
	if requestID != "" {
		return "req:" + requestID, nil
	}

	requestJWT := strings.TrimSpace(req.Request)
	if requestJWT != "" {
		decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
		if err == nil {
			if requestObjectID := strings.TrimSpace(asString(decodedRequest.Payload["jti"])); requestObjectID != "" {
				return "req:" + requestObjectID, nil
			}
		}
		sum := sha256.Sum256([]byte(requestJWT))
		return "req:ext-" + hex.EncodeToString(sum[:12]), nil
	}

	if s.strictIsolation {
		return "", fmt.Errorf("session isolation key is required provide looking_glass_session_id or request_id")
	}
	return "legacy:shared", nil
}

func scopedWalletSubject(defaultSubject string, scopeKey string) string {
	baseSubject := strings.TrimSpace(defaultSubject)
	if baseSubject == "" {
		baseSubject = "did:example:wallet:holder"
	}
	normalizedScope := strings.TrimSpace(scopeKey)
	if normalizedScope == "" {
		return baseSubject
	}
	return baseSubject + "-" + scopeKeyFingerprint(normalizedScope)
}

func scopeKeyFingerprint(scopeKey string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(scopeKey)))
	encoded := hex.EncodeToString(digest[:])
	if len(encoded) < 12 {
		return encoded
	}
	return encoded[:12]
}

func requestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwardedProto != "" {
		scheme = forwardedProto
	}
	host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func inferWalletDIDMethod(subject string) string {
	normalizedSubject := strings.TrimSpace(subject)
	switch {
	case strings.HasPrefix(normalizedSubject, "did:key:"):
		return "key"
	case strings.HasPrefix(normalizedSubject, "did:jwk:"):
		return "jwk"
	case strings.HasPrefix(normalizedSubject, "did:web:"):
		return "web"
	default:
		return ""
	}
}

func activeJWKForKeyMaterial(keySet *intcrypto.KeySet, signingAlgorithm string) (intcrypto.JWK, error) {
	if keySet == nil {
		return intcrypto.JWK{}, fmt.Errorf("wallet key material is unavailable")
	}
	var kid string
	switch signingAlgorithm {
	case "ES256":
		kid = keySet.ECKeyID()
	case "RS256":
		kid = keySet.RSAKeyID()
	case "EdDSA":
		kid = keySet.Ed25519KeyID()
	default:
		return intcrypto.JWK{}, fmt.Errorf("unsupported signing algorithm %q", signingAlgorithm)
	}
	publicJWK, found := keySet.GetJWKByID(kid)
	if !found {
		return intcrypto.JWK{}, fmt.Errorf("wallet public jwk is unavailable for algorithm %s", signingAlgorithm)
	}
	return publicJWK, nil
}

func deriveWalletDIDWeb(baseURL string, scopeKey string) (string, error) {
	normalizedBaseURL := strings.TrimSpace(baseURL)
	if normalizedBaseURL == "" {
		return "", fmt.Errorf("wallet public base URL is required for did:web")
	}
	parsed, err := url.Parse(normalizedBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse wallet public base URL: %w", err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("wallet public base URL host is required for did:web")
	}
	hostSegment := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(parsed.Host)), ":", "%3A")
	pathSegments := []string{}
	if fingerprint := scopeKeyFingerprint(scopeKey); fingerprint != "" {
		pathSegments = append(pathSegments, "wallet", fingerprint)
	}
	identifierSegments := []string{hostSegment}
	for _, segment := range pathSegments {
		identifierSegments = append(identifierSegments, url.PathEscape(strings.TrimSpace(segment)))
	}
	return "did:web:" + strings.Join(identifierSegments, ":"), nil
}

func walletDIDSubjectFromDocumentRequest(r *http.Request) (string, error) {
	baseURL := requestBaseURL(r)
	if strings.TrimSpace(baseURL) == "" {
		return "", fmt.Errorf("wallet public base URL is required")
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse wallet public base URL: %w", err)
	}
	hostSegment := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(parsedBaseURL.Host)), ":", "%3A")
	if hostSegment == "" {
		return "", fmt.Errorf("wallet did:web host is required")
	}
	cleanPath := path.Clean("/" + strings.TrimSpace(r.URL.Path))
	if cleanPath == "/.well-known/did.json" {
		return "did:web:" + hostSegment, nil
	}
	if !strings.HasSuffix(cleanPath, "/did.json") {
		return "", fmt.Errorf("request path %q is not a did document path", cleanPath)
	}
	trimmedPath := strings.Trim(strings.TrimSuffix(cleanPath, "/did.json"), "/")
	if trimmedPath == "" {
		return "did:web:" + hostSegment, nil
	}
	pathSegments := strings.Split(trimmedPath, "/")
	identifierSegments := []string{hostSegment}
	for _, segment := range pathSegments {
		if strings.TrimSpace(segment) == "" {
			continue
		}
		identifierSegments = append(identifierSegments, url.PathEscape(strings.TrimSpace(segment)))
	}
	return "did:web:" + strings.Join(identifierSegments, ":"), nil
}

func buildWalletDIDDocument(wallet *walletMaterial) (map[string]interface{}, error) {
	if wallet == nil {
		return nil, fmt.Errorf("wallet is unavailable")
	}
	publicJWK, err := activeJWKForKeyMaterial(wallet.KeySet, wallet.SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	methodID, err := walletVerificationMethodID(wallet)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       strings.TrimSpace(wallet.Subject),
		"verificationMethod": []interface{}{
			map[string]interface{}{
				"id":           methodID,
				"type":         "JsonWebKey2020",
				"controller":   strings.TrimSpace(wallet.Subject),
				"publicKeyJwk": publicJWK,
			},
		},
		"authentication":  []interface{}{methodID},
		"assertionMethod": []interface{}{methodID},
	}, nil
}

func (s *walletHarnessServer) pruneExpiredWalletsLocked(now time.Time) {
	if s.walletSessionTTL <= 0 {
		return
	}
	for walletID, wallet := range s.wallets {
		if wallet == nil {
			delete(s.wallets, walletID)
			continue
		}
		if now.Sub(wallet.LastAccess) > s.walletSessionTTL {
			delete(s.wallets, walletID)
		}
	}
}

func (s *walletHarnessServer) getOrCreateWallet(scopeKey string, subject string, requestBaseURL string) (*walletMaterial, error) {
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return nil, fmt.Errorf("wallet subject is required")
	}
	normalizedScope := strings.TrimSpace(scopeKey)
	if normalizedScope == "" {
		if s.strictIsolation {
			return nil, fmt.Errorf("session isolation key is required")
		}
		normalizedScope = "legacy:shared"
	}

	now := time.Now().UTC()
	walletID := normalizedScope + "|" + normalizedSubject

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredWalletsLocked(now)

	for _, existing := range s.wallets {
		if existing == nil {
			continue
		}
		if existing.ScopeKey == normalizedScope && strings.TrimSpace(existing.Subject) == normalizedSubject {
			existing.LastAccess = now
			return existing, nil
		}
	}
	if existing, ok := s.wallets[walletID]; ok {
		existing.LastAccess = now
		return existing, nil
	}
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		return nil, fmt.Errorf("create wallet keyset: %w", err)
	}
	signingAlgorithm, err := resolveWalletSigningAlgorithm(envOrDefault("WALLET_DEFAULT_SIGNING_ALG", "ES256"))
	if err != nil {
		return nil, err
	}
	wallet := &walletMaterial{
		ScopeKey:         normalizedScope,
		Subject:          normalizedSubject,
		KeySet:           keySet,
		SigningAlgorithm: signingAlgorithm,
		DIDMethod:        inferWalletDIDMethod(normalizedSubject),
		Credentials:      make(map[string]walletCredentialMaterial),
		CreatedAt:        now,
		LastAccess:       now,
	}
	if strings.HasPrefix(normalizedSubject, "did:example:") {
		derivedDIDMethod := firstNonEmpty(strings.TrimSpace(s.walletDIDMethod), "key")
		derivedSubject := ""
		switch derivedDIDMethod {
		case "key":
			switch wallet.SigningAlgorithm {
			case "ES256":
				derivedSubject, err = vc.DIDKeyFromECPublicKey(keySet.ECPublicKey())
			case "EdDSA":
				derivedSubject, err = vc.DIDKeyFromEd25519PublicKey(keySet.Ed25519PublicKey())
			case "RS256":
				derivedSubject, err = vc.DIDKeyFromRSAPublicKey(keySet.RSAPublicKey())
			}
		case "jwk":
			publicJWK, publicJWKErr := activeJWKForKeyMaterial(keySet, wallet.SigningAlgorithm)
			if publicJWKErr != nil {
				err = publicJWKErr
			} else {
				derivedSubject, err = vc.DIDJWKFromJSON(publicJWK)
			}
		case "web":
			derivedSubject, err = deriveWalletDIDWeb(requestBaseURL, normalizedScope)
		default:
			err = fmt.Errorf("unsupported did method %q", derivedDIDMethod)
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(derivedSubject) != "" {
			wallet.Subject = derivedSubject
			wallet.DIDMethod = derivedDIDMethod
		}
	}
	s.wallets[walletID] = wallet
	return wallet, nil
}

func (s *walletHarnessServer) bindCredential(wallet *walletMaterial, credentialJWT string, credentialConfigID string, credentialFormat string) error {
	normalizedCredential := strings.TrimSpace(credentialJWT)
	if normalizedCredential == "" {
		return fmt.Errorf("credential is required")
	}

	parsedCredential, err := vc.DefaultCredentialFormatRegistry().ParseAnyCredential(normalizedCredential)
	if err != nil {
		return fmt.Errorf("credential parse failed: %w", err)
	}
	subject := strings.TrimSpace(parsedCredential.Subject)
	if subject == "" {
		return fmt.Errorf("credential is missing subject binding")
	}
	if strings.TrimSpace(subject) != wallet.Subject {
		if !strings.HasPrefix(strings.TrimSpace(subject), "did:example:wallet:") && !strings.HasPrefix(wallet.Subject, "did:key:") {
			return fmt.Errorf("credential subject %q does not match wallet_subject %q", strings.TrimSpace(subject), wallet.Subject)
		}
	}
	if wallet.Credentials == nil {
		wallet.Credentials = make(map[string]walletCredentialMaterial)
	}
	summary := summarizeCredential(normalizedCredential)
	normalizedCredentialID := ""
	if decodedCredential, decodeErr := intcrypto.DecodeTokenWithoutValidation(normalizedCredential); decodeErr == nil {
		normalizedCredentialID = strings.TrimSpace(asString(decodedCredential.Payload["jti"]))
	}
	if normalizedCredentialID == "" {
		sum := sha256.Sum256([]byte(normalizedCredential))
		normalizedCredentialID = hex.EncodeToString(sum[:16])
	}
	normalizedCredentialFormat := strings.TrimSpace(credentialFormat)
	if normalizedCredentialFormat == "" {
		normalizedCredentialFormat = summaryFormat(summary)
	}
	normalizedCredentialConfigID := strings.TrimSpace(credentialConfigID)
	now := time.Now().UTC()
	record := walletCredentialMaterial{
		CredentialID:              normalizedCredentialID,
		CredentialJWT:             normalizedCredential,
		Format:                    normalizedCredentialFormat,
		CredentialConfigurationID: normalizedCredentialConfigID,
		VCT:                       summaryVCT(summary),
		Doctype:                   summaryDoctype(summary),
		IssuedAt:                  now,
		UpdatedAt:                 now,
	}
	if existing, ok := wallet.Credentials[normalizedCredentialID]; ok {
		if !existing.IssuedAt.IsZero() {
			record.IssuedAt = existing.IssuedAt
		}
		if record.CredentialConfigurationID == "" {
			record.CredentialConfigurationID = existing.CredentialConfigurationID
		}
		if record.Format == "" {
			record.Format = existing.Format
		}
		if record.VCT == "" {
			record.VCT = existing.VCT
		}
		if record.Doctype == "" {
			record.Doctype = existing.Doctype
		}
	}
	wallet.Credentials[normalizedCredentialID] = record
	activateWalletCredential(wallet, record)
	return nil
}

func credentialRefreshRequired(credentialJWT string, minRemaining time.Duration) (bool, error) {
	normalizedCredential := strings.TrimSpace(credentialJWT)
	if normalizedCredential == "" {
		return true, fmt.Errorf("credential is required")
	}
	parsedCredential, err := vc.DefaultCredentialFormatRegistry().ParseAnyCredential(normalizedCredential)
	if err != nil {
		return true, fmt.Errorf("parse credential: %w", err)
	}
	if parsedCredential.ExpiresAt.IsZero() {
		return false, nil
	}
	return time.Until(parsedCredential.ExpiresAt) <= minRemaining, nil
}

func walletUserIDFromSubject(subject string) string {
	normalized := strings.TrimSpace(subject)
	if normalized == "" {
		return "alice"
	}
	const didPrefix = "did:example:wallet:"
	lowered := strings.ToLower(normalized)
	if strings.HasPrefix(lowered, didPrefix) && len(normalized) > len(didPrefix) {
		return strings.TrimSpace(normalized[len(didPrefix):])
	}
	if idx := strings.LastIndex(normalized, ":"); idx >= 0 && idx+1 < len(normalized) {
		return strings.TrimSpace(normalized[idx+1:])
	}
	return normalized
}

func (s *walletHarnessServer) validateAllowedURL(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not allowed")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	if host != s.targetHost {
		return "", fmt.Errorf("URL host %q is not allowed", host)
	}
	return parsed.String(), nil
}

func withNoStoreHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler, allowedOrigins map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		originAllowed := false
		if origin != "" {
			if _, ok := allowedOrigins[origin]; ok {
				originAllowed = true
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-Wallet-Session, X-Looking-Glass-Session")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.Header().Set("Vary", "Origin")
			}
		}
		if r.Method == http.MethodOptions {
			if origin != "" && !originAllowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseOriginAllowList(raw string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		normalized := strings.TrimSpace(candidate)
		if normalized == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(normalized)
		if err != nil {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		if parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			continue
		}
		allowed[parsed.Scheme+"://"+parsed.Host] = struct{}{}
	}
	return allowed
}

func parseURLAllowList(raw string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		normalized := strings.TrimSpace(candidate)
		if normalized == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(normalized)
		if err != nil {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		if parsed.Host == "" || parsed.User != nil {
			continue
		}
		allowed[strings.TrimRight(parsed.String(), "/")] = struct{}{}
	}
	return allowed
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func buildPresentationSubmission(presDef map[string]interface{}, vpToken string) (string, error) {
	if presDef == nil {
		return "", nil
	}
	return vc.BuildPresentationSubmission(presDef, vpToken)
}

func asString(value interface{}) string {
	str, _ := value.(string)
	return strings.TrimSpace(str)
}

func randomValue(size int) string {
	if size <= 0 {
		size = 24
	}
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)[:size]
}

func oneLine(value string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ")
	return strings.TrimSpace(replacer.Replace(value))
}
