package main

import (
	"context"
	"crypto/rand"
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
	"strings"
	"sync"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type walletHarnessServer struct {
	httpClient *http.Client

	targetBaseURL     string
	targetHost        string
	targetResponseURI string
	issuerBaseURL     string
	allowExternal     bool
	appTitle          string

	defaultWalletSubject string
	walletSessionTTL     time.Duration
	strictIsolation      bool
	allowedCORSOrigins   map[string]struct{}

	mu      sync.Mutex
	wallets map[string]*walletMaterial
}

type walletMaterial struct {
	ScopeKey                  string
	Subject                   string
	KeySet                    *intcrypto.KeySet
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
	VPToken               string   `json:"vp_token,omitempty"`
	DisclosureClaims      []string `json:"disclosure_claims,omitempty"`
	LookingGlassSessionID string   `json:"looking_glass_session_id,omitempty"`
}

type resolvedRequestContext struct {
	RequestID    string
	State        string
	Nonce        string
	ClientID     string
	ResponseMode string
	ResponseURI  string
	Trusted      bool
}

type resolvedRequestEnvelope struct {
	RequestJWT       string
	RequestURI       string
	RequestID        string
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
	TrustedTarget          bool                    `json:"trusted_target"`
	RequiresExternalAccept bool                    `json:"requires_external_approval"`
	AllowExternalVerifiers bool                    `json:"allow_external_verifiers"`
	ClientIDScheme         string                  `json:"client_id_scheme,omitempty"`
	DidWeb                 *didWebResolutionResult `json:"did_web,omitempty"`
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
		targetBaseURL:        targetBaseURL,
		targetHost:           targetHost,
		targetResponseURI:    targetBaseURL + "/oid4vp/response",
		issuerBaseURL:        issuerBaseURL,
		allowExternal:        allowExternal,
		appTitle:             appTitle,
		defaultWalletSubject: defaultWalletSubject,
		walletSessionTTL:     walletSessionTTL,
		strictIsolation:      strictIsolation,
		allowedCORSOrigins:   allowedCORSOrigins,
		wallets:              make(map[string]*walletMaterial),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/submit", server.handleSubmit)
	mux.HandleFunc("/api/resolve", server.handleAPIResolve)
	mux.HandleFunc("/api/session", server.handleAPISession)
	mux.HandleFunc("/api/issue", server.handleAPIIssue)
	mux.HandleFunc("/api/preview", server.handleAPIPreview)
	mux.HandleFunc("/api/present", server.handleAPIPresent)
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
	envelope, err := s.resolveRequestEnvelope(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	requestContext, err := s.resolveRequestContextWithOptions(envelope.RequestID, envelope.RequestJWT, true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	trust := s.evaluateTrust(requestContext, envelope.DecodedPayload)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":         requestContext.RequestID,
		"request_uri":        envelope.RequestURI,
		"request":            envelope.RequestJWT,
		"request_uri_source": envelope.RequestURISource,
		"response_mode":      requestContext.ResponseMode,
		"response_uri":       requestContext.ResponseURI,
		"client_id":          requestContext.ClientID,
		"state":              requestContext.State,
		"nonce":              requestContext.Nonce,
		"scope":              asString(envelope.DecodedPayload["scope"]),
		"dcql_query":         envelope.DecodedPayload["dcql_query"],
		"request_header":     envelope.DecodedHeader,
		"request_payload":    envelope.DecodedPayload,
		"trust":              trust,
	})
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
	wallet, err := s.getOrCreateWallet(scopeKey, subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}
	var keyThumbprint string
	if pubJWK, ok := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID()); ok {
		keyThumbprint = strings.TrimSpace(pubJWK.Thumbprint())
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
		"wallet_key_id":               wallet.KeySet.RSAKeyID(),
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
	wallet, err := s.getOrCreateWallet(scopeKey, subject)
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
	wallet, err := s.getOrCreateWallet(scopeKey, subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credentialSelectionOptions{
		ProvidedCredentialJWT: strings.TrimSpace(req.CredentialJWT),
		CredentialID:          strings.TrimSpace(req.CredentialID),
		CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
		CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
		LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
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
	if !trust.TrustedTarget && !s.allowExternal {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "invalid_request",
			"error_description": "external verifier requests are disabled by wallet configuration",
		})
		return
	}

	presentedCredential, disclosureClaims, err := buildPresentedCredential(wallet.CredentialJWT, req.DisclosureClaims)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	vpToken, err := s.createVPToken(wallet, requestContext, presentedCredential)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("create vp_token: %v", err),
		})
		return
	}
	vpHeader := map[string]interface{}{}
	vpPayload := map[string]interface{}{}
	if decodedVP, decodeErr := intcrypto.DecodeTokenWithoutValidation(vpToken); decodeErr == nil && decodedVP != nil {
		vpHeader = decodedVP.Header
		vpPayload = decodedVP.Payload
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mode":                        "preview",
		"request_id":                  requestContext.RequestID,
		"request_uri":                 envelope.RequestURI,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"vp_token":                    vpToken,
		"vp_header":                   vpHeader,
		"vp_payload":                  vpPayload,
		"request_header":              envelope.DecodedHeader,
		"request_payload":             envelope.DecodedPayload,
		"trust":                       trust,
	})
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
	wallet, err := s.getOrCreateWallet(scopeKey, subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, credentialSelectionOptions{
		ProvidedCredentialJWT: strings.TrimSpace(req.CredentialJWT),
		CredentialID:          strings.TrimSpace(req.CredentialID),
		CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
		CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
		LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
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
	if !trust.TrustedTarget {
		if !s.allowExternal {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":             "invalid_request",
				"error_description": "external verifier requests are disabled by wallet configuration",
			})
			return
		}
		if !req.ApproveExternalTrust {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "external verifier trust approval is required",
			})
			return
		}
	}

	presentedCredential, disclosureClaims, err := buildPresentedCredential(wallet.CredentialJWT, req.DisclosureClaims)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}
	vpToken, err := s.createVPToken(wallet, requestContext, presentedCredential)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("create vp_token: %v", err),
		})
		return
	}
	upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, strings.TrimSpace(req.LookingGlassSessionID))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}
	writeJSON(w, upstreamStatus, map[string]interface{}{
		"mode":                        "present",
		"request_id":                  requestContext.RequestID,
		"request_uri":                 envelope.RequestURI,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"upstream_status":             upstreamStatus,
		"upstream_body":               upstreamBody,
		"external_trust_approved":     req.ApproveExternalTrust,
		"trust":                       trust,
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
	wallet, err := s.getOrCreateWallet(scopeKey, subject)
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

	requestContext, err := s.resolveRequestContext(req.RequestID, req.Request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	vpToken := req.VPToken
	disclosureClaims := req.DisclosureClaims
	if vpToken == "" {
		presentedCredential, selectedDisclosureClaims, err := buildPresentedCredential(wallet.CredentialJWT, req.DisclosureClaims)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		disclosureClaims = selectedDisclosureClaims
		vpToken, err = s.createVPToken(wallet, requestContext, presentedCredential)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("create vp_token: %v", err),
			})
			return
		}
	}

	upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, req.LookingGlassSessionID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": err.Error(),
		})
		return
	}

	writeJSON(w, upstreamStatus, map[string]interface{}{
		"mode":                        "one_click",
		"request_id":                  requestContext.RequestID,
		"response_mode":               requestContext.ResponseMode,
		"response_uri":                requestContext.ResponseURI,
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"credential_source":           credentialSource,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"disclosure_claims":           disclosureClaims,
		"upstream_status":             upstreamStatus,
		"upstream_body":               upstreamBody,
		"wallet_stepwise_hint":        "use mode=stepwise for keygen/issuance/presentation ceremony controls",
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
	requestContext, err := s.resolveRequestContextWithOptions(envelope.RequestID, envelope.RequestJWT, true)
	if err != nil {
		return nil, nil, trustEvaluation{}, err
	}
	trust := s.evaluateTrust(requestContext, envelope.DecodedPayload)
	return envelope, requestContext, trust, nil
}

func (s *walletHarnessServer) resolveRequestEnvelope(ctx context.Context, req apiResolveRequest) (*resolvedRequestEnvelope, error) {
	requestURI := strings.TrimSpace(req.RequestURI)
	openID4VPURI := strings.TrimSpace(req.OpenID4VP)
	requestJWT := strings.TrimSpace(req.RequestJWT)
	requestID := strings.TrimSpace(req.RequestID)
	requestSource := ""

	if openID4VPURI != "" {
		uriRequestURI, uriRequestJWT, err := parseOpenID4VPURI(openID4VPURI)
		if err != nil {
			return nil, err
		}
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
	if requestID == "" {
		requestID = strings.TrimSpace(asString(decodedRequest.Payload["jti"]))
	}
	if requestID == "" {
		return nil, fmt.Errorf("request object is missing jti")
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
		DecodedHeader:    header,
		DecodedPayload:   payload,
		RequestURISource: requestSource,
	}, nil
}

func parseOpenID4VPURI(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", fmt.Errorf("openid4vp_uri is required")
	}
	parsedURI, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid openid4vp_uri: %w", err)
	}
	if !strings.EqualFold(parsedURI.Scheme, "openid4vp") {
		return "", "", fmt.Errorf("unsupported URI scheme %q expected openid4vp", parsedURI.Scheme)
	}
	query := parsedURI.Query()
	requestURI := strings.TrimSpace(query.Get("request_uri"))
	requestJWT := strings.TrimSpace(query.Get("request"))
	if requestURI == "" && requestJWT == "" {
		return "", "", fmt.Errorf("openid4vp_uri must include request_uri or request parameter")
	}
	return requestURI, requestJWT, nil
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
	lastError := fmt.Errorf("request object fetch failed")
	for _, method := range methods {
		var bodyReader io.Reader
		if method == http.MethodPost {
			bodyReader = strings.NewReader(url.Values{}.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, requestURI, bodyReader)
		if err != nil {
			lastError = fmt.Errorf("build %s request_uri request: %w", method, err)
			continue
		}
		req.Header.Set("Accept", "application/json")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastError = fmt.Errorf("request_uri fetch failed: %w", err)
			continue
		}
		responseBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastError = fmt.Errorf("request_uri returned %d: %s", resp.StatusCode, oneLine(string(responseBytes)))
			continue
		}
		trimmedBody := strings.TrimSpace(string(responseBytes))
		if trimmedBody == "" {
			lastError = fmt.Errorf("request_uri returned an empty response body")
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
		lastError = fmt.Errorf("request_uri response did not contain a request object jwt")
	}
	return "", "", lastError
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

func summarizeCredential(rawCredential string) *credentialSummary {
	normalized := strings.TrimSpace(rawCredential)
	if normalized == "" {
		return nil
	}
	summary := &credentialSummary{}
	credentialToDecode := normalized

	if envelope, err := vc.ParseSDJWTEnvelope(normalized); err == nil {
		summary.IsSDJWT = true
		summary.Format = "dc+sd-jwt"
		credentialToDecode = strings.TrimSpace(envelope.IssuerSignedJWT)
		summary.DisclosureCount = len(envelope.Disclosures)
		summary.KeyBindingJWT = strings.TrimSpace(envelope.KeyBindingJWT) != ""
		disclosureClaims := make([]string, 0, len(envelope.Disclosures))
		for _, disclosure := range envelope.Disclosures {
			decodedDisclosure, err := vc.DecodeSDJWTDisclosure(disclosure)
			if err != nil {
				continue
			}
			claimName := strings.TrimSpace(decodedDisclosure.ClaimName)
			if claimName == "" {
				continue
			}
			disclosureClaims = append(disclosureClaims, claimName)
		}
		sort.Strings(disclosureClaims)
		summary.DisclosureClaims = disclosureClaims
	}

	decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(credentialToDecode)
	if err != nil {
		return summary
	}
	claimsCopy := make(map[string]interface{}, len(decodedCredential.Payload))
	for key, value := range decodedCredential.Payload {
		claimsCopy[key] = value
	}
	summary.Claims = claimsCopy
	summary.Subject = strings.TrimSpace(asString(decodedCredential.Payload["sub"]))
	summary.VCT = strings.TrimSpace(asString(decodedCredential.Payload["vct"]))
	summary.Doctype = strings.TrimSpace(asString(decodedCredential.Payload["doctype"]))
	vcObject, _ := decodedCredential.Payload["vc"].(map[string]interface{})
	if rawTypes, ok := vcObject["type"].([]interface{}); ok {
		types := make([]string, 0, len(rawTypes))
		for _, rawType := range rawTypes {
			typeName := strings.TrimSpace(asString(rawType))
			if typeName == "" {
				continue
			}
			types = append(types, typeName)
		}
		sort.Strings(types)
		summary.CredentialTypes = dedupeStringList(types)
	}
	if summary.Format == "" {
		if formatClaim := strings.TrimSpace(asString(decodedCredential.Payload["format"])); formatClaim != "" {
			summary.Format = formatClaim
		}
	}
	if summary.Format == "" {
		if headerType := strings.TrimSpace(asString(decodedCredential.Header["typ"])); headerType != "" {
			switch headerType {
			case "mdoc+jwt":
				summary.Format = "mso_mdoc"
			case "vc+ldp-jwt":
				summary.Format = "ldp_vc"
			case "vc+jwt":
				if _, hasContext := vcObject["@context"]; hasContext {
					summary.Format = "jwt_vc_json-ld"
				} else {
					summary.Format = "jwt_vc_json"
				}
			}
		}
	}
	if summary.Format == "" {
		summary.Format = "jwt_vc_json"
	}
	if expRaw, ok := decodedCredential.Payload["exp"]; ok {
		expUnix, err := toUnixTimestamp(expRaw)
		if err == nil && expUnix > 0 {
			summary.ExpiresAt = time.Unix(expUnix, 0).UTC().Format(time.RFC3339)
		}
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
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "bootstrap",
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"wallet_key_id":               wallet.KeySet.RSAKeyID(),
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
		requestContext, err := s.resolveRequestContext(req.RequestID, req.Request)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		presentedCredential, disclosureClaims, err := buildPresentedCredential(wallet.CredentialJWT, req.DisclosureClaims)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		vpToken, err := s.createVPToken(wallet, requestContext, presentedCredential)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("create vp_token: %v", err),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "build_presentation",
			"request_id":                  requestContext.RequestID,
			"response_mode":               requestContext.ResponseMode,
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"credential_source":           credentialSource,
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
			"disclosure_claims":           disclosureClaims,
			"vp_token":                    vpToken,
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
		requestContext, err := s.resolveRequestContext(req.RequestID, req.Request)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		vpToken := strings.TrimSpace(req.VPToken)
		disclosureClaims := req.DisclosureClaims
		if vpToken == "" {
			presentedCredential, selectedClaims, err := buildPresentedCredential(wallet.CredentialJWT, req.DisclosureClaims)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":             "invalid_request",
					"error_description": err.Error(),
				})
				return
			}
			disclosureClaims = selectedClaims
			vpToken, err = s.createVPToken(wallet, requestContext, presentedCredential)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error":             "wallet_submission_failed",
					"error_description": fmt.Sprintf("create vp_token: %v", err),
				})
				return
			}
		}
		upstreamStatus, upstreamBody, err := s.submitToVerifier(r.Context(), wallet, requestContext, vpToken, req.LookingGlassSessionID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		writeJSON(w, upstreamStatus, map[string]interface{}{
			"mode":                        "stepwise",
			"step":                        "submit_response",
			"request_id":                  requestContext.RequestID,
			"response_mode":               requestContext.ResponseMode,
			"response_uri":                requestContext.ResponseURI,
			"wallet_subject":              wallet.Subject,
			"wallet_scope":                wallet.ScopeKey,
			"credential_source":           credentialSource,
			"credential_id":               wallet.CredentialID,
			"credential_format":           wallet.CredentialFormat,
			"credential_configuration_id": wallet.CredentialConfigurationID,
			"disclosure_claims":           disclosureClaims,
			"upstream_status":             upstreamStatus,
			"upstream_body":               upstreamBody,
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

func buildPresentedCredential(rawCredential string, requestedClaims []string) (string, []string, error) {
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
	form.Set("state", requestContext.State)
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

func (s *walletHarnessServer) resolveRequestContext(requestID string, requestJWT string) (*resolvedRequestContext, error) {
	return s.resolveRequestContextWithOptions(requestID, requestJWT, false)
}

func (s *walletHarnessServer) resolveRequestContextWithOptions(requestID string, requestJWT string, allowExternal bool) (*resolvedRequestContext, error) {
	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		return nil, fmt.Errorf("decode request object jwt: %w", err)
	}
	normalizedRequestID := strings.TrimSpace(requestID)
	requestObjectID := strings.TrimSpace(asString(decodedRequest.Payload["jti"]))
	if requestObjectID == "" {
		return nil, fmt.Errorf("request object is missing jti")
	}
	if normalizedRequestID == "" {
		normalizedRequestID = requestObjectID
	}
	if normalizedRequestID != requestObjectID {
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
	clientID := strings.TrimSpace(asString(decodedRequest.Payload["client_id"]))
	if state == "" || nonce == "" || clientID == "" {
		return nil, fmt.Errorf("request object is missing state/nonce/client_id")
	}

	return &resolvedRequestContext{
		RequestID:    normalizedRequestID,
		State:        state,
		Nonce:        nonce,
		ClientID:     clientID,
		ResponseMode: responseMode,
		ResponseURI:  responseURI,
		Trusted:      trusted,
	}, nil
}

func (s *walletHarnessServer) createVPToken(wallet *walletMaterial, requestContext *resolvedRequestContext, presentedCredentialJWT string) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		return "", fmt.Errorf("wallet public jwk is unavailable")
	}
	thumbprint := strings.TrimSpace(pubJWK.Thumbprint())
	if thumbprint == "" {
		return "", fmt.Errorf("wallet jwk thumbprint is unavailable")
	}

	presentedCredential := strings.TrimSpace(presentedCredentialJWT)
	if presentedCredential == "" {
		presentedCredential = strings.TrimSpace(wallet.CredentialJWT)
	}
	activeCredential := walletActiveCredential(wallet, presentedCredential)
	activeSummary := summarizeCredential(presentedCredential)
	credentialFormat := firstNonEmpty(activeCredential.Format, summaryFormat(activeSummary))
	if credentialFormat == "" {
		credentialFormat = "jwt_vc_json"
	}
	vct := firstNonEmpty(activeCredential.VCT, summaryVCT(activeSummary), "https://protocolsoup.com/credentials/university_degree")
	doctype := firstNonEmpty(activeCredential.Doctype, summaryDoctype(activeSummary))
	credentialID := firstNonEmpty(activeCredential.CredentialID, strings.TrimSpace(wallet.CredentialID))

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   requestContext.ClientID,
		"nonce": requestContext.Nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"jti":   randomValue(20),
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": thumbprint,
		},
		"vp": map[string]interface{}{
			"vct":            vct,
			"format":         credentialFormat,
			"credential_id":  credentialID,
			"credential_jwt": presentedCredential,
			"credentials": []map[string]interface{}{
				{
					"credential_id":  credentialID,
					"format":         credentialFormat,
					"vct":            vct,
					"doctype":        doctype,
					"credential_jwt": presentedCredential,
					"credential":     presentedCredential,
				},
			},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	return token.SignedString(wallet.KeySet.RSAPrivateKey())
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
	if strings.TrimSpace(wallet.Subject) != "" && offerWalletSubject != strings.TrimSpace(wallet.Subject) {
		return nil, fmt.Errorf("offer wallet_subject %q does not match wallet subject %q", offerWalletSubject, wallet.Subject)
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

	proofJWT, err := s.createCredentialProofJWT(wallet, offerWalletSubject, cNonce)
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

func (s *walletHarnessServer) createCredentialProofJWT(wallet *walletMaterial, walletSubject string, cNonce string) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	subject := strings.TrimSpace(walletSubject)
	if subject == "" {
		subject = strings.TrimSpace(wallet.Subject)
	}
	if subject == "" {
		return "", fmt.Errorf("wallet subject is required for proof")
	}
	if strings.TrimSpace(cNonce) == "" {
		return "", fmt.Errorf("c_nonce is required for proof")
	}
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		return "", fmt.Errorf("wallet public jwk is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   s.issuerBaseURL + "/oid4vci",
		"nonce": cNonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   randomValue(20),
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	return token.SignedString(wallet.KeySet.RSAPrivateKey())
}

func (s *walletHarnessServer) createDirectPostResponseJWT(wallet *walletMaterial, requestContext *resolvedRequestContext, vpToken string) (string, error) {
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		return "", fmt.Errorf("wallet public jwk is unavailable")
	}
	thumbprint := strings.TrimSpace(pubJWK.Thumbprint())
	if thumbprint == "" {
		return "", fmt.Errorf("wallet jwk thumbprint is unavailable")
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "oauth-authz-resp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	return token.SignedString(wallet.KeySet.RSAPrivateKey())
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

func (s *walletHarnessServer) getOrCreateWallet(scopeKey string, subject string) (*walletMaterial, error) {
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

	if existing, ok := s.wallets[walletID]; ok {
		existing.LastAccess = now
		return existing, nil
	}
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		return nil, fmt.Errorf("create wallet keyset: %w", err)
	}
	wallet := &walletMaterial{
		ScopeKey:    normalizedScope,
		Subject:     normalizedSubject,
		KeySet:      keySet,
		Credentials: make(map[string]walletCredentialMaterial),
		CreatedAt:   now,
		LastAccess:  now,
	}
	s.wallets[walletID] = wallet
	return wallet, nil
}

func (s *walletHarnessServer) bindCredential(wallet *walletMaterial, credentialJWT string, credentialConfigID string, credentialFormat string) error {
	normalizedCredential := strings.TrimSpace(credentialJWT)
	decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(normalizedCredential)
	if err != nil {
		return fmt.Errorf("credential_jwt decode failed: %w", err)
	}
	subject, _ := decodedCredential.Payload["sub"].(string)
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("credential_jwt missing sub claim")
	}
	if strings.TrimSpace(subject) != wallet.Subject {
		return fmt.Errorf("credential_jwt sub %q does not match wallet_subject %q", strings.TrimSpace(subject), wallet.Subject)
	}
	if wallet.Credentials == nil {
		wallet.Credentials = make(map[string]walletCredentialMaterial)
	}
	summary := summarizeCredential(normalizedCredential)
	normalizedCredentialID := strings.TrimSpace(asString(decodedCredential.Payload["jti"]))
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
	tokenToDecode := normalizedCredential
	if envelope, err := vc.ParseSDJWTEnvelope(normalizedCredential); err == nil {
		tokenToDecode = strings.TrimSpace(envelope.IssuerSignedJWT)
	}
	decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(tokenToDecode)
	if err != nil {
		return true, fmt.Errorf("decode credential_jwt: %w", err)
	}
	expRaw, ok := decodedCredential.Payload["exp"]
	if !ok {
		return true, fmt.Errorf("credential_jwt missing exp claim")
	}
	expUnix, err := toUnixTimestamp(expRaw)
	if err != nil {
		return true, fmt.Errorf("parse credential_jwt exp claim: %w", err)
	}
	expiry := time.Unix(expUnix, 0).UTC()
	return time.Until(expiry) <= minRemaining, nil
}

func toUnixTimestamp(raw interface{}) (int64, error) {
	switch value := raw.(type) {
	case float64:
		return int64(value), nil
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	case json.Number:
		return value.Int64()
	default:
		return 0, fmt.Errorf("unsupported numeric timestamp type %T", raw)
	}
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
