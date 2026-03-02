package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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

	defaultWalletSubject string
	walletSessionTTL     time.Duration
	strictIsolation      bool
	allowedCORSOrigins   map[string]struct{}

	mu      sync.Mutex
	wallets map[string]*walletMaterial
}

type walletMaterial struct {
	ScopeKey      string
	Subject       string
	KeySet        *intcrypto.KeySet
	CredentialJWT string
	CreatedAt     time.Time
	LastAccess    time.Time
}

type walletSubmitRequest struct {
	RequestID             string   `json:"request_id"`
	Request               string   `json:"request,omitempty"`
	WalletSubject         string   `json:"wallet_subject,omitempty"`
	Subject               string   `json:"subject,omitempty"`
	CredentialJWT         string   `json:"credential_jwt,omitempty"`
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
}

func main() {
	listenAddr := envOrDefault("WALLET_LISTEN_ADDR", ":8080")
	targetBaseURL := strings.TrimRight(strings.TrimSpace(envOrDefault("WALLET_TARGET_BASE_URL", "https://protocolsoup.com")), "/")
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
		defaultWalletSubject: defaultWalletSubject,
		walletSessionTTL:     walletSessionTTL,
		strictIsolation:      strictIsolation,
		allowedCORSOrigins:   allowedCORSOrigins,
		wallets:              make(map[string]*walletMaterial),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/submit", server.handleSubmit)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           withNoStoreHeaders(withCORS(mux, server.allowedCORSOrigins)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("wallet harness listening on %s", listenAddr)
	log.Printf("wallet harness target base URL: %s", targetBaseURL)
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

	credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, req.CredentialJWT, req.LookingGlassSessionID)
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
		"mode":                 "one_click",
		"request_id":           requestContext.RequestID,
		"response_mode":        requestContext.ResponseMode,
		"response_uri":         s.targetResponseURI,
		"wallet_subject":       wallet.Subject,
		"wallet_scope":         wallet.ScopeKey,
		"credential_source":    credentialSource,
		"disclosure_claims":    disclosureClaims,
		"upstream_status":      upstreamStatus,
		"upstream_body":        upstreamBody,
		"wallet_stepwise_hint": "use mode=stepwise for keygen/issuance/presentation ceremony controls",
	})
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
			"mode":              "stepwise",
			"step":              "bootstrap",
			"wallet_subject":    wallet.Subject,
			"wallet_scope":      wallet.ScopeKey,
			"wallet_key_id":     wallet.KeySet.RSAKeyID(),
			"credential_cached": strings.TrimSpace(wallet.CredentialJWT) != "",
		})
		return

	case "issue_credential":
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, req.CredentialJWT, req.LookingGlassSessionID)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode":              "stepwise",
			"step":              "issue_credential",
			"wallet_subject":    wallet.Subject,
			"wallet_scope":      wallet.ScopeKey,
			"credential_source": credentialSource,
			"credential_cached": strings.TrimSpace(wallet.CredentialJWT) != "",
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
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, req.CredentialJWT, req.LookingGlassSessionID)
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
			"mode":              "stepwise",
			"step":              "build_presentation",
			"request_id":        requestContext.RequestID,
			"response_mode":     requestContext.ResponseMode,
			"wallet_subject":    wallet.Subject,
			"wallet_scope":      wallet.ScopeKey,
			"credential_source": credentialSource,
			"disclosure_claims": disclosureClaims,
			"vp_token":          vpToken,
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
		credentialSource, err := s.ensureWalletCredential(r.Context(), wallet, req.CredentialJWT, req.LookingGlassSessionID)
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
			"mode":              "stepwise",
			"step":              "submit_response",
			"request_id":        requestContext.RequestID,
			"response_mode":     requestContext.ResponseMode,
			"response_uri":      s.targetResponseURI,
			"wallet_subject":    wallet.Subject,
			"wallet_scope":      wallet.ScopeKey,
			"credential_source": credentialSource,
			"disclosure_claims": disclosureClaims,
			"upstream_status":   upstreamStatus,
			"upstream_body":     upstreamBody,
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
	providedCredentialJWT string,
	lookingGlassSessionID string,
) (string, error) {
	if wallet == nil {
		return "", fmt.Errorf("wallet context is required")
	}

	credentialSource := ""
	if strings.TrimSpace(providedCredentialJWT) != "" {
		if err := s.bindCredential(wallet, providedCredentialJWT); err != nil {
			return "", fmt.Errorf("bind provided credential_jwt: %w", err)
		}
		credentialSource = "provided"
	}

	needsCredentialBootstrap := strings.TrimSpace(wallet.CredentialJWT) == ""
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
		autoIssuedCredentialJWT, err := s.issueCredentialForWallet(ctx, wallet, lookingGlassSessionID)
		if err != nil {
			return "", fmt.Errorf("issue credential via oid4vci: %w", err)
		}
		if err := s.bindCredential(wallet, autoIssuedCredentialJWT); err != nil {
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

func buildPresentedCredential(rawCredential string, requestedClaims []string) (string, []string, error) {
	normalized := strings.TrimSpace(rawCredential)
	if normalized == "" {
		return "", nil, fmt.Errorf("wallet credential is required")
	}
	envelope, err := vc.ParseSDJWTEnvelope(normalized)
	if err != nil {
		return "", nil, fmt.Errorf("parse wallet credential as sd-jwt: %w", err)
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

	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.targetResponseURI, strings.NewReader(form.Encode()))
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
	responseURI := strings.TrimSpace(asString(decodedRequest.Payload["response_uri"]))
	if responseURI == "" {
		return nil, fmt.Errorf("request object is missing response_uri")
	}
	expectedResponseURI, err := s.validateAllowedURL(s.targetResponseURI)
	if err != nil {
		return nil, fmt.Errorf("validate target response URI: %w", err)
	}
	if responseURI != expectedResponseURI {
		return nil, fmt.Errorf("request object response_uri %q does not match trusted verifier callback", responseURI)
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
		ResponseURI:  expectedResponseURI,
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

	vct := "https://protocolsoup.com/credentials/university_degree"
	credentialForVCT := presentedCredential
	if credentialEnvelope, err := vc.ParseSDJWTEnvelope(credentialForVCT); err == nil {
		credentialForVCT = strings.TrimSpace(credentialEnvelope.IssuerSignedJWT)
	}
	if credentialForVCT == "" {
		credentialForVCT = strings.TrimSpace(wallet.CredentialJWT)
	}
	if decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(credentialForVCT); err == nil {
		if tokenVCT, ok := decodedCredential.Payload["vct"].(string); ok && strings.TrimSpace(tokenVCT) != "" {
			vct = strings.TrimSpace(tokenVCT)
		}
	}

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
			"credential_jwt": presentedCredential,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	return token.SignedString(wallet.KeySet.RSAPrivateKey())
}

func (s *walletHarnessServer) issueCredentialForWallet(ctx context.Context, wallet *walletMaterial, lookingGlassSessionID string) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}

	offerPayload, err := func() (map[string]interface{}, error) {
		offerURL := s.targetBaseURL + "/oid4vci/offers/pre-authorized"
		offerBody := map[string]interface{}{
			"wallet_user_id": walletUserIDFromSubject(wallet.Subject),
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
		if lookingGlassSessionID != "" {
			req.Header.Set("X-Looking-Glass-Session", lookingGlassSessionID)
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
		return "", err
	}

	preAuthorizedCode := asString(offerPayload["pre_authorized_code"])
	if preAuthorizedCode == "" {
		return "", fmt.Errorf("offer response missing pre_authorized_code")
	}
	offerWalletSubject := asString(offerPayload["wallet_subject"])
	if offerWalletSubject == "" {
		return "", fmt.Errorf("offer response missing wallet_subject")
	}
	if strings.TrimSpace(wallet.Subject) != "" && offerWalletSubject != strings.TrimSpace(wallet.Subject) {
		return "", fmt.Errorf("offer wallet_subject %q does not match wallet subject %q", offerWalletSubject, wallet.Subject)
	}

	tokenPayload, err := func() (map[string]interface{}, error) {
		tokenURL := s.targetBaseURL + "/oid4vci/token"
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
		form.Set("pre-authorized_code", preAuthorizedCode)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, fmt.Errorf("build token request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if lookingGlassSessionID != "" {
			req.Header.Set("X-Looking-Glass-Session", lookingGlassSessionID)
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
		return "", err
	}

	accessToken := asString(tokenPayload["access_token"])
	cNonce := asString(tokenPayload["c_nonce"])
	if accessToken == "" || cNonce == "" {
		return "", fmt.Errorf("token response missing access_token or c_nonce")
	}

	proofJWT, err := s.createCredentialProofJWT(wallet, offerWalletSubject, cNonce)
	if err != nil {
		return "", err
	}

	credentialURL := s.targetBaseURL + "/oid4vci/credential"
	credentialRequestBody := map[string]interface{}{
		"credential_configuration_id": "UniversityDegreeCredential",
		"proofs": []map[string]interface{}{
			{
				"proof_type": "jwt",
				"jwt":        proofJWT,
			},
		},
	}
	rawCredentialBody, err := json.Marshal(credentialRequestBody)
	if err != nil {
		return "", fmt.Errorf("marshal credential request: %w", err)
	}
	credentialReq, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialURL, strings.NewReader(string(rawCredentialBody)))
	if err != nil {
		return "", fmt.Errorf("build credential request: %w", err)
	}
	credentialReq.Header.Set("Accept", "application/json")
	credentialReq.Header.Set("Content-Type", "application/json")
	credentialReq.Header.Set("Authorization", "Bearer "+accessToken)
	if lookingGlassSessionID != "" {
		credentialReq.Header.Set("X-Looking-Glass-Session", lookingGlassSessionID)
	}
	credentialResp, err := s.httpClient.Do(credentialReq)
	if err != nil {
		return "", fmt.Errorf("credential request failed: %w", err)
	}
	defer credentialResp.Body.Close()
	credentialBody, _ := io.ReadAll(credentialResp.Body)
	if credentialResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credential request returned %d: %s", credentialResp.StatusCode, oneLine(string(credentialBody)))
	}
	var credentialPayload map[string]interface{}
	if err := json.Unmarshal(credentialBody, &credentialPayload); err != nil {
		return "", fmt.Errorf("decode credential response: %w", err)
	}
	credentialJWT := asString(credentialPayload["credential"])
	if credentialJWT == "" {
		return "", fmt.Errorf("credential response missing credential")
	}
	return credentialJWT, nil
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
		"aud":   s.targetBaseURL + "/oid4vci",
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
		ScopeKey:   normalizedScope,
		Subject:    normalizedSubject,
		KeySet:     keySet,
		CreatedAt:  now,
		LastAccess: now,
	}
	s.wallets[walletID] = wallet
	return wallet, nil
}

func (s *walletHarnessServer) bindCredential(wallet *walletMaterial, credentialJWT string) error {
	decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(credentialJWT)
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
	wallet.CredentialJWT = strings.TrimSpace(credentialJWT)
	return nil
}

func credentialRefreshRequired(credentialJWT string, minRemaining time.Duration) (bool, error) {
	envelope, err := vc.ParseSDJWTEnvelope(strings.TrimSpace(credentialJWT))
	if err != nil {
		return true, fmt.Errorf("parse credential_jwt: %w", err)
	}
	decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(strings.TrimSpace(envelope.IssuerSignedJWT))
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
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
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
