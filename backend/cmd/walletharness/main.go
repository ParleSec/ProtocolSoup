package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type walletHarnessServer struct {
	httpClient *http.Client

	targetBaseURL     string
	targetHost        string
	targetResponseURI string

	defaultWalletSubject string
	allowedCORSOrigins   map[string]struct{}

	mu      sync.Mutex
	wallets map[string]*walletMaterial
}

type walletMaterial struct {
	Subject       string
	KeySet        *intcrypto.KeySet
	CredentialJWT string
}

type walletSubmitRequest struct {
	RequestID     string `json:"request_id"`
	Request       string `json:"request,omitempty"`
	WalletSubject string `json:"wallet_subject,omitempty"`
	Subject       string `json:"subject,omitempty"`
	CredentialJWT string `json:"credential_jwt,omitempty"`
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
	if req.RequestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request_id is required",
		})
		return
	}
	if req.Request == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request is required",
		})
		return
	}

	subject := req.WalletSubject
	if subject == "" {
		subject = req.Subject
	}
	if subject == "" {
		subject = s.defaultWalletSubject
	}
	wallet, err := s.getOrCreateWallet(subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	if req.CredentialJWT != "" {
		if err := s.bindCredential(wallet, req.CredentialJWT); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "credential_jwt is required for wallet submission",
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

	vpToken, err := s.createVPToken(wallet, requestContext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("create vp_token: %v", err),
		})
		return
	}

	form := url.Values{}
	form.Set("state", requestContext.State)
	if requestContext.ResponseMode == "direct_post.jwt" {
		responseJWT, err := s.createDirectPostResponseJWT(wallet, requestContext, vpToken)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("create direct_post.jwt response: %v", err),
			})
			return
		}
		encryptedResponse, err := s.encryptForVerifier(responseJWT)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "wallet_submission_failed",
				"error_description": fmt.Sprintf("encrypt direct_post.jwt response: %v", err),
			})
			return
		}
		form.Set("response", encryptedResponse)
	} else {
		form.Set("vp_token", vpToken)
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.targetResponseURI, strings.NewReader(form.Encode()))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("build upstream request: %v", err),
		})
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	upstreamReq.Header.Set("Accept", "application/json")

	upstreamResp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_submission_failed",
			"error_description": fmt.Sprintf("upstream request failed: %v", err),
		})
		return
	}
	defer upstreamResp.Body.Close()
	upstreamBody, _ := io.ReadAll(upstreamResp.Body)
	var decodedBody interface{}
	if len(strings.TrimSpace(string(upstreamBody))) > 0 {
		if err := json.Unmarshal(upstreamBody, &decodedBody); err != nil {
			decodedBody = string(upstreamBody)
		}
	}

	writeJSON(w, upstreamResp.StatusCode, map[string]interface{}{
		"request_id":      requestContext.RequestID,
		"response_mode":   requestContext.ResponseMode,
		"response_uri":    s.targetResponseURI,
		"wallet_subject":  wallet.Subject,
		"upstream_status": upstreamResp.StatusCode,
		"upstream_body":   decodedBody,
	})
}

func (s *walletHarnessServer) resolveRequestContext(requestID string, requestJWT string) (*resolvedRequestContext, error) {
	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		return nil, fmt.Errorf("decode request object jwt: %w", err)
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
		RequestID:    requestID,
		State:        state,
		Nonce:        nonce,
		ClientID:     clientID,
		ResponseMode: responseMode,
		ResponseURI:  expectedResponseURI,
	}, nil
}

func (s *walletHarnessServer) createVPToken(wallet *walletMaterial, requestContext *resolvedRequestContext) (string, error) {
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

	vct := "https://protocolsoup.com/credentials/university_degree"
	if decodedCredential, err := intcrypto.DecodeTokenWithoutValidation(wallet.CredentialJWT); err == nil {
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
			"credential_jwt": wallet.CredentialJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
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

func (s *walletHarnessServer) getOrCreateWallet(subject string) (*walletMaterial, error) {
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return nil, fmt.Errorf("wallet subject is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.wallets[normalizedSubject]; ok {
		return existing, nil
	}
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		return nil, fmt.Errorf("create wallet keyset: %w", err)
	}
	wallet := &walletMaterial{
		Subject: normalizedSubject,
		KeySet:  keySet,
	}
	s.wallets[normalizedSubject] = wallet
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
