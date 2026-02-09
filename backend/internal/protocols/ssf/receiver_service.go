package ssf

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
)

// ReceiverService is a standalone SSF receiver that runs on a separate port
type ReceiverService struct {
	port           int
	transmitterURL string
	bearerToken    string
	
	// JWKS cache
	jwksCache     *JWKSCache
	
	// Event and action logs
	receivedEvents   []ReceivedEvent
	responseActions  []ResponseAction
	eventsMu         sync.RWMutex
	actionsMu        sync.RWMutex
	
	// Callback to execute real actions
	actionExecutor ActionExecutor
	
	// HTTP server
	server *http.Server
}

// ActionExecutor interface for executing real response actions
type ActionExecutor interface {
	RevokeUserSessions(ctx context.Context, email string) error
	DisableUser(ctx context.Context, email string) error
	EnableUser(ctx context.Context, email string) error
	ForcePasswordReset(ctx context.Context, email string) error
	InvalidateTokens(ctx context.Context, email string) error
	// Session-aware methods for isolated sandbox
	RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error
	DisableUserForSession(ctx context.Context, sessionID, email string) error
	EnableUserForSession(ctx context.Context, sessionID, email string) error
	ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error
	InvalidateTokensForSession(ctx context.Context, sessionID, email string) error
	InitSessionUserStates(sessionID string)
}

// JWKSCache caches public keys fetched from the transmitter
type JWKSCache struct {
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
	ttl        time.Duration
	jwksURL    string
	mu         sync.RWMutex
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(jwksURL string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:    make(map[string]*rsa.PublicKey),
		ttl:     ttl,
		jwksURL: jwksURL,
	}
}

// GetKey retrieves a public key by key ID, fetching from JWKS if needed
func (c *JWKSCache) GetKey(keyID string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		if key, ok := c.keys[keyID]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()
	
	// Fetch fresh JWKS
	if err := c.refresh(); err != nil {
		return nil, err
	}
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	key, ok := c.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", keyID)
	}
	return key, nil
}

// refresh fetches the JWKS from the transmitter
func (c *JWKSCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	log.Printf("[SSF Receiver] Fetching JWKS from %s", c.jwksURL)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}
	
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}
	
	// Parse each key
	newKeys := make(map[string]*rsa.PublicKey)
	for _, keyData := range jwks.Keys {
		var keyInfo struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(keyData, &keyInfo); err != nil {
			continue
		}
		
		if keyInfo.Kty != "RSA" {
			continue
		}
		
		// Parse RSA public key from JWK
		key, err := parseRSAPublicKeyFromJWK(keyInfo.N, keyInfo.E)
		if err != nil {
			log.Printf("[SSF Receiver] Failed to parse key %s: %v", keyInfo.Kid, err)
			continue
		}
		
		newKeys[keyInfo.Kid] = key
		log.Printf("[SSF Receiver] Cached key: %s", keyInfo.Kid)
	}
	
	c.keys = newKeys
	c.fetchedAt = time.Now()
	
	log.Printf("[SSF Receiver] JWKS cache refreshed with %d keys", len(newKeys))
	return nil
}

// parseRSAPublicKeyFromJWK parses an RSA public key from JWK components
func parseRSAPublicKeyFromJWK(nBase64, eBase64 string) (*rsa.PublicKey, error) {
	// Decode N (modulus) - base64url encoded
	nBytes, err := base64.RawURLEncoding.DecodeString(nBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}
	
	// Decode E (exponent) - base64url encoded
	eBytes, err := base64.RawURLEncoding.DecodeString(eBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}
	
	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	
	// Create public key
	n := new(big.Int).SetBytes(nBytes)
	
	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// NewReceiverService creates a new standalone SSF receiver
func NewReceiverService(port int, transmitterURL, bearerToken string, executor ActionExecutor) *ReceiverService {
	jwksURL := transmitterURL + "/ssf/jwks"
	
	return &ReceiverService{
		port:           port,
		transmitterURL: transmitterURL,
		bearerToken:    bearerToken,
		jwksCache:      NewJWKSCache(jwksURL, 5*time.Minute),
		receivedEvents: make([]ReceivedEvent, 0),
		responseActions: make([]ResponseAction, 0),
		actionExecutor: executor,
	}
}

// Start starts the receiver service on its own port
func (rs *ReceiverService) Start() error {
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	
	// SSF Receiver endpoints
	router.Post("/ssf/push", rs.handlePush)
	router.Get("/ssf/status", rs.handleStatus)
	router.Get("/ssf/events", rs.handleGetEvents)
	router.Get("/ssf/actions", rs.handleGetActions)
	router.Delete("/ssf/logs", rs.handleClearLogs)
	
	rs.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", rs.port),
		Handler: router,
	}
	
	log.Printf("[SSF Receiver] Starting on port %d", rs.port)
	log.Printf("[SSF Receiver] Transmitter URL: %s", rs.transmitterURL)
	log.Printf("[SSF Receiver] Push endpoint: http://localhost:%d/ssf/push", rs.port)
	
	return rs.server.ListenAndServe()
}

// Stop gracefully stops the receiver service
func (rs *ReceiverService) Stop(ctx context.Context) error {
	if rs.server != nil {
		return rs.server.Shutdown(ctx)
	}
	return nil
}

// handlePush handles incoming push delivery requests per RFC 8935 §2.
// The request body is the raw compact-serialized SET.
func (rs *ReceiverService) handlePush(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request
	authHeader := r.Header.Get("Authorization")
	if rs.bearerToken != "" {
		expectedAuth := "Bearer " + rs.bearerToken
		if authHeader != expectedAuth {
			log.Printf("[SSF Receiver] Authentication failed: invalid bearer token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	
	// Read raw SET token from request body (RFC 8935 §2)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to read request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	
	setToken := string(body)
	if setToken == "" {
		http.Error(w, "Empty SET token", http.StatusBadRequest)
		return
	}
	
	log.Printf("[SSF Receiver] Received push delivery: %d bytes", len(body))
	
	status := rs.processSET(r.Context(), setToken)
	
	if status.Status == "failed" {
		http.Error(w, status.Description, http.StatusBadRequest)
		return
	}
	
	// RFC 8935 §2.2: 202 Accepted on success
	w.WriteHeader(http.StatusAccepted)
}

// processSET processes a single raw SET token.
// The JTI is extracted from the decoded token per RFC 8935 (push delivers a single raw SET).
func (rs *ReceiverService) processSET(ctx context.Context, setToken string) SetStatus {
	receivedAt := time.Now()
	
	// Decode the SET header to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(setToken, jwt.MapClaims{})
	if err != nil {
		log.Printf("[SSF Receiver] Failed to parse SET header: %v", err)
		return SetStatus{Status: "failed", Description: "Invalid SET format"}
	}
	
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		log.Printf("[SSF Receiver] SET missing kid header")
		return SetStatus{Status: "failed", Description: "Missing key ID"}
	}
	
	// Fetch the public key from JWKS
	publicKey, err := rs.jwksCache.GetKey(keyID)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to get public key: %v", err)
		return SetStatus{Status: "failed", Description: fmt.Sprintf("Key fetch failed: %v", err)}
	}
	
	// Verify the SET signature
	parsedToken, err := jwt.Parse(setToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	
	if err != nil {
		log.Printf("[SSF Receiver] SET signature verification failed: %v", err)
		rs.addReceivedEvent(ReceivedEvent{
			ID:             "",
			ReceivedAt:     receivedAt,
			DeliveryMethod: "push",
			Verified:       false,
			VerifyError:    err.Error(),
		})
		return SetStatus{Status: "failed", Description: fmt.Sprintf("Signature verification failed: %v", err)}
	}
	
	log.Printf("[SSF Receiver] SET signature verified successfully")
	
	// Extract claims and process
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return SetStatus{Status: "failed", Description: "Invalid claims format"}
	}
	
	// Decode the SET for processing
	decoded, err := DecodeWithoutValidation(setToken)
	if err != nil {
		return SetStatus{Status: "failed", Description: "Failed to decode SET"}
	}
	
	// Extract JTI from the decoded token
	jti := decoded.JTI
	log.Printf("[SSF Receiver] Processing SET: %s", jti)
	
	// Record the received event
	processedAt := time.Now()
	rs.addReceivedEvent(ReceivedEvent{
		ID:             jti,
		ReceivedAt:     receivedAt,
		DeliveryMethod: "push",
		SET:            decoded,
		Verified:       true,
		Processed:      true,
		ProcessedAt:    &processedAt,
	})
	
	// Extract subject email
	var subjectEmail string
	if subID, ok := claims["sub_id"].(map[string]interface{}); ok {
		if email, ok := subID["email"].(string); ok {
			subjectEmail = email
		}
	}

	// Extract session ID from the SET (custom claim for sandbox isolation)
	sessionID := ""
	if sid, ok := claims["ssf_session_id"].(string); ok {
		sessionID = sid
		log.Printf("[SSF Receiver] Session ID extracted: %s", sessionID)
	}

	// Initialize session states if this is a session-scoped event
	if sessionID != "" && rs.actionExecutor != nil {
		rs.actionExecutor.InitSessionUserStates(sessionID)
	}

	// Process events and execute response actions
	for _, event := range decoded.Events {
		log.Printf("[SSF Receiver] Processing event: %s for subject: %s (session: %s)", event.Type, subjectEmail, sessionID)
		rs.executeResponseActions(ctx, jti, event, subjectEmail, sessionID)
	}
	
	log.Printf("[SSF Receiver] SET processed successfully: %s", jti)
	return SetStatus{Status: "success", Description: "Event processed and actions executed"}
}

// executeResponseActions delegates to the shared EventProcessor
func (rs *ReceiverService) executeResponseActions(_ context.Context, eventID string, event DecodedEvent, subjectEmail, sessionID string) {
	actions := ExecuteResponseActions(rs.actionExecutor, eventID, event, subjectEmail, sessionID)
	for _, action := range actions {
		rs.addResponseAction(action)
		log.Printf("[SSF Receiver] Action recorded: %s - %s (session: %s)", action.Action, action.Status, sessionID)
	}
}

// addReceivedEvent adds an event to the received log
func (rs *ReceiverService) addReceivedEvent(event ReceivedEvent) {
	rs.eventsMu.Lock()
	defer rs.eventsMu.Unlock()
	
	if len(rs.receivedEvents) >= 100 {
		rs.receivedEvents = rs.receivedEvents[1:]
	}
	rs.receivedEvents = append(rs.receivedEvents, event)
}

// addResponseAction adds a response action to the log
func (rs *ReceiverService) addResponseAction(action ResponseAction) {
	rs.actionsMu.Lock()
	defer rs.actionsMu.Unlock()
	
	if len(rs.responseActions) >= 200 {
		rs.responseActions = rs.responseActions[1:]
	}
	rs.responseActions = append(rs.responseActions, action)
}

// HTTP Handlers

func (rs *ReceiverService) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":          "running",
		"port":            rs.port,
		"transmitter_url": rs.transmitterURL,
		"events_received": len(rs.receivedEvents),
		"actions_taken":   len(rs.responseActions),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (rs *ReceiverService) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	rs.eventsMu.RLock()
	defer rs.eventsMu.RUnlock()
	
	// Return in reverse order (newest first)
	events := make([]ReceivedEvent, len(rs.receivedEvents))
	for i, e := range rs.receivedEvents {
		events[len(rs.receivedEvents)-1-i] = e
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

func (rs *ReceiverService) handleGetActions(w http.ResponseWriter, r *http.Request) {
	rs.actionsMu.RLock()
	defer rs.actionsMu.RUnlock()
	
	// Return in reverse order (newest first)
	actions := make([]ResponseAction, len(rs.responseActions))
	for i, a := range rs.responseActions {
		actions[len(rs.responseActions)-1-i] = a
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"actions": actions,
		"total":   len(actions),
	})
}

func (rs *ReceiverService) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	rs.eventsMu.Lock()
	rs.receivedEvents = make([]ReceivedEvent, 0)
	rs.eventsMu.Unlock()
	
	rs.actionsMu.Lock()
	rs.responseActions = make([]ResponseAction, 0)
	rs.actionsMu.Unlock()
	
	w.WriteHeader(http.StatusNoContent)
}

// GetReceivedEvents returns the received events (for backward compat)
func (rs *ReceiverService) GetReceivedEvents() []ReceivedEvent {
	rs.eventsMu.RLock()
	defer rs.eventsMu.RUnlock()
	
	result := make([]ReceivedEvent, len(rs.receivedEvents))
	for i, e := range rs.receivedEvents {
		result[len(rs.receivedEvents)-1-i] = e
	}
	return result
}

// GetResponseActions returns the response actions (for backward compat)
func (rs *ReceiverService) GetResponseActions() []ResponseAction {
	rs.actionsMu.RLock()
	defer rs.actionsMu.RUnlock()
	
	result := make([]ResponseAction, len(rs.responseActions))
	for i, a := range rs.responseActions {
		result[len(rs.responseActions)-1-i] = a
	}
	return result
}

