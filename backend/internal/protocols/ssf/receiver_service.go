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

	// JTI replay detection per RFC 8935 §2 step 4 / RFC 8417 §2.2
	seenJTIs   map[string]time.Time
	seenJTIsMu sync.RWMutex
	
	// Event and action logs
	receivedEvents   []ReceivedEvent
	responseActions  []ResponseAction
	eventsMu         sync.RWMutex
	actionsMu        sync.RWMutex
	
	// Callback to execute real actions
	actionExecutor ActionExecutor
	
	// Event broadcast channels
	eventListeners []chan<- ReceiverEvent
	listenerMu     sync.RWMutex
	
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

// GetKey retrieves a public key by key ID, fetching from JWKS if needed.
// Returns the key, an optional CapturedHTTPExchange (non-nil when a fresh JWKS fetch occurred),
// and any error.
func (c *JWKSCache) GetKey(keyID string) (*rsa.PublicKey, *CapturedHTTPExchange, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		if key, ok := c.keys[keyID]; ok {
			c.mu.RUnlock()
			return key, nil, nil // Cache hit, no HTTP exchange
		}
	}
	c.mu.RUnlock()
	
	// Fetch fresh JWKS (returns captured HTTP exchange)
	exchange, err := c.refresh()
	if err != nil {
		return nil, exchange, err
	}
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	key, ok := c.keys[keyID]
	if !ok {
		return nil, exchange, fmt.Errorf("key %s not found in JWKS", keyID)
	}
	return key, exchange, nil
}

// refresh fetches the JWKS from the transmitter and returns a CapturedHTTPExchange
// with the full request/response details for visibility in the sandbox.
func (c *JWKSCache) refresh() (*CapturedHTTPExchange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	log.Printf("[SSF Receiver] Fetching JWKS from %s", c.jwksURL)
	
	startTime := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.jwksURL)
	duration := time.Since(startTime)

	// Build captured exchange even on error (partial capture)
	exchange := &CapturedHTTPExchange{
		Label:      "JWKS Fetch",
		Timestamp:  startTime,
		DurationMs: duration.Milliseconds(),
		Request: HTTPCapture{
			Method:  "GET",
			URL:     c.jwksURL,
			Headers: map[string]string{"Accept": "application/json"},
		},
		Response: HTTPCapture{
			Headers: make(map[string]string),
		},
	}

	if err != nil {
		exchange.Response.Body = fmt.Sprintf("error: %v", err)
		return exchange, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	exchange.Response.StatusCode = resp.StatusCode
	for k := range resp.Header {
		exchange.Response.Headers[k] = resp.Header.Get(k)
	}
	
	if resp.StatusCode != http.StatusOK {
		exchange.Response.Body = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return exchange, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	// Read the full body for capture
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return exchange, fmt.Errorf("failed to read JWKS body: %w", err)
	}
	exchange.Response.Body = string(bodyBytes)
	
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(bodyBytes, &jwks); err != nil {
		return exchange, fmt.Errorf("failed to decode JWKS: %w", err)
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
	return exchange, nil
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
		port:            port,
		transmitterURL:  transmitterURL,
		bearerToken:     bearerToken,
		jwksCache:       NewJWKSCache(jwksURL, 5*time.Minute),
		seenJTIs:        make(map[string]time.Time),
		receivedEvents:  make([]ReceivedEvent, 0),
		responseActions: make([]ResponseAction, 0),
		actionExecutor:  executor,
	}
}

// AddEventListener adds a listener for receiver pipeline events
func (rs *ReceiverService) AddEventListener(ch chan<- ReceiverEvent) {
	rs.listenerMu.Lock()
	defer rs.listenerMu.Unlock()
	rs.eventListeners = append(rs.eventListeners, ch)
}

// RemoveEventListener removes an event listener
func (rs *ReceiverService) RemoveEventListener(ch chan<- ReceiverEvent) {
	rs.listenerMu.Lock()
	defer rs.listenerMu.Unlock()
	for i, listener := range rs.eventListeners {
		if listener == ch {
			rs.eventListeners = append(rs.eventListeners[:i], rs.eventListeners[i+1:]...)
			return
		}
	}
}

// broadcast sends an event to all listeners
func (rs *ReceiverService) broadcast(event ReceiverEvent) {
	rs.listenerMu.RLock()
	defer rs.listenerMu.RUnlock()
	for _, listener := range rs.eventListeners {
		select {
		case listener <- event:
		default:
			log.Printf("[SSF] WARNING: receiver event channel full, dropping %s event for session %s", event.Type, event.SessionID)
		}
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
			writeReceiverSSFError(w, http.StatusUnauthorized, "authentication_failed", "Invalid bearer token")
			return
		}
	}
	
	// Read raw SET token from request body (RFC 8935 §2)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to read request body: %v", err)
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body")
		return
	}
	
	setToken := string(body)
	if setToken == "" {
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request", "Empty SET token")
		return
	}
	
	// Extract session ID from delivery header (not from the SET itself)
	sessionID := r.Header.Get("X-SSF-Session")

	log.Printf("[SSF Receiver] Received push delivery: %d bytes (session: %s)", len(body), sessionID)
	
	status := rs.processSET(r.Context(), setToken, sessionID)
	
	if status.Status == "failed" {
		writeReceiverSSFError(w, http.StatusBadRequest, "invalid_request", status.Description)
		return
	}
	
	// RFC 8935 §2.2: 202 Accepted on success
	w.WriteHeader(http.StatusAccepted)
}

// ProcessPollResponse handles events retrieved via poll delivery (RFC 8936).
// sessionIDs maps JTI -> session ID (from the stored event metadata, not from the SET).
func (rs *ReceiverService) ProcessPollResponse(ctx context.Context, sets map[string]string, sessionIDs map[string]string) []SetStatus {
	var statuses []SetStatus
	for _, setToken := range sets {
		// For poll, we pass the token directly; session ID comes from stored metadata
		jti := ""
		for k, v := range sets {
			if v == setToken {
				jti = k
				break
			}
		}
		sessionID := sessionIDs[jti]
		status := rs.processSET(ctx, setToken, sessionID)
		statuses = append(statuses, status)
	}
	return statuses
}

// processSET processes a single raw SET token.
// The JTI is extracted from the decoded token per RFC 8935 (push delivers a single raw SET).
// sessionID is passed via the X-SSF-Session delivery header, not from the SET itself.
func (rs *ReceiverService) processSET(ctx context.Context, setToken, sessionID string) SetStatus {
	receivedAt := time.Now()

	// Broadcast: Event Received
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventReceived,
		Timestamp: receivedAt,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"delivery_method": "push",
			"token_length":    len(setToken),
		},
	})
	
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
	
	// Fetch the public key from JWKS (may trigger a real HTTP fetch to the transmitter)
	publicKey, jwksExchange, err := rs.jwksCache.GetKey(keyID)
	if err != nil {
		log.Printf("[SSF Receiver] Failed to get public key: %v", err)
		return SetStatus{Status: "failed", Description: fmt.Sprintf("Key fetch failed: %v", err)}
	}

	// Broadcast JWKS fetch as an HTTP exchange if a real fetch occurred
	if jwksExchange != nil {
		jwksExchange.SessionID = sessionID
		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventHTTPExchange,
			Timestamp: jwksExchange.Timestamp,
			SessionID: sessionID,
			Data:      jwksExchange,
		})
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

		// Broadcast: Verify Failed
		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventVerifyFailed,
			Timestamp: time.Now(),
			SessionID: sessionID,
			Data: map[string]interface{}{
				"error": err.Error(),
			},
		})

		return SetStatus{Status: "failed", Description: fmt.Sprintf("Signature verification failed: %v", err)}
	}
	
	log.Printf("[SSF Receiver] SET signature verified successfully")
	
	// Build structured DecodedSET directly from the verified token's claims
	// instead of re-parsing via DecodeWithoutValidation (which would be a redundant third parse).
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return SetStatus{Status: "failed", Description: "Invalid claims format"}
	}

	decoded := buildDecodedSETFromClaims(claims, parsedToken.Header, setToken)

	// Extract JTI from the decoded token
	jti := decoded.JTI
	log.Printf("[SSF Receiver] Processing SET: %s", jti)

	// Broadcast: Event Verified
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventVerified,
		Timestamp: time.Now(),
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"issuer":    decoded.Issuer,
			"subject":   decoded.Subject,
			"events":    len(decoded.Events),
			"algorithm": "RS256",
			"key_id":    keyID,
		},
	})

	// RFC 8935 §2 step 4 / RFC 8417 §2.2: Reject replayed SETs by tracking seen JTIs
	if jti != "" {
		rs.seenJTIsMu.RLock()
		_, seen := rs.seenJTIs[jti]
		rs.seenJTIsMu.RUnlock()
		if seen {
			log.Printf("[SSF Receiver] Duplicate SET rejected (jti %s already processed)", jti)
			return SetStatus{Status: "failed", Description: fmt.Sprintf("duplicate SET rejected (jti %s already processed)", jti)}
		}
	}

	// Broadcast: Processing
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessing,
		Timestamp: time.Now(),
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"event_count": len(decoded.Events),
		},
	})
	
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
	
	// Extract subject email from the decoded SET
	var subjectEmail string
	if decoded.Subject != nil {
		subjectEmail = decoded.Subject.Email
	}

	// Session ID comes from X-SSF-Session delivery header (not the SET)
	if sessionID != "" {
		log.Printf("[SSF Receiver] Session ID from delivery header: %s", sessionID)
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
	
	// Record JTI as seen for replay detection
	if jti != "" {
		rs.seenJTIsMu.Lock()
		rs.seenJTIs[jti] = time.Now()
		rs.seenJTIsMu.Unlock()
	}

	// Broadcast: Event Processed
	finalAt := time.Now()
	rs.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessed,
		Timestamp: finalAt,
		EventID:   jti,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"processing_time_ms": finalAt.Sub(receivedAt).Milliseconds(),
		},
	})

	log.Printf("[SSF Receiver] SET processed successfully: %s", jti)
	return SetStatus{Status: "success", Description: "Event processed and actions executed"}
}

// executeResponseActions delegates to the shared EventProcessor
func (rs *ReceiverService) executeResponseActions(_ context.Context, eventID string, event DecodedEvent, subjectEmail, sessionID string) {
	actions := ExecuteResponseActions(rs.actionExecutor, eventID, event, subjectEmail, sessionID)
	for _, action := range actions {
		rs.addResponseAction(action)
		log.Printf("[SSF Receiver] Action recorded: %s - %s (session: %s)", action.Action, action.Status, sessionID)

		// Broadcast: Response Action
		rs.broadcast(ReceiverEvent{
			Type:      ReceiverEventResponseAction,
			Timestamp: action.ExecutedAt,
			EventID:   eventID,
			SessionID: sessionID,
			Data: map[string]interface{}{
				"action":     action.Action,
				"event_type": event.Metadata.Name,
				"category":   event.Metadata.Category,
				"zero_trust": event.Metadata.ZeroTrustImpact,
			},
		})
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
	rs.ClearLogs()
	w.WriteHeader(http.StatusNoContent)
}

// ClearLogs clears received events, response actions, and JTI replay cache
func (rs *ReceiverService) ClearLogs() {
	rs.eventsMu.Lock()
	rs.receivedEvents = make([]ReceivedEvent, 0)
	rs.eventsMu.Unlock()

	rs.actionsMu.Lock()
	rs.responseActions = make([]ResponseAction, 0)
	rs.actionsMu.Unlock()

	rs.seenJTIsMu.Lock()
	rs.seenJTIs = make(map[string]time.Time)
	rs.seenJTIsMu.Unlock()
}

// writeReceiverSSFError writes an error response per RFC 8935 §2.3.
func writeReceiverSSFError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"err":         errCode,
		"description": description,
	})
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

// buildDecodedSETFromClaims constructs a DecodedSET from already-verified jwt.MapClaims,
// avoiding a redundant re-parse of the raw token string.
func buildDecodedSETFromClaims(claims jwt.MapClaims, header map[string]interface{}, rawToken string) *DecodedSET {
	decoded := &DecodedSET{
		RawToken: rawToken,
		Header:   header,
		Events:   []DecodedEvent{},
	}

	if jti, ok := claims["jti"].(string); ok {
		decoded.JTI = jti
	}
	if iss, ok := claims["iss"].(string); ok {
		decoded.Issuer = iss
	}
	if aud, ok := claims["aud"].([]interface{}); ok {
		for _, a := range aud {
			if s, ok := a.(string); ok {
				decoded.Audience = append(decoded.Audience, s)
			}
		}
	} else if aud, ok := claims["aud"].(string); ok {
		decoded.Audience = []string{aud}
	}
	if iat, ok := claims["iat"].(float64); ok {
		decoded.IssuedAt = time.Unix(int64(iat), 0)
	}
	if txn, ok := claims["txn"].(string); ok {
		decoded.TransactionID = txn
	}

	// Parse sub_id
	if subID, ok := claims["sub_id"].(map[string]interface{}); ok {
		subject := &SETSubject{}
		if f, ok := subID["format"].(string); ok {
			subject.Format = f
		}
		if e, ok := subID["email"].(string); ok {
			subject.Email = e
		}
		if p, ok := subID["phone_number"].(string); ok {
			subject.PhoneNumber = p
		}
		if i, ok := subID["iss"].(string); ok {
			subject.Issuer = i
		}
		if s, ok := subID["sub"].(string); ok {
			subject.Subject = s
		}
		if id, ok := subID["id"].(string); ok {
			subject.ID = id
		}
		if u, ok := subID["uri"].(string); ok {
			subject.URI = u
		}
		decoded.Subject = subject
	}

	// Parse events
	if events, ok := claims["events"].(map[string]interface{}); ok {
		for eventType, payload := range events {
			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			var eventPayload EventPayload
			if err := json.Unmarshal(payloadBytes, &eventPayload); err != nil {
				continue
			}
			metadata := GetEventMetadata(eventType)
			decoded.Events = append(decoded.Events, DecodedEvent{
				Type:       eventType,
				Metadata:   metadata,
				Payload:    eventPayload,
				RawPayload: payload,
			})
		}
	}

	return decoded
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

