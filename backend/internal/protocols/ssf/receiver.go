package ssf

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Receiver handles incoming SSF events
type Receiver struct {
	decoder   *SETDecoder
	publicKey *rsa.PublicKey
	issuer    string
	audience  string

	// Action executor for real state changes
	actionExecutor ActionExecutor

	// JTI replay detection per RFC 8935 §2 step 4 / RFC 8417 §2.2
	seenJTIs   map[string]time.Time
	seenJTIsMu sync.RWMutex

	// Received events log (in-memory for demo)
	receivedEvents   []ReceivedEvent
	receivedEventsMu sync.RWMutex

	// Response actions log
	responseActions   []ResponseAction
	responseActionsMu sync.RWMutex

	// Event listeners
	eventListeners []chan<- ReceiverEvent
	listenerMu     sync.RWMutex
}

// ReceivedEvent represents an event received by the receiver
type ReceivedEvent struct {
	ID             string      `json:"id"`
	ReceivedAt     time.Time   `json:"received_at"`
	DeliveryMethod string      `json:"delivery_method"`
	SET            *DecodedSET `json:"set"`
	Verified       bool        `json:"verified"`
	VerifyError    string      `json:"verify_error,omitempty"`
	Processed      bool        `json:"processed"`
	ProcessedAt    *time.Time  `json:"processed_at,omitempty"`
}

// ResponseAction represents an automated response action taken
type ResponseAction struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	ExecutedAt  time.Time `json:"executed_at"`
	SessionID   string    `json:"session_id,omitempty"`
}

// Response action status
const (
	ResponseStatusExecuted = "executed"
	ResponseStatusPending  = "pending"
	ResponseStatusFailed   = "failed"
)

// ReceiverEvent represents events in the receiver pipeline
type ReceiverEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	EventID   string      `json:"event_id"`
	Data      interface{} `json:"data"`
}

// Receiver event types
const (
	ReceiverEventReceived       = "event_received"
	ReceiverEventVerified       = "event_verified"
	ReceiverEventVerifyFailed   = "event_verify_failed"
	ReceiverEventProcessing     = "event_processing"
	ReceiverEventProcessed      = "event_processed"
	ReceiverEventResponseAction = "response_action"
)

// NewReceiver creates a new SSF receiver
func NewReceiver(publicKey *rsa.PublicKey, issuer, audience string, executor ActionExecutor) *Receiver {
	return &Receiver{
		decoder:         NewSETDecoder(publicKey, issuer, audience),
		publicKey:       publicKey,
		issuer:          issuer,
		audience:        audience,
		actionExecutor:  executor,
		seenJTIs:        make(map[string]time.Time),
		receivedEvents:  make([]ReceivedEvent, 0),
		responseActions: make([]ResponseAction, 0),
	}
}

// AddEventListener adds a listener for receiver events
func (r *Receiver) AddEventListener(ch chan<- ReceiverEvent) {
	r.listenerMu.Lock()
	defer r.listenerMu.Unlock()
	r.eventListeners = append(r.eventListeners, ch)
}

// RemoveEventListener removes an event listener
func (r *Receiver) RemoveEventListener(ch chan<- ReceiverEvent) {
	r.listenerMu.Lock()
	defer r.listenerMu.Unlock()
	for i, listener := range r.eventListeners {
		if listener == ch {
			r.eventListeners = append(r.eventListeners[:i], r.eventListeners[i+1:]...)
			return
		}
	}
}

// broadcast sends an event to all listeners
func (r *Receiver) broadcast(event ReceiverEvent) {
	r.listenerMu.RLock()
	defer r.listenerMu.RUnlock()
	for _, listener := range r.eventListeners {
		select {
		case listener <- event:
		default:
			// Drop if channel is full
		}
	}
}

// ProcessPushDelivery handles a single SET delivered via push per RFC 8935 §2.
// The body is the raw compact-serialized SET (not JSON-wrapped).
// sessionID is extracted from the X-SSF-Session delivery header (not from the SET itself).
func (r *Receiver) ProcessPushDelivery(ctx context.Context, setToken, sessionID string) (SetStatus, error) {
	if setToken == "" {
		return SetStatus{Status: "failed", Description: "Empty SET token"}, fmt.Errorf("empty SET token")
	}

	// Use the token itself as a preliminary ID; the real JTI is inside the JWT
	status := r.processSET(ctx, "", setToken, "push", sessionID)
	return status, nil
}

// ProcessPollResponse handles events retrieved via poll.
// sessionIDs maps JTI -> session ID (from the stored event metadata, not from the SET).
func (r *Receiver) ProcessPollResponse(ctx context.Context, sets map[string]string, sessionIDs map[string]string) []SetStatus {
	var statuses []SetStatus

	for jti, setToken := range sets {
		sessionID := sessionIDs[jti]
		status := r.processSET(ctx, jti, setToken, "poll", sessionID)
		statuses = append(statuses, status)
	}

	return statuses
}

// processSET processes a single SET token.
// For push delivery (RFC 8935), jti may be empty and is extracted from the decoded token.
// For poll delivery (RFC 8936), jti is provided from the poll response map key.
// sessionID is passed via delivery context (header or stored event metadata), not from the SET itself.
func (r *Receiver) processSET(ctx context.Context, jti, setToken, deliveryMethod, sessionID string) SetStatus {
	now := time.Now()

	// Broadcast: Event Received
	r.broadcast(ReceiverEvent{
		Type:      ReceiverEventReceived,
		Timestamp: now,
		EventID:   jti,
		Data: map[string]interface{}{
			"delivery_method": deliveryMethod,
			"token_preview":   truncateToken(setToken),
		},
	})

	// Decode and verify the SET
	decoded, err := r.decoder.Decode(setToken)

	// For push delivery the JTI comes from the decoded token itself
	if decoded != nil && decoded.JTI != "" {
		jti = decoded.JTI
	}

	// RFC 8935 §2 step 4 / RFC 8417 §2.2: Reject replayed SETs by tracking seen JTIs
	if jti != "" {
		r.seenJTIsMu.RLock()
		_, seen := r.seenJTIs[jti]
		r.seenJTIsMu.RUnlock()
		if seen {
			return SetStatus{
				Status:      "failed",
				Description: fmt.Sprintf("duplicate SET rejected (jti %s already processed)", jti),
			}
		}
	}

	received := ReceivedEvent{
		ID:             jti,
		ReceivedAt:     now,
		DeliveryMethod: deliveryMethod,
		Verified:       err == nil,
	}

	if err != nil {
		received.VerifyError = err.Error()

		// Try decoding without validation for display
		unverified, _ := DecodeWithoutValidation(setToken)
		if unverified != nil && unverified.JTI != "" {
			jti = unverified.JTI
			received.ID = jti
		}
		received.SET = unverified

		// Broadcast: Verify Failed
		r.broadcast(ReceiverEvent{
			Type:      ReceiverEventVerifyFailed,
			Timestamp: time.Now(),
			EventID:   jti,
			Data: map[string]interface{}{
				"error": err.Error(),
			},
		})

		r.addReceivedEvent(received)

		return SetStatus{
			Status:      "failed",
			Description: fmt.Sprintf("Verification failed: %s", err.Error()),
		}
	}

	received.SET = decoded

	// Broadcast: Event Verified
	r.broadcast(ReceiverEvent{
		Type:      ReceiverEventVerified,
		Timestamp: time.Now(),
		EventID:   jti,
		Data: map[string]interface{}{
			"issuer":  decoded.Issuer,
			"subject": decoded.Subject,
			"events":  len(decoded.Events),
		},
	})

	// Process the events
	r.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessing,
		Timestamp: time.Now(),
		EventID:   jti,
		Data: map[string]interface{}{
			"event_count": len(decoded.Events),
		},
	})

	// Initialize session states if needed (session ID comes from delivery context, not the SET)
	if sessionID != "" && r.actionExecutor != nil {
		r.actionExecutor.InitSessionUserStates(sessionID)
	}

	// Extract subject email (guard against nil Subject for verification events)
	var subjectEmail string
	if decoded.Subject != nil {
		subjectEmail = decoded.Subject.Email
	}

	// Execute response actions for each event
	for _, event := range decoded.Events {
		r.executeResponseActions(ctx, jti, event, subjectEmail, sessionID)
	}

	processedAt := time.Now()
	received.Processed = true
	received.ProcessedAt = &processedAt

	r.addReceivedEvent(received)

	// Record JTI as seen for replay detection
	if jti != "" {
		r.seenJTIsMu.Lock()
		r.seenJTIs[jti] = processedAt
		r.seenJTIsMu.Unlock()
	}

	// Broadcast: Event Processed
	r.broadcast(ReceiverEvent{
		Type:      ReceiverEventProcessed,
		Timestamp: processedAt,
		EventID:   jti,
		Data: map[string]interface{}{
			"processing_time_ms": processedAt.Sub(now).Milliseconds(),
		},
	})

	return SetStatus{
		Status:      "success",
		Description: "Event processed successfully",
	}
}

// executeResponseActions delegates to the shared EventProcessor and records results
func (r *Receiver) executeResponseActions(_ context.Context, eventID string, event DecodedEvent, subjectEmail, sessionID string) {
	actions := ExecuteResponseActions(r.actionExecutor, eventID, event, subjectEmail, sessionID)

	for _, action := range actions {
		r.addResponseAction(action)

		// Broadcast: Response Action
		r.broadcast(ReceiverEvent{
			Type:      ReceiverEventResponseAction,
			Timestamp: action.ExecutedAt,
			EventID:   eventID,
			Data: map[string]interface{}{
				"action":     action.Action,
				"event_type": event.Metadata.Name,
				"category":   event.Metadata.Category,
				"zero_trust": event.Metadata.ZeroTrustImpact,
				"session_id": sessionID,
			},
		})

		// Small delay for visualization
		time.Sleep(50 * time.Millisecond)
	}
}

// ====================
// Shared Event Processing (used by both Receiver and ReceiverService)
// ====================

// ExecuteResponseActions executes security response actions for a decoded event.
// This is the shared implementation used by both the legacy Receiver and the standalone ReceiverService.
func ExecuteResponseActions(executor ActionExecutor, eventID string, event DecodedEvent, subjectEmail, sessionID string) []ResponseAction {
	metadata := event.Metadata
	var actions []ResponseAction

	for i, actionDesc := range metadata.ResponseActions {
		executedAt := time.Now()
		status := ResponseStatusExecuted

		// Execute real actions if we have an executor
		if executor != nil && subjectEmail != "" {
			ctx := context.Background()
			var err error
			lower := strings.ToLower(actionDesc)
			switch {
			case containsAnyOf(lower, "terminate", "revoke", "session"):
				log.Printf("[SSF Receiver] Executing: Revoke sessions for %s (session: %s)", subjectEmail, sessionID)
				err = executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "disable", "suspend"):
				log.Printf("[SSF Receiver] Executing: Disable user %s (session: %s)", subjectEmail, sessionID)
				err = executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "enable", "reactivate"):
				log.Printf("[SSF Receiver] Executing: Enable user %s (session: %s)", subjectEmail, sessionID)
				err = executor.EnableUserForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "password", "reset"):
				log.Printf("[SSF Receiver] Executing: Force password reset for %s (session: %s)", subjectEmail, sessionID)
				err = executor.ForcePasswordResetForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "invalidate", "token"):
				log.Printf("[SSF Receiver] Executing: Invalidate tokens for %s (session: %s)", subjectEmail, sessionID)
				err = executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
			default:
				log.Printf("[SSF Receiver] Executing: %s (generic action)", actionDesc)
			}
			if err != nil {
				log.Printf("[SSF Receiver] Action failed: %v", err)
				status = ResponseStatusFailed
			}
		}

		actions = append(actions, ResponseAction{
			ID:          fmt.Sprintf("%s-action-%d", eventID, i),
			EventID:     eventID,
			EventType:   event.Type,
			Action:      actionDesc,
			Description: fmt.Sprintf("Automated response: %s (session: %s)", actionDesc, sessionID),
			Status:      status,
			ExecutedAt:  executedAt,
			SessionID:   sessionID,
		})
	}

	return actions
}

// containsAnyOf checks if the already-lowered string s contains any of the substrings.
func containsAnyOf(sLower string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(sLower, sub) {
			return true
		}
	}
	return false
}

// addReceivedEvent adds an event to the received log
func (r *Receiver) addReceivedEvent(event ReceivedEvent) {
	r.receivedEventsMu.Lock()
	defer r.receivedEventsMu.Unlock()

	// Keep only last 100 events
	if len(r.receivedEvents) >= 100 {
		r.receivedEvents = r.receivedEvents[1:]
	}
	r.receivedEvents = append(r.receivedEvents, event)
}

// addResponseAction adds a response action to the log
func (r *Receiver) addResponseAction(action ResponseAction) {
	r.responseActionsMu.Lock()
	defer r.responseActionsMu.Unlock()

	// Keep only last 200 actions
	if len(r.responseActions) >= 200 {
		r.responseActions = r.responseActions[1:]
	}
	r.responseActions = append(r.responseActions, action)
}

// GetReceivedEvents returns the received events log
func (r *Receiver) GetReceivedEvents() []ReceivedEvent {
	r.receivedEventsMu.RLock()
	defer r.receivedEventsMu.RUnlock()

	// Return a copy in reverse order (newest first)
	result := make([]ReceivedEvent, len(r.receivedEvents))
	for i, event := range r.receivedEvents {
		result[len(r.receivedEvents)-1-i] = event
	}
	return result
}

// GetResponseActions returns the response actions log
func (r *Receiver) GetResponseActions() []ResponseAction {
	r.responseActionsMu.RLock()
	defer r.responseActionsMu.RUnlock()

	// Return a copy in reverse order (newest first)
	result := make([]ResponseAction, len(r.responseActions))
	for i, action := range r.responseActions {
		result[len(r.responseActions)-1-i] = action
	}
	return result
}

// ClearLogs clears the received events, response actions logs, and JTI replay cache
func (r *Receiver) ClearLogs() {
	r.receivedEventsMu.Lock()
	r.receivedEvents = make([]ReceivedEvent, 0)
	r.receivedEventsMu.Unlock()

	r.responseActionsMu.Lock()
	r.responseActions = make([]ResponseAction, 0)
	r.responseActionsMu.Unlock()

	r.seenJTIsMu.Lock()
	r.seenJTIs = make(map[string]time.Time)
	r.seenJTIsMu.Unlock()
}

// SetStatus represents the processing status of a SET
type SetStatus struct {
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
}

// PollRequest represents an SSF poll request
type PollRequest struct {
	Ack               []string `json:"ack,omitempty"`
	MaxEvents         int      `json:"maxEvents,omitempty"`
	ReturnImmediately bool     `json:"returnImmediately,omitempty"`
}

// PollResponse represents an SSF poll response
type PollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// truncateToken returns a truncated preview of a token
func truncateToken(token string) string {
	if len(token) <= 50 {
		return token
	}
	return token[:25] + "..." + token[len(token)-20:]
}
