package ssf

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Receiver handles incoming SSF events
type Receiver struct {
	decoder   *SETDecoder
	publicKey *rsa.PublicKey
	issuer    string
	audience  string

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
func NewReceiver(publicKey *rsa.PublicKey, issuer, audience string) *Receiver {
	return &Receiver{
		decoder:         NewSETDecoder(publicKey, issuer, audience),
		publicKey:       publicKey,
		issuer:          issuer,
		audience:        audience,
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

// ProcessPushDelivery handles events delivered via push (webhook)
func (r *Receiver) ProcessPushDelivery(ctx context.Context, body []byte) (*PushResponse, error) {
	// Parse the push request
	var pushReq PushRequest
	if err := json.Unmarshal(body, &pushReq); err != nil {
		return nil, fmt.Errorf("invalid push request format: %w", err)
	}

	response := &PushResponse{
		Sets: make(map[string]SetStatus),
	}

	// Process each SET
	for jti, setToken := range pushReq.Sets {
		status := r.processSET(ctx, jti, setToken, "push")
		response.Sets[jti] = status
	}

	return response, nil
}

// ProcessPollResponse handles events retrieved via poll
func (r *Receiver) ProcessPollResponse(ctx context.Context, sets map[string]string) []SetStatus {
	var statuses []SetStatus

	for jti, setToken := range sets {
		status := r.processSET(ctx, jti, setToken, "poll")
		statuses = append(statuses, status)
	}

	return statuses
}

// processSET processes a single SET token
func (r *Receiver) processSET(ctx context.Context, jti, setToken, deliveryMethod string) SetStatus {
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

	// Execute response actions for each event
	for _, event := range decoded.Events {
		r.executeResponseActions(ctx, jti, event)
	}

	processedAt := time.Now()
	received.Processed = true
	received.ProcessedAt = &processedAt

	r.addReceivedEvent(received)

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

// executeResponseActions simulates the automated response actions
func (r *Receiver) executeResponseActions(_ context.Context, eventID string, event DecodedEvent) {
	metadata := event.Metadata

	for i, actionDesc := range metadata.ResponseActions {
		action := ResponseAction{
			ID:          fmt.Sprintf("%s-action-%d", eventID, i),
			EventID:     eventID,
			EventType:   event.Type,
			Action:      actionDesc,
			Description: fmt.Sprintf("Automated response: %s", actionDesc),
			Status:      ResponseStatusExecuted,
			ExecutedAt:  time.Now(),
		}

		r.addResponseAction(action)

		// Broadcast: Response Action
		r.broadcast(ReceiverEvent{
			Type:      ReceiverEventResponseAction,
			Timestamp: action.ExecutedAt,
			EventID:   eventID,
			Data: map[string]interface{}{
				"action":     action.Action,
				"event_type": metadata.Name,
				"category":   metadata.Category,
				"zero_trust": metadata.ZeroTrustImpact,
			},
		})

		// Small delay for visualization
		time.Sleep(50 * time.Millisecond)
	}
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

// ClearLogs clears the received events and response actions logs
func (r *Receiver) ClearLogs() {
	r.receivedEventsMu.Lock()
	r.receivedEvents = make([]ReceivedEvent, 0)
	r.receivedEventsMu.Unlock()

	r.responseActionsMu.Lock()
	r.responseActions = make([]ResponseAction, 0)
	r.responseActionsMu.Unlock()
}

// PushRequest represents an SSF push delivery request
type PushRequest struct {
	Sets map[string]string `json:"sets"`
}

// PushResponse represents an SSF push delivery response
type PushResponse struct {
	Sets map[string]SetStatus `json:"sets"`
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
