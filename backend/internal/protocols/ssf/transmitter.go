package ssf

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/google/uuid"
)

// Transmitter handles event generation and delivery
type Transmitter struct {
	storage    *Storage
	encoder    *SETEncoder
	baseURL    string
	httpClient *http.Client
	glass      *glassBox

	// Event broadcast channels
	eventListeners []chan<- TransmitterEvent
	listenerMu     sync.RWMutex
}

// TransmitterEvent represents an event in the transmission pipeline
type TransmitterEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	EventID   string      `json:"event_id"`
	SubjectID string      `json:"subject_id"`
	EventType string      `json:"event_type"`
	SessionID string      `json:"session_id,omitempty"`
	Data      interface{} `json:"data"`
}

// Event pipeline stages
const (
	TransmitterEventActionTriggered = "action_triggered"
	TransmitterEventSETGenerated    = "set_generated"
	TransmitterEventSETSigned       = "set_signed"
	TransmitterEventDeliveryStarted = "delivery_started"
	TransmitterEventDeliverySuccess = "delivery_success"
	TransmitterEventDeliveryFailed  = "delivery_failed"
	TransmitterEventQueued          = "event_queued"
	TransmitterEventHTTPExchange    = "http_exchange"
)

// NewTransmitter creates a new SSF transmitter
func NewTransmitter(storage *Storage, privateKey *rsa.PrivateKey, keyID, baseURL string) *Transmitter {
	encoder := NewSETEncoder(baseURL, privateKey, keyID)
	return &Transmitter{
		storage:    storage,
		encoder:    encoder,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// AddEventListener adds a listener for transmitter events
func (t *Transmitter) AddEventListener(ch chan<- TransmitterEvent) {
	t.listenerMu.Lock()
	defer t.listenerMu.Unlock()
	t.eventListeners = append(t.eventListeners, ch)
}

// RemoveEventListener removes an event listener
func (t *Transmitter) RemoveEventListener(ch chan<- TransmitterEvent) {
	t.listenerMu.Lock()
	defer t.listenerMu.Unlock()
	for i, listener := range t.eventListeners {
		if listener == ch {
			t.eventListeners = append(t.eventListeners[:i], t.eventListeners[i+1:]...)
			return
		}
	}
}

// SetGlass attaches the Looking Glass bus used for stream-lab visibility.
func (t *Transmitter) SetGlass(g *glassBox) {
	t.glass = g
}

// broadcast sends an event to Looking Glass and any remaining channel listeners.
func (t *Transmitter) broadcast(event TransmitterEvent) {
	t.glass.emitTransmitter(event)
	t.listenerMu.RLock()
	defer t.listenerMu.RUnlock()
	for _, listener := range t.eventListeners {
		select {
		case listener <- event:
		default:
			log.Printf("[SSF] WARNING: transmitter event channel full, dropping %s event for session %s", event.Type, event.SessionID)
		}
	}
}

// GenerateEvent creates and stores an SSF event
func (t *Transmitter) GenerateEvent(ctx context.Context, streamID string, event SecurityEvent) (*StoredEvent, error) {
	// Get stream configuration
	stream, err := t.storage.GetStream(ctx, streamID)
	if err != nil {
		return nil, fmt.Errorf("stream not found: %w", err)
	}

	// SSF §6: Enforce stream status. Disabled/paused streams MUST NOT generate
	// events. Verification and stream-updated are framework events: verification
	// is always permitted ([SSF] §8.1.4), and stream-updated MUST be sent before
	// the Transmitter pauses or disables the stream ([SSF] §8.1.5).
	frameworkEvent := event.EventType == EventTypeVerification || event.EventType == EventTypeStreamUpdated
	if !frameworkEvent {
		switch stream.Status {
		case StreamStatusDisabled:
			return nil, fmt.Errorf("stream is disabled")
		case StreamStatusPaused:
			return nil, fmt.Errorf("stream is paused")
		case StreamStatusEnabled, "":
		}
	}

	// Check if event type is requested by receiver.
	// Framework events MAY be sent even when not listed in events_requested ([SSF] §8.1.5).
	if !frameworkEvent {
		eventRequested := false
		for _, requested := range stream.EventsRequested {
			if requested == event.EventType {
				eventRequested = true
				break
			}
		}
		if !eventRequested {
			return nil, fmt.Errorf("event type %s not requested by receiver", event.EventType)
		}

		allowed, allowErr := t.storage.SubjectIsTransmittable(ctx, streamID, subjectToClaim(event.Subject))
		if allowErr != nil {
			return nil, allowErr
		}
		if !allowed {
			return nil, ErrSubjectNotInStream
		}
	}

	// Generate event ID
	eventID := uuid.New().String()
	event.ID = eventID
	event.Issuer = stream.Issuer
	event.Audience = stream.Audience
	event.IssuedAt = time.Now()
	if event.EventTimestamp.IsZero() {
		event.EventTimestamp = event.IssuedAt
	}
	// SSF §4.1.9 SHOULD set txn; ProtocolSoup demos share one cause across SETs.
	if event.TransactionID == "" {
		event.TransactionID = uuid.New().String()
	}

	// Broadcast: Action Triggered
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventActionTriggered,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data: map[string]interface{}{
			"subject":  event.Subject,
			"metadata": GetEventMetadata(event.EventType),
		},
	})

	// Encode event data
	eventData, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	// Generate SET token -- use eventID as the JTI so poll responses map correctly
	setToken, err := t.encoder.Encode(event, stream.Audience, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SET: %w", err)
	}

	signedClaims := claimsFromCompactSET(setToken)
	glassData := map[string]interface{}{
		"token":          setToken,
		"claims":         signedClaims,
		"iss":            signedClaims["iss"],
		"iat":            signedClaims["iat"],
		"jti":            signedClaims["jti"],
		"aud":            signedClaims["aud"],
		"sub_id":         signedClaims["sub_id"],
		"events":         signedClaims["events"],
		"event_uris":     []string{event.EventType},
		"session_in_set": false,
		"algorithm":      "RS256",
	}

	// Broadcast: SET Generated
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventSETGenerated,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data: glassData,
	})

	// Broadcast: SET Signed
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventSETSigned,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data:      glassData,
	})

	// Find subject ID if exists
	var subjectIDPtr *string
	if email := event.Subject.email(); email != "" {
		subject, err := t.storage.GetSubjectByIdentifier(ctx, streamID, SubjectFormatEmail, email)
		if err == nil && subject != nil {
			subjectIDPtr = &subject.ID
		}
	}

	// Store event
	storedEvent := StoredEvent{
		ID:        eventID,
		StreamID:  streamID,
		SubjectID: subjectIDPtr,
		EventType: event.EventType,
		EventData: string(eventData),
		SETToken:  setToken,
		SessionID: event.SessionID,
		Status:    EventStatusPending,
		CreatedAt: time.Now(),
	}

	if err := t.storage.StoreEvent(ctx, storedEvent); err != nil {
		return nil, fmt.Errorf("failed to store event: %w", err)
	}

	// Broadcast: Event Queued
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventQueued,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data: map[string]interface{}{
			"delivery_method": stream.DeliveryMethod,
		},
	})

	// If push delivery, deliver synchronously so the caller can capture all
	// pipeline events (transmitter + receiver) in the same request cycle.
	// The receiver is localhost so this adds ~10-20ms, not seconds.
	if stream.DeliveryMethod == DeliveryMethodPush && stream.DeliveryEndpoint != "" {
		t.deliverEvent(ctx, stream, &storedEvent)
	}

	return &storedEvent, nil
}

// Retry configuration for push delivery
const (
	maxDeliveryRetries     = 3
	initialRetryBackoff    = 1 * time.Second
	maxRetryBackoff        = 8 * time.Second
	retryBackoffMultiplier = 2
)

// deliverEvent attempts to deliver an event via push with exponential backoff retry.
func (t *Transmitter) deliverEvent(ctx context.Context, stream *Stream, event *StoredEvent) {
	// Broadcast: Delivery Started
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventDeliveryStarted,
		Timestamp: time.Now(),
		EventID:   event.ID,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data: map[string]interface{}{
			"endpoint":    stream.DeliveryEndpoint,
			"method":      "POST",
			"max_retries": maxDeliveryRetries,
		},
	})

	// Update status to delivering
	_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusDelivering)

	backoff := initialRetryBackoff

	for attempt := 1; attempt <= maxDeliveryRetries; attempt++ {
		statusCode, respBody, exchange, err := t.attemptDelivery(ctx, stream, event)

		// Broadcast HTTP exchange for every delivery attempt (success or failure)
		if exchange != nil {
			t.broadcast(TransmitterEvent{
				Type:      TransmitterEventHTTPExchange,
				Timestamp: exchange.Timestamp,
				EventID:   event.ID,
				EventType: event.EventType,
				SessionID: event.SessionID,
				Data:      exchange,
			})
		}

		if err == nil && statusCode >= 200 && statusCode < 300 {
			// Success
			_ = t.storage.RecordDeliveryAttempt(ctx, event.ID, attempt,
				fmt.Sprintf("%d", statusCode), statusCode, respBody, "")
			_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusDelivered)

			// Broadcast: Delivery Success
			t.broadcast(TransmitterEvent{
				Type:      TransmitterEventDeliverySuccess,
				Timestamp: time.Now(),
				EventID:   event.ID,
				EventType: event.EventType,
				SessionID: event.SessionID,
				Data: map[string]interface{}{
					"status_code":   statusCode,
					"response_body": respBody,
					"attempt":       attempt,
				},
			})
			return
		}

		// Build error description
		errorMsg := ""
		if err != nil {
			errorMsg = err.Error()
		} else {
			errorMsg = fmt.Sprintf("HTTP %d: %s", statusCode, respBody)
		}

		// Record the failed attempt
		_ = t.storage.RecordDeliveryAttempt(ctx, event.ID, attempt,
			"failed", statusCode, respBody, errorMsg)

		if attempt < maxDeliveryRetries {
			// Broadcast: Retry scheduled
			t.broadcast(TransmitterEvent{
				Type:      TransmitterEventDeliveryFailed,
				Timestamp: time.Now(),
				EventID:   event.ID,
				EventType: event.EventType,
				SessionID: event.SessionID,
				Data: map[string]interface{}{
					"status_code": statusCode,
					"error":       errorMsg,
					"attempt":     attempt,
					"retrying_in": backoff.String(),
				},
			})

			log.Printf("SSF delivery attempt %d/%d failed for event %s: %s (retrying in %s)",
				attempt, maxDeliveryRetries, event.ID, errorMsg, backoff)

			// Wait with exponential backoff, respecting context cancellation
			select {
			case <-ctx.Done():
				t.handleDeliveryFailure(ctx, event, statusCode, respBody, "delivery cancelled: "+ctx.Err().Error(), attempt)
				return
			case <-time.After(backoff):
			}

			// Exponential backoff with cap
			backoff *= time.Duration(retryBackoffMultiplier)
			if backoff > maxRetryBackoff {
				backoff = maxRetryBackoff
			}
		} else {
			// All retries exhausted
			t.handleDeliveryFailure(ctx, event, statusCode, respBody, errorMsg, attempt)
		}
	}
}

// attemptDelivery makes a single push delivery attempt per RFC 8935 §2.
// Returns the HTTP status code, response body, captured HTTP exchange, and any transport error.
func (t *Transmitter) attemptDelivery(ctx context.Context, stream *Stream, event *StoredEvent) (int, string, *CapturedHTTPExchange, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", stream.DeliveryEndpoint, bytes.NewReader([]byte(event.SETToken)))
	if err != nil {
		return 0, "", nil, err
	}

	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	// Looking Glass already records this hop via TransmitterEventHTTPExchange
	// (full SET body, RFC 8935). Skip CaptureMiddleware so Wire is not duplicated.
	req.Header.Set(lookingglass.SkipCaptureHeader, "1")

	// [SSF] §6.1.1: honour Receiver-supplied authorization_header on every push.
	if strings.TrimSpace(stream.AuthorizationHeader) != "" {
		req.Header.Set("Authorization", stream.AuthorizationHeader)
	} else if stream.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+stream.BearerToken)
	}

	// Looking Glass session is a presentation-layer header for the internal
	// receiver only. Never send it to an external conformance push URL.
	if event.SessionID != "" && isInternalPushEndpoint(t.baseURL, stream.DeliveryEndpoint) {
		req.Header.Set(lookingGlassSessionHeader, event.SessionID)
	}

	// Capture request details
	reqHeaders := make(map[string]string)
	for k := range req.Header {
		reqHeaders[k] = req.Header.Get(k)
	}

	exchange := &CapturedHTTPExchange{
		Label:     "Push Delivery (RFC 8935)",
		Timestamp: time.Now(),
		SessionID: event.SessionID,
		Request: HTTPCapture{
			Method:  "POST",
			URL:     stream.DeliveryEndpoint,
			Headers: reqHeaders,
			Body:    event.SETToken,
		},
		Response: HTTPCapture{
			Headers: make(map[string]string),
		},
	}

	startTime := time.Now()
	resp, err := t.httpClient.Do(req)
	exchange.DurationMs = time.Since(startTime).Milliseconds()

	if err != nil {
		exchange.Response.Body = fmt.Sprintf("error: %v", err)
		return 0, "", exchange, err
	}
	defer resp.Body.Close()

	// Capture response details
	exchange.Response.StatusCode = resp.StatusCode
	for k := range resp.Header {
		exchange.Response.Headers[k] = resp.Header.Get(k)
	}

	respBody, _ := io.ReadAll(resp.Body)
	exchange.Response.Body = string(respBody)

	return resp.StatusCode, string(respBody), exchange, nil
}

// handleDeliveryFailure handles final delivery failure after all retries are exhausted.
func (t *Transmitter) handleDeliveryFailure(ctx context.Context, event *StoredEvent, statusCode int, respBody, errorMsg string, attempts int) {
	_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusFailed)

	if errorMsg == "" {
		errorMsg = fmt.Sprintf("HTTP %d: %s", statusCode, respBody)
	}

	// Broadcast: Delivery Failed (final)
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventDeliveryFailed,
		Timestamp: time.Now(),
		EventID:   event.ID,
		EventType: event.EventType,
		SessionID: event.SessionID,
		Data: map[string]interface{}{
			"status_code":       statusCode,
			"error":             errorMsg,
			"attempts":          attempts,
			"retries_exhausted": true,
		},
	})

	log.Printf("SSF delivery failed for event %s after %d attempt(s): %s", event.ID, attempts, errorMsg)
}

// GetPendingEventsForPoll returns events pending for poll delivery.
// RFC 8936: unacknowledged SETs MUST be retransmitted — do not mark delivered
// on first poll. maxEvents 0 is acknowledge-only (no SETs in the response).
// Returns: sets (JTI -> SET token), sessionIDs (JTI -> session ID), moreAvailable, error.
func (t *Transmitter) GetPendingEventsForPoll(ctx context.Context, streamID string, maxEvents int, ack []string, setErrs map[string]SETError) (map[string]string, map[string]string, bool, error) {
	if len(setErrs) > 0 {
		if err := t.storage.RecordSETErrors(ctx, setErrs); err != nil {
			return nil, nil, false, fmt.Errorf("failed to record setErrs: %w", err)
		}
	}
	if len(ack) > 0 {
		if err := t.storage.AcknowledgeEvents(ctx, ack); err != nil {
			return nil, nil, false, fmt.Errorf("failed to acknowledge events: %w", err)
		}
	}

	if maxEvents == 0 {
		return map[string]string{}, map[string]string{}, false, nil
	}

	events, err := t.storage.GetPendingEvents(ctx, streamID, maxEvents+1)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to get pending events: %w", err)
	}

	moreAvailable := len(events) > maxEvents
	if moreAvailable {
		events = events[:maxEvents]
	}

	sets := make(map[string]string)
	sessionIDs := make(map[string]string)
	for _, event := range events {
		sets[event.ID] = event.SETToken
		if event.SessionID != "" {
			sessionIDs[event.ID] = event.SessionID
		}
	}

	return sets, sessionIDs, moreAvailable, nil
}

// TriggerVerification sends a verification SET per SSF §7.
// The state parameter is an opaque string echoed in the verification event payload,
// allowing the caller to correlate the response.
func (t *Transmitter) TriggerVerification(ctx context.Context, streamID, state, sessionID string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:      EventTypeVerification,
		EventTimestamp: time.Now(),
		State:          state,
		SessionID:      sessionID, // Looking Glass routing only; never a SET claim
		// Verification events use a minimal subject (the stream itself)
		Subject: SubjectIdentifier{
			Format: SubjectFormatOpaque,
			ID:     streamID,
		},
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerSessionRevoked triggers a session revoked event
func (t *Transmitter) TriggerSessionRevoked(ctx context.Context, streamID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	return t.TriggerSessionRevokedWithSession(ctx, streamID, "", subject, reason, initiator)
}

// TriggerSessionRevokedWithSession triggers a session revoked event with session context
func (t *Transmitter) TriggerSessionRevokedWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeSessionRevoked,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		InitiatingEntity: initiator,
	}
	if reason != "" {
		event.ReasonAdmin = &ReasonInfo{EN: reason}
	}

	// Update subject's active sessions
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		if subj.ActiveSessions > 0 {
			subj.ActiveSessions--
		}
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerCredentialChange triggers a credential change event
func (t *Transmitter) TriggerCredentialChange(ctx context.Context, streamID string, subject SubjectIdentifier, credentialType, changeType, initiator string) (*StoredEvent, error) {
	return t.TriggerCredentialChangeWithSession(ctx, streamID, "", subject, credentialType, changeType, initiator)
}

// TriggerCredentialChangeWithSession triggers a credential change event with session context
func (t *Transmitter) TriggerCredentialChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, credentialType, changeType, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeCredentialChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CredentialType:   credentialType,
		ChangeType:       changeType, // CAEP §3.3: REQUIRED (create | revoke | update | delete)
		InitiatingEntity: initiator,
		ReasonAdmin:      &ReasonInfo{EN: "Credential " + changeType + " for " + credentialType},
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerDeviceComplianceChange triggers a device compliance change event
func (t *Transmitter) TriggerDeviceComplianceChange(ctx context.Context, streamID string, subject SubjectIdentifier, currentStatus, previousStatus string) (*StoredEvent, error) {
	return t.TriggerDeviceComplianceChangeWithSession(ctx, streamID, "", subject, currentStatus, previousStatus)
}

// TriggerDeviceComplianceChangeWithSession triggers a device compliance change event with session context
func (t *Transmitter) TriggerDeviceComplianceChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, currentStatus, previousStatus string) (*StoredEvent, error) {
	if currentStatus != ComplianceStatusCompliant && currentStatus != ComplianceStatusNonCompliant {
		return nil, fmt.Errorf("current_status MUST be compliant or not-compliant (CAEP §3.5.1)")
	}
	if previousStatus != ComplianceStatusCompliant && previousStatus != ComplianceStatusNonCompliant {
		return nil, fmt.Errorf("previous_status MUST be compliant or not-compliant (CAEP §3.5.1)")
	}
	if subject.Format != SubjectFormatComplex {
		email := subject.email()
		if email == "" {
			email = subject.Email
		}
		subject = deviceComplianceSubject(email, t.baseURL)
	}
	event := SecurityEvent{
		EventType:        EventTypeDeviceComplianceChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CurrentStatus:    currentStatus,
		PreviousStatus:   previousStatus,
		InitiatingEntity: InitiatingEntityPolicy,
		ReasonAdmin:      &ReasonInfo{EN: "Device compliance changed to " + currentStatus},
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerCredentialCompromise triggers a credential compromise event
func (t *Transmitter) TriggerCredentialCompromise(ctx context.Context, streamID string, subject SubjectIdentifier, reason, credentialType string) (*StoredEvent, error) {
	return t.TriggerCredentialCompromiseWithSession(ctx, streamID, "", subject, reason, credentialType)
}

// TriggerCredentialCompromiseWithSession triggers a credential compromise event with session context.
// RISC §2.7: credential_type is REQUIRED and is written into the SET.
func (t *Transmitter) TriggerCredentialCompromiseWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason, credentialType string) (*StoredEvent, error) {
	if credentialType == "" {
		credentialType = CredentialTypePassword
	}
	event := SecurityEvent{
		EventType:        EventTypeCredentialCompromise,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CredentialType:   credentialType,
		InitiatingEntity: InitiatingEntitySystem,
	}
	if reason != "" {
		event.ReasonAdmin = &ReasonInfo{EN: reason}
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerAccountDisabled triggers an account disabled event
func (t *Transmitter) TriggerAccountDisabled(ctx context.Context, streamID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	return t.TriggerAccountDisabledWithSession(ctx, streamID, "", subject, reason, initiator)
}

// TriggerAccountDisabledWithSession triggers an account disabled event with session context
func (t *Transmitter) TriggerAccountDisabledWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeAccountDisabled,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		Reason:           riscAccountDisabledReason(reason),
		InitiatingEntity: initiator,
	}
	if reason != "" {
		event.ReasonAdmin = &ReasonInfo{EN: reason}
	}

	// Update subject status
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.Status = SubjectStatusDisabled
		subj.ActiveSessions = 0
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerAccountEnabled triggers an account enabled event
func (t *Transmitter) TriggerAccountEnabled(ctx context.Context, streamID string, subject SubjectIdentifier, initiator string) (*StoredEvent, error) {
	return t.TriggerAccountEnabledWithSession(ctx, streamID, "", subject, initiator)
}

// TriggerAccountEnabledWithSession triggers an account enabled event with session context
func (t *Transmitter) TriggerAccountEnabledWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeAccountEnabled,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		InitiatingEntity: initiator,
	}

	// Update subject status
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.Status = SubjectStatusActive
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerAccountPurged triggers an account purged event
func (t *Transmitter) TriggerAccountPurged(ctx context.Context, streamID string, subject SubjectIdentifier, initiator string) (*StoredEvent, error) {
	return t.TriggerAccountPurgedWithSession(ctx, streamID, "", subject, initiator)
}

// TriggerAccountPurgedWithSession triggers an account purged event with session context
func (t *Transmitter) TriggerAccountPurgedWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeAccountPurged,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		InitiatingEntity: initiator,
	}

	// Update subject status (don't delete, mark as purged for demo)
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.Status = SubjectStatusPurged
		subj.ActiveSessions = 0
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerIdentifierChanged triggers an identifier changed event
func (t *Transmitter) TriggerIdentifierChanged(ctx context.Context, streamID string, subject SubjectIdentifier, oldValue, newValue string, initiator string) (*StoredEvent, error) {
	return t.TriggerIdentifierChangedWithSession(ctx, streamID, "", subject, oldValue, newValue, initiator)
}

// TriggerIdentifierChangedWithSession triggers an identifier changed event with session context
func (t *Transmitter) TriggerIdentifierChangedWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, oldValue, newValue string, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeIdentifierChanged,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		OldValue:         oldValue,
		NewValue:         newValue,
		InitiatingEntity: initiator,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerTokenClaimsChange triggers a token claims change event (CAEP §3.2)
func (t *Transmitter) TriggerTokenClaimsChange(ctx context.Context, streamID string, subject SubjectIdentifier, claims map[string]interface{}) (*StoredEvent, error) {
	return t.TriggerTokenClaimsChangeWithSession(ctx, streamID, "", subject, claims)
}

// TriggerTokenClaimsChangeWithSession triggers a token claims change event with session context.
// CAEP §3.2: The "claims" member is a JSON object whose keys are JWT claim names that have changed.
func (t *Transmitter) TriggerTokenClaimsChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, claims map[string]interface{}) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeTokenClaimsChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		Claims:           claims,
		InitiatingEntity: InitiatingEntitySystem,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerIdentifierRecycled triggers an identifier recycled event (RISC §2.6)
func (t *Transmitter) TriggerIdentifierRecycled(ctx context.Context, streamID string, subject SubjectIdentifier, oldValue, newValue string) (*StoredEvent, error) {
	return t.TriggerIdentifierRecycledWithSession(ctx, streamID, "", subject, oldValue, newValue)
}

// TriggerIdentifierRecycledWithSession triggers an identifier recycled event with session context.
// RISC: Includes old-value (previous holder) and new-value (current holder) per the identifier recycling semantics.
func (t *Transmitter) TriggerIdentifierRecycledWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, oldValue, newValue string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeIdentifierRecycled,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		OldValue:         oldValue,
		NewValue:         newValue,
		InitiatingEntity: InitiatingEntitySystem,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerAccountCredentialChangeRequired triggers a credential change required event (RISC §2.1)
func (t *Transmitter) TriggerAccountCredentialChangeRequired(ctx context.Context, streamID string, subject SubjectIdentifier, reason, initiator string) (*StoredEvent, error) {
	return t.TriggerAccountCredentialChangeRequiredWithSession(ctx, streamID, "", subject, reason, initiator)
}

// TriggerAccountCredentialChangeRequiredWithSession triggers a credential change required event with session context.
// RISC: Signals that the subject must change their credentials.
func (t *Transmitter) TriggerAccountCredentialChangeRequiredWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeAccountCredentialChangeRequired,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		Reason:           reason,
		InitiatingEntity: initiator,
		ReasonAdmin:      &ReasonInfo{EN: reason},
	}

	// Mark user as needing password reset
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.Status = SubjectStatusAtRisk
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerAssuranceLevelChange triggers an assurance level change event
func (t *Transmitter) TriggerAssuranceLevelChange(ctx context.Context, streamID string, subject SubjectIdentifier, currentLevel, previousLevel string) (*StoredEvent, error) {
	return t.TriggerAssuranceLevelChangeWithSession(ctx, streamID, "", subject, currentLevel, previousLevel, AssuranceNamespaceNIST)
}

// TriggerAssuranceLevelChangeWithSession triggers an assurance level change event with session context
func (t *Transmitter) TriggerAssuranceLevelChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, currentLevel, previousLevel, namespace string) (*StoredEvent, error) {
	if namespace == "" {
		namespace = AssuranceNamespaceNIST
	}
	event := SecurityEvent{
		EventType:        EventTypeAssuranceLevelChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CurrentLevel:     currentLevel,  // CAEP §3.4: use current_level, not current_status
		PreviousLevel:    previousLevel, // CAEP §3.4: use previous_level, not previous_status
		Namespace:        namespace,     // CAEP §3.4 REQUIRED
		InitiatingEntity: InitiatingEntitySystem,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerSessionsRevoked maps the lab action to CAEP session-revoked for all
// sessions. RISC §2.11: new implementations MUST use the CAEP event.
func (t *Transmitter) TriggerSessionsRevoked(ctx context.Context, streamID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	return t.TriggerSessionsRevokedWithSession(ctx, streamID, "", subject, reason, initiator)
}

func (t *Transmitter) TriggerSessionsRevokedWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeSessionRevoked,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		InitiatingEntity: initiator,
	}
	if reason != "" {
		event.ReasonAdmin = &ReasonInfo{EN: reason}
	}

	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.ActiveSessions = 0
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerStreamUpdated emits a stream-updated SET ([SSF] §8.1.5) with opaque
// sub_id equal to stream_id. Call this before a Transmitter-initiated pause
// or disable, and after a Transmitter-initiated re-enable.
func (t *Transmitter) TriggerStreamUpdated(ctx context.Context, streamID, status, reason, sessionID string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:      EventTypeStreamUpdated,
		EventTimestamp: time.Now(),
		SessionID:      sessionID,
		StreamStatus:   status,
		Reason:         reason,
		Subject: SubjectIdentifier{
			Format: SubjectFormatOpaque,
			ID:     streamID,
		},
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// UpdateStatusAsTransmitter sends stream-updated, then writes the new status.
// Receiver-initiated POST /status does not use this path ([SSF] §8.1.2).
func (t *Transmitter) UpdateStatusAsTransmitter(ctx context.Context, streamID, status, reason, sessionID string) error {
	if _, err := t.TriggerStreamUpdated(ctx, streamID, status, reason, sessionID); err != nil {
		return err
	}
	stream, err := t.storage.GetStream(ctx, streamID)
	if err != nil {
		return err
	}
	stream.Status = status
	return t.storage.UpdateStream(ctx, *stream)
}

func isInternalPushEndpoint(baseURL, endpoint string) bool {
	if endpoint == "" {
		return false
	}
	base := strings.TrimRight(baseURL, "/")
	if base != "" && (strings.HasPrefix(endpoint, base+"/ssf/receiver/") ||
		strings.HasPrefix(endpoint, base+"/ssf/push")) {
		return true
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return strings.Contains(parsed.Path, "/ssf/")
	}
	return false
}
