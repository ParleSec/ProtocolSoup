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
	"sync"
	"time"

	"github.com/google/uuid"
)

// Transmitter handles event generation and delivery
type Transmitter struct {
	storage    *Storage
	encoder    *SETEncoder
	baseURL    string
	httpClient *http.Client

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

// broadcast sends an event to all listeners
func (t *Transmitter) broadcast(event TransmitterEvent) {
	t.listenerMu.RLock()
	defer t.listenerMu.RUnlock()
	for _, listener := range t.eventListeners {
		select {
		case listener <- event:
		default:
			// Drop if channel is full
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

	// Check if event type is requested by receiver
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

	// Generate event ID
	eventID := uuid.New().String()
	event.ID = eventID
	event.Issuer = stream.Issuer
	event.Audience = stream.Audience
	event.IssuedAt = time.Now()
	if event.EventTimestamp.IsZero() {
		event.EventTimestamp = event.IssuedAt
	}

	// Broadcast: Action Triggered
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventActionTriggered,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
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

	// Broadcast: SET Generated
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventSETGenerated,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		Data: map[string]interface{}{
			"claims": event,
		},
	})

	// Broadcast: SET Signed
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventSETSigned,
		Timestamp: time.Now(),
		EventID:   eventID,
		SubjectID: event.Subject.Email,
		EventType: event.EventType,
		Data: map[string]interface{}{
			"token":     setToken,
			"algorithm": "RS256",
		},
	})

	// Find subject ID if exists
	var subjectIDPtr *string
	subject, err := t.storage.GetSubjectByIdentifier(ctx, streamID, event.Subject.Format, event.Subject.Email)
	if err == nil && subject != nil {
		subjectIDPtr = &subject.ID
	}

	// Store event
	storedEvent := StoredEvent{
		ID:        eventID,
		StreamID:  streamID,
		SubjectID: subjectIDPtr,
		EventType: event.EventType,
		EventData: string(eventData),
		SETToken:  setToken,
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
		Data: map[string]interface{}{
			"delivery_method": stream.DeliveryMethod,
		},
	})

	// If push delivery, attempt delivery immediately with background context
	// Use background context to ensure delivery completes even after handler returns
	if stream.DeliveryMethod == DeliveryMethodPush && stream.DeliveryEndpoint != "" {
		go t.deliverEvent(context.Background(), stream, &storedEvent)
	}

	return &storedEvent, nil
}

// deliverEvent attempts to deliver an event via push
func (t *Transmitter) deliverEvent(ctx context.Context, stream *Stream, event *StoredEvent) {
	// Broadcast: Delivery Started
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventDeliveryStarted,
		Timestamp: time.Now(),
		EventID:   event.ID,
		EventType: event.EventType,
		Data: map[string]interface{}{
			"endpoint": stream.DeliveryEndpoint,
			"method":   "POST",
		},
	})

	// Update status to delivering
	_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusDelivering)

	// Send raw SET per RFC 8935 §2: body is the compact JWT, Content-Type is application/secevent+jwt
	req, err := http.NewRequestWithContext(ctx, "POST", stream.DeliveryEndpoint, bytes.NewReader([]byte(event.SETToken)))
	if err != nil {
		t.handleDeliveryFailure(ctx, event, 0, "", err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	// Add bearer token if configured for authenticated push delivery
	if stream.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+stream.BearerToken)
	}

	// Execute request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		t.handleDeliveryFailure(ctx, event, 0, "", err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Record delivery attempt
	_ = t.storage.RecordDeliveryAttempt(ctx, event.ID, 1,
		fmt.Sprintf("%d", resp.StatusCode), resp.StatusCode, string(respBody), "")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Success
		_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusDelivered)

		// Broadcast: Delivery Success
		t.broadcast(TransmitterEvent{
			Type:      TransmitterEventDeliverySuccess,
			Timestamp: time.Now(),
			EventID:   event.ID,
			EventType: event.EventType,
			Data: map[string]interface{}{
				"status_code":   resp.StatusCode,
				"response_body": string(respBody),
			},
		})
	} else {
		t.handleDeliveryFailure(ctx, event, resp.StatusCode, string(respBody), "")
	}
}

// handleDeliveryFailure handles a failed delivery attempt
func (t *Transmitter) handleDeliveryFailure(ctx context.Context, event *StoredEvent, statusCode int, respBody, errorMsg string) {
	_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusFailed)

	if errorMsg == "" {
		errorMsg = fmt.Sprintf("HTTP %d: %s", statusCode, respBody)
	}

	// Broadcast: Delivery Failed
	t.broadcast(TransmitterEvent{
		Type:      TransmitterEventDeliveryFailed,
		Timestamp: time.Now(),
		EventID:   event.ID,
		EventType: event.EventType,
		Data: map[string]interface{}{
			"status_code": statusCode,
			"error":       errorMsg,
		},
	})

	log.Printf("SSF delivery failed for event %s: %s", event.ID, errorMsg)
}

// GetPendingEventsForPoll returns events pending for poll delivery
func (t *Transmitter) GetPendingEventsForPoll(ctx context.Context, streamID string, maxEvents int, ack []string) (map[string]string, bool, error) {
	// Acknowledge any events if provided
	if len(ack) > 0 {
		if err := t.storage.AcknowledgeEvents(ctx, ack); err != nil {
			return nil, false, fmt.Errorf("failed to acknowledge events: %w", err)
		}
	}

	// Get pending events
	events, err := t.storage.GetPendingEvents(ctx, streamID, maxEvents)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get pending events: %w", err)
	}

	// Build response
	sets := make(map[string]string)
	for _, event := range events {
		sets[event.ID] = event.SETToken
		// Mark as delivered since receiver is polling
		_ = t.storage.UpdateEventStatus(ctx, event.ID, EventStatusDelivered)
	}

	// Check if there are more events
	moreAvailable := len(events) == maxEvents

	return sets, moreAvailable, nil
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
		Reason:           reason,
		InitiatingEntity: initiator,
		ReasonAdmin:      &ReasonInfo{EN: reason},
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
		ChangeType:       changeType, // CAEP §3.2: REQUIRED (create | revoke | update)
		InitiatingEntity: initiator,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerDeviceComplianceChange triggers a device compliance change event
func (t *Transmitter) TriggerDeviceComplianceChange(ctx context.Context, streamID string, subject SubjectIdentifier, currentStatus, previousStatus string) (*StoredEvent, error) {
	return t.TriggerDeviceComplianceChangeWithSession(ctx, streamID, "", subject, currentStatus, previousStatus)
}

// TriggerDeviceComplianceChangeWithSession triggers a device compliance change event with session context
func (t *Transmitter) TriggerDeviceComplianceChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, currentStatus, previousStatus string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeDeviceComplianceChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CurrentStatus:    currentStatus,
		PreviousStatus:   previousStatus,
		InitiatingEntity: InitiatingEntitySystem,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerCredentialCompromise triggers a credential compromise event
func (t *Transmitter) TriggerCredentialCompromise(ctx context.Context, streamID string, subject SubjectIdentifier, reason string) (*StoredEvent, error) {
	return t.TriggerCredentialCompromiseWithSession(ctx, streamID, "", subject, reason)
}

// TriggerCredentialCompromiseWithSession triggers a credential compromise event with session context
func (t *Transmitter) TriggerCredentialCompromiseWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeCredentialCompromise,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		Reason:           reason,
		InitiatingEntity: InitiatingEntitySystem,
		ReasonAdmin:      &ReasonInfo{EN: reason},
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
		Reason:           reason,
		InitiatingEntity: initiator,
		ReasonAdmin:      &ReasonInfo{EN: reason},
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

// TriggerAssuranceLevelChange triggers an assurance level change event
func (t *Transmitter) TriggerAssuranceLevelChange(ctx context.Context, streamID string, subject SubjectIdentifier, currentLevel, previousLevel string) (*StoredEvent, error) {
	return t.TriggerAssuranceLevelChangeWithSession(ctx, streamID, "", subject, currentLevel, previousLevel)
}

// TriggerAssuranceLevelChangeWithSession triggers an assurance level change event with session context
func (t *Transmitter) TriggerAssuranceLevelChangeWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, currentLevel, previousLevel string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeAssuranceLevelChange,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		CurrentLevel:     currentLevel,  // CAEP §3.3: use current_level, not current_status
		PreviousLevel:    previousLevel, // CAEP §3.3: use previous_level, not previous_status
		InitiatingEntity: InitiatingEntitySystem,
	}
	return t.GenerateEvent(ctx, streamID, event)
}

// TriggerSessionsRevoked triggers a sessions revoked event (all sessions)
func (t *Transmitter) TriggerSessionsRevoked(ctx context.Context, streamID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	return t.TriggerSessionsRevokedWithSession(ctx, streamID, "", subject, reason, initiator)
}

// TriggerSessionsRevokedWithSession triggers a sessions revoked event with session context
func (t *Transmitter) TriggerSessionsRevokedWithSession(ctx context.Context, streamID, sessionID string, subject SubjectIdentifier, reason string, initiator string) (*StoredEvent, error) {
	event := SecurityEvent{
		EventType:        EventTypeSessionsRevoked,
		Subject:          subject,
		SessionID:        sessionID,
		EventTimestamp:   time.Now(),
		Reason:           reason,
		InitiatingEntity: initiator,
		ReasonAdmin:      &ReasonInfo{EN: reason},
	}

	// Update subject's active sessions to 0
	subj, err := t.storage.GetSubjectByIdentifier(ctx, streamID, subject.Format, subject.Email)
	if err == nil && subj != nil {
		subj.ActiveSessions = 0
		_ = t.storage.UpdateSubject(ctx, *subj)
	}

	return t.GenerateEvent(ctx, streamID, event)
}
