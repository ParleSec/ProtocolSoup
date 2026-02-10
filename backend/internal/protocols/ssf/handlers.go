package ssf

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
)

// getSessionID extracts or generates a session ID from the request
func getSessionID(r *http.Request) string {
	// Check header first (frontend will send this)
	sessionID := r.Header.Get("X-SSF-Session")
	if sessionID != "" {
		return sessionID
	}

	// Check cookie as fallback
	cookie, err := r.Cookie("ssf_session")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Return empty if no session header (frontend should always send one)
	return ""
}

// handleInfo returns SSF plugin information
func (p *Plugin) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"protocol":    "Shared Signals Framework (SSF)",
		"version":     "1.0",
		"description": "OpenID Shared Signals Framework for real-time security event sharing",
		"specifications": []string{
			"OpenID Shared Signals Framework 1.0",
			"CAEP - Continuous Access Evaluation Profile",
			"RISC - Risk Incident Sharing and Coordination",
			"RFC 8417 - Security Event Token (SET)",
		},
		"features": map[string]bool{
			"transmitter": true,
			"receiver":    true,
			"push":        true,
			"poll":        true,
			"caep":        true,
			"risc":        true,
		},
	}
	writeJSON(w, http.StatusOK, info)
}

// handleSSFConfiguration returns the SSF transmitter metadata per OpenID SSF 1.0 §3.1
func (p *Plugin) handleSSFConfiguration(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"spec_version": "1_0-ID3",
		"issuer":       p.baseURL,
		"jwks_uri":     p.baseURL + "/ssf/jwks",
		"delivery_methods_supported": []string{
			DeliveryMethodPush,
			DeliveryMethodPoll,
		},
		"configuration_endpoint":   p.baseURL + "/ssf/stream",
		"status_endpoint":          p.baseURL + "/ssf/status",
		"verification_endpoint":    p.baseURL + "/ssf/verify",
		"add_subject_endpoint":     p.baseURL + "/ssf/subjects",
		"remove_subject_endpoint":  p.baseURL + "/ssf/subjects",
		"events_supported":         GetSupportedEventURIs(),
		"critical_subject_members": []string{SubjectFormatEmail, SubjectFormatIssuerSub},
	}
	writeJSON(w, http.StatusOK, config)
}

// handleJWKS returns the public keys for SET verification
func (p *Plugin) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if p.keySet == nil {
		writeError(w, http.StatusInternalServerError, "Key set not available")
		return
	}
	writeJSON(w, http.StatusOK, p.keySet.PublicJWKS())
}

// ====================
// Stream Management
// ====================

// handleGetStream returns the current stream configuration
func (p *Plugin) handleGetStream(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}
	writeJSON(w, http.StatusOK, stream)
}

// handleUpdateStream updates the stream configuration
func (p *Plugin) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	var update struct {
		DeliveryMethod   string   `json:"delivery_method,omitempty"`
		DeliveryEndpoint string   `json:"delivery_endpoint_url,omitempty"`
		EventsRequested  []string `json:"events_requested,omitempty"`
		Status           string   `json:"status,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	// Apply updates
	if update.DeliveryMethod != "" {
		stream.DeliveryMethod = update.DeliveryMethod
	}
	if update.DeliveryEndpoint != "" {
		stream.DeliveryEndpoint = update.DeliveryEndpoint
	}
	if len(update.EventsRequested) > 0 {
		stream.EventsRequested = update.EventsRequested
	}
	if update.Status != "" {
		stream.Status = update.Status
	}

	if err := p.storage.UpdateStream(r.Context(), *stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update stream")
		return
	}

	writeJSON(w, http.StatusOK, stream)
}

// handleCreateStream creates a new stream per SSF §4.1
func (p *Plugin) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeliveryMethod   string   `json:"delivery_method"`
		DeliveryEndpoint string   `json:"delivery_endpoint_url,omitempty"`
		EventsRequested  []string `json:"events_requested,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate delivery method
	switch req.DeliveryMethod {
	case DeliveryMethodPush, DeliveryMethodPoll:
		// Valid
	default:
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid delivery_method: %q (must be %q or %q)", req.DeliveryMethod, DeliveryMethodPush, DeliveryMethodPoll))
		return
	}

	// Push delivery requires an endpoint
	if req.DeliveryMethod == DeliveryMethodPush && req.DeliveryEndpoint == "" {
		writeError(w, http.StatusBadRequest, "delivery_endpoint_url is required for push delivery")
		return
	}

	sessionID := getSessionID(r)
	streamID := generateID()
	if sessionID != "" {
		streamID = "session-" + sessionID
	}

	eventsRequested := req.EventsRequested
	if len(eventsRequested) == 0 {
		eventsRequested = GetSupportedEventURIs()
	}

	stream := Stream{
		ID:               streamID,
		Issuer:           p.baseURL,
		Audience:         []string{p.baseURL + "/receiver"},
		EventsSupported:  GetSupportedEventURIs(),
		EventsRequested:  eventsRequested,
		DeliveryMethod:   req.DeliveryMethod,
		DeliveryEndpoint: req.DeliveryEndpoint,
		Status:           StreamStatusEnabled,
	}

	if err := p.storage.CreateStream(r.Context(), stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create stream")
		return
	}

	writeJSON(w, http.StatusCreated, stream)
}

// handleDeleteStream deletes a stream per SSF §4.1
func (p *Plugin) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return
	}

	if err := p.storage.DeleteStream(r.Context(), stream.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete stream")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ====================
// Subject Management
// ====================

// handleListSubjects returns all subjects
func (p *Plugin) handleListSubjects(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get stream")
			return
		}
		// Ensure demo data exists for this session
		_ = p.storage.SeedSessionDemoData(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
		// Initialize user states for this session
		p.actionExecutor.InitSessionUserStates(sessionID)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get stream")
			return
		}
	}

	subjects, err := p.storage.ListSubjects(r.Context(), stream.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list subjects")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"subjects":   subjects,
		"total":      len(subjects),
		"session_id": sessionID,
	})
}

// handleAddSubject adds a new subject
func (p *Plugin) handleAddSubject(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	var req struct {
		Format      string `json:"format"`
		Identifier  string `json:"identifier"`
		DisplayName string `json:"display_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Format == "" {
		req.Format = SubjectFormatEmail
	}
	if req.Identifier == "" {
		writeError(w, http.StatusBadRequest, "Identifier is required")
		return
	}

	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	subjectID := generateID()
	if sessionID != "" {
		subjectID = sessionID + "-" + subjectID
	}

	subject := Subject{
		ID:             subjectID,
		StreamID:       stream.ID,
		Format:         req.Format,
		Identifier:     req.Identifier,
		DisplayName:    req.DisplayName,
		Status:         SubjectStatusActive,
		ActiveSessions: 1,
	}

	if err := p.storage.AddSubject(r.Context(), subject); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add subject")
		return
	}

	if p.actionExecutor != nil {
		p.actionExecutor.ResetUserStateForSession(sessionID, subject.Identifier, subject.ActiveSessions)
	}

	writeJSON(w, http.StatusCreated, subject)
}

// handleDeleteSubject removes a subject
func (p *Plugin) handleDeleteSubject(w http.ResponseWriter, r *http.Request) {
	subjectID := chi.URLParam(r, "id")
	if subjectID == "" {
		writeError(w, http.StatusBadRequest, "Subject ID is required")
		return
	}

	subject, err := p.storage.GetSubject(r.Context(), subjectID)
	if err == nil {
		_ = p.storage.DeleteSecurityState(r.Context(), subject.StreamID, subject.Identifier)
	}

	if err := p.storage.DeleteSubject(r.Context(), subjectID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete subject")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ====================
// Action Handlers (Interactive Triggers)
// ====================

// handleTriggerAction handles all action triggers
func (p *Plugin) handleTriggerAction(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	action := chi.URLParam(r, "action")
	sessionID := getSessionID(r)

	var req ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SubjectIdentifier == "" {
		writeError(w, http.StatusBadRequest, "subject_identifier is required")
		return
	}

	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	// ── Subscribe temp channels to capture ALL pipeline events ──────────
	// Delivery is synchronous, so every transmitter and receiver event is
	// captured in these channels and returned in the API response.
	// This makes event delivery reliable regardless of SSE connection state.
	txCapture := make(chan TransmitterEvent, 128)
	p.transmitter.AddEventListener(txCapture)
	defer p.transmitter.RemoveEventListener(txCapture)

	rxCapture := make(chan ReceiverEvent, 128)
	p.receiverService.AddEventListener(rxCapture)
	defer p.receiverService.RemoveEventListener(rxCapture)

	subject := SubjectIdentifier{
		Format: SubjectFormatEmail,
		Email:  req.SubjectIdentifier,
	}

	initiator := req.Initiator
	if initiator == "" {
		initiator = InitiatingEntityAdmin
	}

	var event *StoredEvent

	switch action {
	case "session-revoked":
		reason := req.Reason
		if reason == "" {
			reason = "Session revoked by administrator"
		}
		event, err = p.transmitter.TriggerSessionRevokedWithSession(r.Context(), stream.ID, sessionID, subject, reason, initiator)

	case "credential-change":
		credType := req.CredentialType
		if credType == "" {
			credType = CredentialTypePassword
		}
		changeType := req.ChangeType
		if changeType == "" {
			changeType = "update" // CAEP §3.2 default
		}
		event, err = p.transmitter.TriggerCredentialChangeWithSession(r.Context(), stream.ID, sessionID, subject, credType, changeType, initiator)

	case "device-compliance-change":
		current := req.CurrentStatus
		previous := req.PreviousStatus
		if current == "" {
			current = ComplianceStatusNonCompliant
		}
		if previous == "" {
			previous = ComplianceStatusCompliant
		}
		event, err = p.transmitter.TriggerDeviceComplianceChangeWithSession(r.Context(), stream.ID, sessionID, subject, current, previous)

	case "credential-compromise":
		reason := req.Reason
		if reason == "" {
			reason = "Credentials potentially exposed in data breach"
		}
		event, err = p.transmitter.TriggerCredentialCompromiseWithSession(r.Context(), stream.ID, sessionID, subject, reason)

	case "account-disabled":
		reason := req.Reason
		if reason == "" {
			reason = "Account disabled by administrator"
		}
		event, err = p.transmitter.TriggerAccountDisabledWithSession(r.Context(), stream.ID, sessionID, subject, reason, initiator)

	case "account-enabled":
		event, err = p.transmitter.TriggerAccountEnabledWithSession(r.Context(), stream.ID, sessionID, subject, initiator)

	case "account-purged":
		event, err = p.transmitter.TriggerAccountPurgedWithSession(r.Context(), stream.ID, sessionID, subject, initiator)

	case "identifier-changed":
		if req.NewValue == "" {
			writeError(w, http.StatusBadRequest, "new_value is required for identifier-changed")
			return
		}
		event, err = p.transmitter.TriggerIdentifierChangedWithSession(r.Context(), stream.ID, sessionID, subject,
			req.SubjectIdentifier, req.NewValue, initiator)

	case "assurance-level-change":
		current := req.CurrentStatus
		previous := req.PreviousStatus
		if current == "" {
			current = "aal1"
		}
		if previous == "" {
			previous = "aal2"
		}
		event, err = p.transmitter.TriggerAssuranceLevelChangeWithSession(r.Context(), stream.ID, sessionID, subject, current, previous)

	case "sessions-revoked":
		reason := req.Reason
		if reason == "" {
			reason = "All sessions revoked due to security incident"
		}
		event, err = p.transmitter.TriggerSessionsRevokedWithSession(r.Context(), stream.ID, sessionID, subject, reason, initiator)

	default:
		writeError(w, http.StatusBadRequest, "Unknown action: "+action)
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Get event metadata for response
	metadata := GetEventMetadata(event.EventType)

	// ── Drain captured pipeline events ─────────────────────────────────
	// Delivery is synchronous, so by this point ALL transmitter + receiver
	// events have been broadcast and are sitting in our temp channels.

	// Prepend the initiating action request as the first HTTP exchange
	// so the full chain is visible: action call → transmitter → receiver.
	reqBody, _ := json.Marshal(req)
	actionExchange := map[string]interface{}{
		"source": "transmitter",
		"event": map[string]interface{}{
			"type":       "http_exchange",
			"timestamp":  time.Now(),
			"event_id":   event.ID,
			"session_id": sessionID,
			"data": CapturedHTTPExchange{
				Label: fmt.Sprintf("Action: %s (SSF §4)", metadata.Name),
				Request: HTTPCapture{
					Method: r.Method,
					URL:    fmt.Sprintf("/ssf/actions/%s", action),
					Headers: map[string]string{
						"Content-Type":    "application/json",
						"X-Ssf-Session":   sessionID,
					},
					Body: string(reqBody),
				},
				Response: HTTPCapture{
					StatusCode: http.StatusOK,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
				DurationMs: 0, // filled below
				Timestamp:  time.Now(),
				SessionID:  sessionID,
			},
		},
	}

	var pipelineEvents []map[string]interface{}
	pipelineEvents = append(pipelineEvents, actionExchange)
	drainDone := false
	for !drainDone {
		select {
		case txEv := <-txCapture:
			if txEv.SessionID != "" && txEv.SessionID != sessionID {
				continue
			}
			pipelineEvents = append(pipelineEvents, map[string]interface{}{
				"source": "transmitter",
				"event":  txEv,
			})
		case rxEv := <-rxCapture:
			if rxEv.SessionID != "" && rxEv.SessionID != sessionID {
				continue
			}
			pipelineEvents = append(pipelineEvents, map[string]interface{}{
				"source": "receiver",
				"event":  rxEv,
			})
		default:
			drainDone = true
		}
	}

	// Set real duration on the action exchange now that execution is complete
	if exData, ok := actionExchange["event"].(map[string]interface{}); ok {
		if capture, ok := exData["data"].(CapturedHTTPExchange); ok {
			capture.DurationMs = time.Since(startTime).Milliseconds()
			exData["data"] = capture
		}
	}

	writeJSON(w, http.StatusOK, ActionResponse{
		EventID:         event.ID,
		EventType:       event.EventType,
		EventName:       metadata.Name,
		Category:        string(metadata.Category),
		Subject:         req.SubjectIdentifier,
		Status:          event.Status,
		DeliveryMethod:  stream.DeliveryMethod,
		ResponseActions: metadata.ResponseActions,
		ZeroTrustImpact: metadata.ZeroTrustImpact,
		PipelineEvents:  pipelineEvents,
	})
}

// ActionRequest represents a request to trigger an action
type ActionRequest struct {
	SubjectIdentifier string `json:"subject_identifier"`
	Reason            string `json:"reason,omitempty"`
	Initiator         string `json:"initiator,omitempty"`
	CredentialType    string `json:"credential_type,omitempty"`
	ChangeType        string `json:"change_type,omitempty"` // CAEP §3.2: create | revoke | update
	CurrentStatus     string `json:"current_status,omitempty"`
	PreviousStatus    string `json:"previous_status,omitempty"`
	NewValue          string `json:"new_value,omitempty"`
}

// ActionResponse represents the response after triggering an action
type ActionResponse struct {
	EventID         string                   `json:"event_id"`
	EventType       string                   `json:"event_type"`
	EventName       string                   `json:"event_name"`
	Category        string                   `json:"category"`
	Subject         string                   `json:"subject"`
	Status          string                   `json:"status"`
	DeliveryMethod  string                   `json:"delivery_method"`
	ResponseActions []string                 `json:"response_actions"`
	ZeroTrustImpact string                   `json:"zero_trust_impact"`
	PipelineEvents  []map[string]interface{} `json:"pipeline_events,omitempty"`
}

// ====================
// Event Delivery
// ====================

// handlePush handles push delivery per RFC 8935 §2.
// The request body is the raw compact-serialized SET with Content-Type: application/secevent+jwt.
// On success returns 202 Accepted with an empty body.
func (p *Plugin) handlePush(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body")
		return
	}

	setToken := string(body)
	sessionID := r.Header.Get("X-SSF-Session")

	// Process through the standalone receiver (same Go process, direct call)
	result := p.receiverService.processSET(r.Context(), setToken, sessionID)
	if result.Status == "failed" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", result.Description)
		return
	}

	// RFC 8935 §2.2: 202 Accepted on success
	w.WriteHeader(http.StatusAccepted)
}

// handlePoll handles poll requests
func (p *Plugin) handlePoll(w http.ResponseWriter, r *http.Request) {
	var req PollRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req = PollRequest{} // Use defaults if parsing fails
		}
	}

	if req.MaxEvents <= 0 {
		req.MaxEvents = 10
	}

	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	sets, sessionIDs, moreAvailable, err := p.transmitter.GetPendingEventsForPoll(r.Context(), stream.ID, req.MaxEvents, req.Ack)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Process polled events through the standalone receiver
	if len(sets) > 0 {
		p.receiverService.ProcessPollResponse(r.Context(), sets, sessionIDs)
	}

	writeJSON(w, http.StatusOK, PollResponse{
		Sets:          sets,
		MoreAvailable: moreAvailable,
	})
}

// handleAcknowledge acknowledges received events
func (p *Plugin) handleAcknowledge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ack []string `json:"ack"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := p.storage.AcknowledgeEvents(r.Context(), req.Ack); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ====================
// Stream Verification (SSF §7)
// ====================

// handleVerification triggers a verification event per SSF §7.
// The transmitter sends a verification SET containing the provided state value
// through the configured delivery method, confirming the stream pipeline is healthy.
func (p *Plugin) handleVerification(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	var req struct {
		State string `json:"state"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.State == "" {
		writeError(w, http.StatusBadRequest, "state is required per SSF §7")
		return
	}

	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	event, err := p.transmitter.TriggerVerification(r.Context(), stream.ID, req.State)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "verification_sent",
		"event_id": event.ID,
		"state":    req.State,
		"delivery": stream.DeliveryMethod,
	})
}

// ====================
// Stream Status (SSF §6)
// ====================

// handleGetStatus returns the current stream status per SSF §6.
func (p *Plugin) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": stream.Status,
	})
}

// handleUpdateStatus updates the stream status per SSF §6.
// Accepts: enabled, paused, disabled.
func (p *Plugin) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	var req struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate status value
	switch req.Status {
	case StreamStatusEnabled, StreamStatusPaused, StreamStatusDisabled:
		// Valid
	default:
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid status: %q (must be enabled, paused, or disabled)", req.Status))
		return
	}

	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	stream.Status = req.Status
	if err := p.storage.UpdateStream(r.Context(), *stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update stream status")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": stream.Status,
	})
}

// ====================
// Event History & Logs
// ====================

// handleGetEvents returns the event history
func (p *Plugin) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	status := r.URL.Query().Get("status")
	events, err := p.storage.GetEvents(r.Context(), stream.ID, status, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get events")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":     events,
		"total":      len(events),
		"session_id": sessionID,
	})
}

// handleGetReceivedEvents returns events received by the receiver
func (p *Plugin) handleGetReceivedEvents(w http.ResponseWriter, r *http.Request) {
	events := p.receiverService.GetReceivedEvents()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

// handleGetResponseActions returns the response actions log
func (p *Plugin) handleGetResponseActions(w http.ResponseWriter, r *http.Request) {
	actions := p.receiverService.GetResponseActions()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"actions": actions,
		"total":   len(actions),
	})
}

// handleClearLogs clears receiver logs
func (p *Plugin) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	p.receiverService.ClearLogs()
	w.WriteHeader(http.StatusNoContent)
}

// ====================
// Event Types Info
// ====================

// handleGetEventTypes returns all supported event types
func (p *Plugin) handleGetEventTypes(w http.ResponseWriter, r *http.Request) {
	eventTypes := GetAllEventTypes()
	writeJSON(w, http.StatusOK, eventTypes)
}

// ====================
// SET Inspection
// ====================

// handleDecodeSET decodes a SET token for inspection
func (p *Plugin) handleDecodeSET(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	decoded, err := DecodeWithoutValidation(req.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, decoded)
}

// ====================
// SSE Event Stream
// ====================

// handleEventStream serves a Server-Sent Events stream that bridges internal
// transmitter and receiver broadcast channels to the frontend in real time.
// The session ID is passed via query parameter because EventSource cannot send
// custom headers.
func (p *Plugin) handleEventStream(w http.ResponseWriter, r *http.Request) {
	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get session ID from query param (EventSource can't send custom headers)
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		sessionID = getSessionID(r)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// ── Cancel any existing SSE goroutine for this session ──────────────
	// Without this, reconnects leave phantom goroutines that consume
	// broadcast events but write to dead proxy connections, causing the
	// "events randomly stop appearing" symptom.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	p.sseSessionsMu.Lock()
	if old, exists := p.sseSessions[sessionID]; exists {
		old.cancel() // kills the old goroutine's select loop
		log.Printf("[SSF] SSE: replaced stale connection for session %s", sessionID)
	}
	p.sseConnIDSeq++
	connID := p.sseConnIDSeq
	p.sseSessions[sessionID] = sseConn{id: connID, cancel: cancel}
	p.sseSessionsMu.Unlock()

	// Clean up tracking on exit (only if we're still the active connection)
	defer func() {
		p.sseSessionsMu.Lock()
		if cur, exists := p.sseSessions[sessionID]; exists && cur.id == connID {
			delete(p.sseSessions, sessionID)
		}
		p.sseSessionsMu.Unlock()
	}()

	// Subscribe to transmitter events (large buffer to avoid drops during burst flows)
	txCh := make(chan TransmitterEvent, 512)
	p.transmitter.AddEventListener(txCh)
	defer p.transmitter.RemoveEventListener(txCh)

	// Subscribe to receiver events
	rxCh := make(chan ReceiverEvent, 512)
	p.receiverService.AddEventListener(rxCh)
	defer p.receiverService.RemoveEventListener(rxCh)

	// Send initial connected event
	fmt.Fprintf(w, "event: connected\ndata: {\"session_id\":%q}\n\n", sessionID)
	flusher.Flush()

	// Keep-alive ticker prevents proxies from closing idle connections
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-keepAlive.C:
			// SSE comment line — keeps connection alive through proxies
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return // client gone
			}
			flusher.Flush()

		case txEvent := <-txCh:
			// Filter by session ID
			if sessionID != "" && txEvent.SessionID != "" && txEvent.SessionID != sessionID {
				continue
			}
			data, err := json.Marshal(map[string]interface{}{
				"source": "transmitter",
				"event":  txEvent,
			})
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: pipeline\ndata: %s\n\n", data); err != nil {
				return // client disconnected
			}
			flusher.Flush()

		case rxEvent := <-rxCh:
			// Filter by session ID
			if sessionID != "" && rxEvent.SessionID != "" && rxEvent.SessionID != sessionID {
				continue
			}
			data, err := json.Marshal(map[string]interface{}{
				"source": "receiver",
				"event":  rxEvent,
			})
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: pipeline\ndata: %s\n\n", data); err != nil {
				return // client disconnected
			}
			flusher.Flush()
		}
	}
}

// ====================
// Helpers
// ====================

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeSSFError writes an error response per RFC 8935 §2.3.
// The wire format is {"err":"<code>","description":"<text>"} with codes:
// invalid_request, invalid_key, authentication_failed, access_denied.
func writeSSFError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, map[string]string{
		"err":         errCode,
		"description": description,
	})
}

func generateID() string {
	return randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			b[i] = letters[i%len(letters)]
		} else {
			b[i] = letters[num.Int64()]
		}
	}
	return string(b)
}

// ====================
// Standalone Receiver Handlers
// ====================

// handleReceiverStatus returns the standalone receiver status
func (p *Plugin) handleReceiverStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":           "running",
		"port":             p.receiverPort,
		"endpoint":         fmt.Sprintf("http://localhost:%d/ssf/push", p.receiverPort),
		"transmitter_url":  p.baseURL,
		"bearer_token":     "configured", // Never expose token material, even partially
		"events_received":  len(p.receiverService.GetReceivedEvents()),
		"actions_executed": len(p.receiverService.GetResponseActions()),
	}
	writeJSON(w, http.StatusOK, status)
}

// handleReceiverEvents returns events received by the standalone receiver
func (p *Plugin) handleReceiverEvents(w http.ResponseWriter, r *http.Request) {
	events := p.receiverService.GetReceivedEvents()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  len(events),
		"source": "standalone_receiver",
	})
}

// handleReceiverActions returns response actions from the standalone receiver
func (p *Plugin) handleReceiverActions(w http.ResponseWriter, r *http.Request) {
	actions := p.receiverService.GetResponseActions()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"actions": actions,
		"total":   len(actions),
		"source":  "standalone_receiver",
	})
}

// ====================
// Security State Handlers
// ====================

// handleGetSecurityStates returns all user security states
func (p *Plugin) handleGetSecurityStates(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	if p.actionExecutor != nil {
		p.actionExecutor.InitSessionUserStates(sessionID)
	}

	states := p.actionExecutor.GetAllUserStatesForSession(sessionID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"states":     states,
		"total":      len(states),
		"session_id": sessionID,
	})
}

// handleGetSecurityState returns security state for a specific user
func (p *Plugin) handleGetSecurityState(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	email := chi.URLParam(r, "email")
	if email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	// URL decode the email parameter
	decodedEmail, err := decodeURLParam(email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email parameter")
		return
	}

	if p.actionExecutor != nil {
		p.actionExecutor.InitSessionUserStates(sessionID)
	}

	state, err := p.actionExecutor.GetUserStateForSession(sessionID, decodedEmail)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, state)
}

// handleResetSecurityState resets security state for a user
func (p *Plugin) handleResetSecurityState(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	email := chi.URLParam(r, "email")
	if email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	// URL decode the email parameter
	decodedEmail, err := decodeURLParam(email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email parameter")
		return
	}

	var req struct {
		Sessions int `json:"sessions"`
	}
	req.Sessions = 3 // Default sessions

	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	p.actionExecutor.ResetUserStateForSession(sessionID, decodedEmail, req.Sessions)

	state, _ := p.actionExecutor.GetUserStateForSession(sessionID, decodedEmail)
	writeJSON(w, http.StatusOK, state)
}

// decodeURLParam decodes URL-encoded parameters using the standard library
func decodeURLParam(s string) (string, error) {
	return url.QueryUnescape(s)
}
