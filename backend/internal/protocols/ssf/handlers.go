package ssf

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

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

	// Return empty for legacy behavior (though frontend should always send session)
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

// handleSSFConfiguration returns the SSF transmitter metadata
func (p *Plugin) handleSSFConfiguration(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":   p.baseURL,
		"jwks_uri": p.baseURL + "/ssf/jwks",
		"delivery_methods_supported": []string{
			DeliveryMethodPush,
			DeliveryMethodPoll,
		},
		"configuration_endpoint":   p.baseURL + "/ssf/stream",
		"add_subject_endpoint":     p.baseURL + "/ssf/subjects",
		"remove_subject_endpoint":  p.baseURL + "/ssf/subjects",
		"verification_endpoint":    p.baseURL + "/ssf/verify",
		"status_endpoint":          p.baseURL + "/ssf/status",
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
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL)
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

	stream, err := p.storage.GetDefaultStream(r.Context(), p.baseURL)
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

// ====================
// Subject Management
// ====================

// handleListSubjects returns all subjects
func (p *Plugin) handleListSubjects(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get stream")
			return
		}
		// Ensure demo data exists for this session
		_ = p.storage.SeedSessionDemoData(r.Context(), sessionID, p.baseURL)
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
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL)
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

	writeJSON(w, http.StatusCreated, subject)
}

// handleDeleteSubject removes a subject
func (p *Plugin) handleDeleteSubject(w http.ResponseWriter, r *http.Request) {
	subjectID := chi.URLParam(r, "id")
	if subjectID == "" {
		writeError(w, http.StatusBadRequest, "Subject ID is required")
		return
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
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL)
	} else {
		stream, err = p.storage.GetDefaultStream(r.Context(), p.baseURL)
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

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
		event, err = p.transmitter.TriggerCredentialChangeWithSession(r.Context(), stream.ID, sessionID, subject, credType, initiator)

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
	})
}

// ActionRequest represents a request to trigger an action
type ActionRequest struct {
	SubjectIdentifier string `json:"subject_identifier"`
	Reason            string `json:"reason,omitempty"`
	Initiator         string `json:"initiator,omitempty"`
	CredentialType    string `json:"credential_type,omitempty"`
	CurrentStatus     string `json:"current_status,omitempty"`
	PreviousStatus    string `json:"previous_status,omitempty"`
	NewValue          string `json:"new_value,omitempty"`
}

// ActionResponse represents the response after triggering an action
type ActionResponse struct {
	EventID         string   `json:"event_id"`
	EventType       string   `json:"event_type"`
	EventName       string   `json:"event_name"`
	Category        string   `json:"category"`
	Subject         string   `json:"subject"`
	Status          string   `json:"status"`
	DeliveryMethod  string   `json:"delivery_method"`
	ResponseActions []string `json:"response_actions"`
	ZeroTrustImpact string   `json:"zero_trust_impact"`
}

// ====================
// Event Delivery
// ====================

// handlePush handles push delivery (webhook endpoint)
func (p *Plugin) handlePush(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	response, err := p.receiver.ProcessPushDelivery(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, response)
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

	stream, err := p.storage.GetDefaultStream(r.Context(), p.baseURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get stream")
		return
	}

	sets, moreAvailable, err := p.transmitter.GetPendingEventsForPoll(r.Context(), stream.ID, req.MaxEvents, req.Ack)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// If this is a poll request (not just checking), process the events in receiver
	if len(sets) > 0 {
		p.receiver.ProcessPollResponse(r.Context(), sets)
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
// Event History & Logs
// ====================

// handleGetEvents returns the event history
func (p *Plugin) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	var stream *Stream
	var err error

	if sessionID != "" {
		stream, err = p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL)
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

// handleGetReceivedEvents returns events received by both receivers
func (p *Plugin) handleGetReceivedEvents(w http.ResponseWriter, r *http.Request) {
	// Prefer standalone receiver (production-like)
	events := p.receiverService.GetReceivedEvents()
	source := "standalone_receiver"

	// If no events from standalone, fall back to legacy
	if len(events) == 0 {
		events = p.receiver.GetReceivedEvents()
		source = "legacy_receiver"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  len(events),
		"source": source,
	})
}

// handleGetResponseActions returns the response actions log
func (p *Plugin) handleGetResponseActions(w http.ResponseWriter, r *http.Request) {
	// Prefer standalone receiver (production-like)
	actions := p.receiverService.GetResponseActions()
	source := "standalone_receiver"

	// If no actions from standalone, fall back to legacy
	if len(actions) == 0 {
		actions = p.receiver.GetResponseActions()
		source = "legacy_receiver"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"actions": actions,
		"total":   len(actions),
		"source":  source,
	})
}

// handleClearLogs clears the receiver logs
func (p *Plugin) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	p.receiver.ClearLogs()
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
		"bearer_token":     p.receiverToken[:10] + "...", // Partial for security
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

	// Initialize session states if needed
	if sessionID != "" {
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

	// Initialize session states if needed
	if sessionID != "" {
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

// decodeURLParam decodes URL-encoded parameters
func decodeURLParam(s string) (string, error) {
	// Simple URL decoding for common characters
	result := s
	replacements := map[string]string{
		"%40": "@",
		"%2F": "/",
		"%3A": ":",
		"%2B": "+",
		"%20": " ",
		"%3D": "=",
		"%26": "&",
		"%3F": "?",
	}
	for encoded, decoded := range replacements {
		result = stringReplaceAll(result, encoded, decoded)
	}
	return result, nil
}

func stringReplaceAll(s, old, new string) string {
	for {
		idx := stringIndex(s, old)
		if idx < 0 {
			break
		}
		s = s[:idx] + new + s[idx+len(old):]
	}
	return s
}

func stringIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
