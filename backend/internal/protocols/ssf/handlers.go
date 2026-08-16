package ssf

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// getSessionID extracts or generates a session ID from the request
func getSessionID(r *http.Request) string {
	if sessionID := r.Header.Get(lookingGlassSessionHeader); sessionID != "" {
		return sessionID
	}
	return r.URL.Query().Get("lg_session")
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

// handleSSFConfiguration returns transmitter metadata per OpenID SSF 1.0 Final §7.1.
// spec_version is "1_0". events_supported belongs on the stream, not here.
// critical_subject_members are Complex Subject member names (SSF §3).
func (p *Plugin) handleSSFConfiguration(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"spec_version": "1_0",
		"issuer":       p.baseURL,
		"jwks_uri":     p.baseURL + "/ssf/jwks",
		"delivery_methods_supported": []string{
			DeliveryMethodPush,
			DeliveryMethodPoll,
		},
		"configuration_endpoint":  p.baseURL + "/ssf/stream",
		"status_endpoint":         p.baseURL + "/ssf/status",
		"verification_endpoint":   p.baseURL + "/ssf/verify",
		"add_subject_endpoint":    p.baseURL + "/ssf/subjects",
		"remove_subject_endpoint": p.baseURL + "/ssf/subjects",
		"critical_subject_members": []string{
			"user",
			"device",
			"session",
		},
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

// handleGetStream returns stream configuration (SSF §8.1.1.2).
// Without stream_id the Transmitter returns a list. With stream_id, one stream or 404.
func (p *Plugin) handleGetStream(w http.ResponseWriter, r *http.Request) {
	streamID := strings.TrimSpace(r.URL.Query().Get("stream_id"))
	if streamID == "" {
		streams, err := p.listStreamsForRequest(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to list streams")
			return
		}
		writeJSON(w, http.StatusOK, streams)
		return
	}

	stream, err := p.getStreamForRequest(r, streamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return
	}
	writeJSON(w, http.StatusOK, stream)
}

type streamConfigBody struct {
	StreamID        string          `json:"stream_id"`
	EventsRequested []string        `json:"events_requested"`
	Delivery        *StreamDelivery `json:"delivery"`
	Status          string          `json:"status"`
}

func requestStreamID(r *http.Request, bodyID string) string {
	if q := strings.TrimSpace(r.URL.Query().Get("stream_id")); q != "" {
		return q
	}
	return strings.TrimSpace(bodyID)
}

func (p *Plugin) listStreamsForRequest(r *http.Request) ([]Stream, error) {
	sessionID := getSessionID(r)
	if sessionID != "" {
		stream, err := p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken)
		if err != nil {
			return nil, err
		}
		return []Stream{*stream}, nil
	}
	return p.storage.ListStreams(r.Context())
}

func (p *Plugin) getStreamForRequest(r *http.Request, streamID string) (*Stream, error) {
	stream, err := p.storage.GetStream(r.Context(), streamID)
	if err != nil {
		return nil, err
	}
	if sessionID := getSessionID(r); sessionID != "" && stream.ID != "session-"+sessionID {
		return nil, fmt.Errorf("stream not found")
	}
	return stream, nil
}

// handleUpdateStream updates stream configuration (SSF §8.1.1). stream_id is REQUIRED.
func (p *Plugin) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	var update streamConfigBody
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	streamID := requestStreamID(r, update.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	stream, err := p.getStreamForRequest(r, streamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return
	}

	if update.Delivery != nil {
		if update.Delivery.Method != "" {
			switch update.Delivery.Method {
			case DeliveryMethodPush, DeliveryMethodPoll:
				stream.DeliveryMethod = update.Delivery.Method
			default:
				writeError(w, http.StatusBadRequest,
					fmt.Sprintf("Invalid delivery.method: %q (must be %q or %q)", update.Delivery.Method, DeliveryMethodPush, DeliveryMethodPoll))
				return
			}
		}
		if update.Delivery.EndpointURL != "" {
			stream.DeliveryEndpoint = update.Delivery.EndpointURL
		}
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

// handleCreateStream creates a new stream per SSF §8.1.1.
func (p *Plugin) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var req streamConfigBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Delivery == nil || req.Delivery.Method == "" {
		writeError(w, http.StatusBadRequest, "delivery.method is required")
		return
	}

	switch req.Delivery.Method {
	case DeliveryMethodPush, DeliveryMethodPoll:
	default:
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid delivery.method: %q (must be %q or %q)", req.Delivery.Method, DeliveryMethodPush, DeliveryMethodPoll))
		return
	}

	if req.Delivery.Method == DeliveryMethodPush && req.Delivery.EndpointURL == "" {
		writeError(w, http.StatusBadRequest, "delivery.endpoint_url is required for push delivery")
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
		DeliveryMethod:   req.Delivery.Method,
		DeliveryEndpoint: req.Delivery.EndpointURL,
		Status:           StreamStatusEnabled,
	}

	if err := p.storage.CreateStream(r.Context(), stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create stream")
		return
	}

	writeJSON(w, http.StatusCreated, stream)
}

// handleDeleteStream deletes a stream. stream_id is REQUIRED (SSF §8.1.1).
func (p *Plugin) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	var req streamConfigBody
	if r.Body != nil && r.Body != http.NoBody {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	if _, err := p.getStreamForRequest(r, streamID); err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return
	}

	if err := p.storage.DeleteStream(r.Context(), streamID); err != nil {
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
			changeType = "update" // CAEP §3.3 default
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
		credType := req.CredentialType
		if credType == "" {
			credType = CredentialTypePassword
		}
		event, err = p.transmitter.TriggerCredentialCompromiseWithSession(r.Context(), stream.ID, sessionID, subject, reason, credType)

	case "account-disabled":
		reason := req.Reason
		event, err = p.transmitter.TriggerAccountDisabledWithSession(r.Context(), stream.ID, sessionID, subject, reason, initiator)

	case "account-enabled":
		event, err = p.transmitter.TriggerAccountEnabledWithSession(r.Context(), stream.ID, sessionID, subject, initiator)

	case "account-purged":
		event, err = p.transmitter.TriggerAccountPurgedWithSession(r.Context(), stream.ID, sessionID, subject, initiator)

	case "identifier-changed":
		newValue := req.NewValue
		if newValue == "" {
			// Default: simulate an email change for the subject
			newValue = "updated-" + req.SubjectIdentifier
		}
		event, err = p.transmitter.TriggerIdentifierChangedWithSession(r.Context(), stream.ID, sessionID, subject,
			req.SubjectIdentifier, newValue, initiator)

	case "assurance-level-change":
		current := req.CurrentStatus
		previous := req.PreviousStatus
		if current == "" {
			current = "aal1"
		}
		if previous == "" {
			previous = "aal2"
		}
		namespace := req.Namespace
		if namespace == "" {
			namespace = AssuranceNamespaceNIST
		}
		event, err = p.transmitter.TriggerAssuranceLevelChangeWithSession(r.Context(), stream.ID, sessionID, subject, current, previous, namespace)

	case "token-claims-change":
		// CAEP §3.2: claims is a JSON object of changed claim names -> new values
		claims := map[string]interface{}{
			"role":  "viewer",
			"group": []string{"security-team"},
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		}
		if req.CurrentStatus != "" {
			claims["role"] = req.CurrentStatus // allow overriding via request
		}
		event, err = p.transmitter.TriggerTokenClaimsChangeWithSession(r.Context(), stream.ID, sessionID, subject, claims)

	case "identifier-recycled":
		oldValue := req.SubjectIdentifier // current subject is the new holder
		newValue := req.NewValue
		if newValue == "" {
			newValue = "recycled-" + req.SubjectIdentifier // show what the identifier was reassigned to
		}
		event, err = p.transmitter.TriggerIdentifierRecycledWithSession(r.Context(), stream.ID, sessionID, subject, oldValue, newValue)

	case "account-credential-change-required":
		reason := req.Reason
		if reason == "" {
			reason = "Credential rotation policy triggered"
		}
		event, err = p.transmitter.TriggerAccountCredentialChangeRequiredWithSession(r.Context(), stream.ID, sessionID, subject, reason, initiator)

	case "sessions-revoked":
		// RISC §2.11: emit CAEP session-revoked for all sessions, not RISC sessions-revoked.
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
	ChangeType        string `json:"change_type,omitempty"` // CAEP §3.3: create | revoke | update | delete
	CurrentStatus     string `json:"current_status,omitempty"`
	PreviousStatus    string `json:"previous_status,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
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
	ZeroTrustImpact string   `json:"zero_trust_impact"`
}

// ====================
// Event Delivery
// ====================

// handlePoll handles RFC 8936 poll requests. /ssf/ack remains a thin alias
// that does not replace poll acks (acks belong in the next poll body).
func (p *Plugin) handlePoll(w http.ResponseWriter, r *http.Request) {
	var req PollRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req = PollRequest{}
		}
	}

	maxEvents := 10
	if req.MaxEvents != nil {
		if *req.MaxEvents == 0 {
			maxEvents = 0
		} else if *req.MaxEvents > 0 {
			maxEvents = *req.MaxEvents
		}
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

	returnImmediately := true
	if req.ReturnImmediately != nil {
		returnImmediately = *req.ReturnImmediately
	}

	sets, sessionIDs, moreAvailable, err := p.transmitter.GetPendingEventsForPoll(r.Context(), stream.ID, maxEvents, req.Ack, req.SetErrs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !returnImmediately && maxEvents > 0 && len(sets) == 0 {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-r.Context().Done():
				writeJSON(w, http.StatusOK, PollResponse{Sets: map[string]string{}, MoreAvailable: false})
				return
			case <-time.After(50 * time.Millisecond):
			}
			sets, sessionIDs, moreAvailable, err = p.transmitter.GetPendingEventsForPoll(r.Context(), stream.ID, maxEvents, nil, nil)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if len(sets) > 0 {
				break
			}
		}
	}

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

// handleVerification triggers a verification SET per SSF §8.1.4.2.
// Success is 204 No Content with an empty body. stream_id is REQUIRED.
func (p *Plugin) handleVerification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	if req.State == "" {
		writeError(w, http.StatusBadRequest, "state is required per SSF §8.1.4")
		return
	}

	stream, err := p.getStreamForRequest(r, streamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return
	}

	if _, err := p.transmitter.TriggerVerification(r.Context(), stream.ID, req.State, getSessionID(r)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

// writeSSFError writes an error response per RFC 8935 §2.3 / §2.4.
// The wire format is {"err":"<code>","description":"<text>"}. Codes:
// invalid_request, invalid_key, invalid_issuer, invalid_audience,
// authentication_failed, access_denied.
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
		"endpoint":         p.receiverEndpoint,
		"transmitter_url":  p.baseURL,
		"bearer_token":     "configured", // Never expose token material, even partially
		"events_received":  len(p.receiverService.GetReceivedEvents()),
		"actions_executed": len(p.receiverService.GetResponseActions()),
	}
	writeJSON(w, http.StatusOK, status)
}

// handleReceiverPushProxy proxies push delivery requests from the transmitter
// to the standalone receiver service running on localhost:{receiverPort}.
// This keeps only port 8080 exposed in production while maintaining real HTTP
// traffic between transmitter and receiver.
func (p *Plugin) handleReceiverPushProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := fmt.Sprintf("http://localhost:%d/ssf/push", p.receiverPort)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to read request body")
		return
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "Failed to create proxy request")
		return
	}

	// Forward all headers from the original request
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("Receiver unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	// Forward response headers and status
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	_, _ = w.Write(respBody)
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
