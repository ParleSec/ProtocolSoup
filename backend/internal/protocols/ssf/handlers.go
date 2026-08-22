package ssf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
		"add_subject_endpoint":    p.baseURL + "/ssf/subjects/add",
		"remove_subject_endpoint": p.baseURL + "/ssf/subjects/remove",
		"authorization_schemes": []map[string]string{
			{"spec_urn": "urn:ietf:rfc:6749"},
		},
		"default_subjects": "ALL",
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
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFRead)
	if !ok {
		return
	}

	streamID := strings.TrimSpace(r.URL.Query().Get("stream_id"))
	if streamID == "" {
		streams, err := p.storage.ListStreamsForReceiver(r.Context(), ident.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to list streams")
			return
		}
		writeStreamJSON(w, http.StatusOK, streams)
		return
	}

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}
	writeStreamJSON(w, http.StatusOK, stream)
}

type streamConfigBody struct {
	StreamID        string          `json:"stream_id"`
	EventsRequested []string        `json:"events_requested"`
	Delivery        *StreamDelivery `json:"delivery"`
	Description     string          `json:"description"`
	Status          string          `json:"status"`
}

func requestStreamID(r *http.Request, bodyID string) string {
	if q := strings.TrimSpace(r.URL.Query().Get("stream_id")); q != "" {
		return q
	}
	return strings.TrimSpace(bodyID)
}

func (p *Plugin) ownedStream(ctx context.Context, ident receiverIdentity, streamID string, w http.ResponseWriter) (*Stream, error) {
	stream, err := p.storage.GetStreamByID(ctx, streamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Stream not found")
		return nil, err
	}
	if stream.ReceiverID != ident.ID {
		p.writeBearerError(w, http.StatusForbidden, "insufficient_scope", "the Event Receiver is not allowed to access this stream")
		return nil, fmt.Errorf("forbidden")
	}
	return stream, nil
}

func (p *Plugin) pollEndpointURL(streamID string) string {
	return strings.TrimRight(p.baseURL, "/") + "/ssf/poll/" + streamID
}

// applyTransmitterPollURL sets delivery.endpoint_url for RFC 8936. SSF §6.1.2:
// the URL is specified by the Transmitter and MUST be unique per stream for a
// given Receiver.
func (p *Plugin) applyTransmitterPollURL(stream *Stream) {
	stream.DeliveryMethod = DeliveryMethodPoll
	stream.DeliveryEndpoint = p.pollEndpointURL(stream.ID)
}

func (p *Plugin) applyDelivery(stream *Stream, delivery *StreamDelivery, ident receiverIdentity, w http.ResponseWriter) bool {
	if delivery == nil {
		p.applyTransmitterPollURL(stream)
		return true
	}
	method := delivery.Method
	if method == "" {
		method = DeliveryMethodPoll
	}
	switch method {
	case DeliveryMethodPush:
		stream.DeliveryMethod = DeliveryMethodPush
		if delivery.EndpointURL == "" {
			if strings.HasPrefix(ident.ID, "session:") {
				stream.DeliveryEndpoint = p.receiverEndpoint
			} else {
				writeError(w, http.StatusBadRequest, "delivery.endpoint_url is required for push delivery")
				return false
			}
		} else {
			stream.DeliveryEndpoint = delivery.EndpointURL
		}
		stream.AuthorizationHeader = delivery.AuthorizationHeader
	case DeliveryMethodPoll:
		p.applyTransmitterPollURL(stream)
		stream.AuthorizationHeader = ""
	default:
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid delivery.method: %q (must be %q or %q)", method, DeliveryMethodPush, DeliveryMethodPoll))
		return false
	}
	return true
}

// handleUpdateStream updates stream configuration (SSF §8.1.1). stream_id is REQUIRED.
func (p *Plugin) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

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

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	if update.Delivery != nil {
		if !p.applyDelivery(stream, update.Delivery, ident, w) {
			return
		}
	}
	if update.EventsRequested != nil {
		stream.EventsRequested = update.EventsRequested
	}
	if update.Description != "" {
		stream.Description = update.Description
	}
	if update.Status != "" {
		stream.Status = update.Status
	}

	if err := p.storage.UpdateStream(r.Context(), *stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update stream")
		return
	}

	writeStreamJSON(w, http.StatusOK, stream)
}

// handleReplaceStream replaces stream configuration (SSF §8.1.1.3).
// The stream_id and the full set of Receiver-Supplied properties MUST be present.
func (p *Plugin) handleReplaceStream(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	var req streamConfigBody
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	if issRaw, ok := raw["iss"]; ok {
		var iss string
		if err := json.Unmarshal(issRaw, &iss); err != nil || iss != stream.Issuer {
			writeError(w, http.StatusBadRequest, "Transmitter-Supplied iss MUST match the expected value")
			return
		}
	}
	if deliveredRaw, ok := raw["events_delivered"]; ok {
		var delivered []string
		if err := json.Unmarshal(deliveredRaw, &delivered); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid events_delivered")
			return
		}
		expected := eventsDelivered(stream.EventsSupported, stream.EventsRequested)
		if !equalStringSlices(delivered, expected) {
			writeError(w, http.StatusBadRequest, "events_delivered MUST match the value before the replace")
			return
		}
	}

	if _, ok := raw["delivery"]; !ok {
		p.applyTransmitterPollURL(stream)
		stream.AuthorizationHeader = ""
	} else if !p.applyDelivery(stream, req.Delivery, ident, w) {
		return
	}

	if _, ok := raw["events_requested"]; !ok {
		stream.EventsRequested = nil
	} else {
		stream.EventsRequested = req.EventsRequested
	}
	if _, ok := raw["description"]; !ok {
		stream.Description = ""
	} else {
		stream.Description = req.Description
	}

	if err := p.storage.UpdateStream(r.Context(), *stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to replace stream")
		return
	}

	writeStreamJSON(w, http.StatusOK, stream)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// handleCreateStream creates a new stream per SSF §8.1.1.1.
func (p *Plugin) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	var req streamConfigBody
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}

	eventsRequested := req.EventsRequested
	if len(eventsRequested) == 0 {
		eventsRequested = GetSupportedEventURIs()
	}

	audience := []string{ident.ID}
	if strings.HasPrefix(ident.ID, "session:") || ident.ID == "anonymous" {
		audience = []string{p.baseURL + "/receiver"}
	}

	bearer := ""
	if strings.HasPrefix(ident.ID, "session:") {
		bearer = p.receiverToken
	}

	streamID := generateStreamID()
	stream := Stream{
		ID:                  streamID,
		Issuer:              p.baseURL,
		Audience:            audience,
		EventsSupported:     GetSupportedEventURIs(),
		EventsRequested:     eventsRequested,
		BearerToken:         bearer,
		Status:              StreamStatusEnabled,
		ReceiverID:          ident.ID,
		SessionID:           getSessionID(r),
		Description:         req.Description,
		MinVerificationSecs: p.minVerifyInt,
	}
	if !p.applyDelivery(&stream, req.Delivery, ident, w) {
		return
	}

	if err := p.storage.CreateStream(r.Context(), stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create stream")
		return
	}

	writeStreamJSON(w, http.StatusCreated, stream)
}

// handleDeleteStream deletes a stream. stream_id is REQUIRED (SSF §8.1.1.5).
func (p *Plugin) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

	var req streamConfigBody
	if r.Body != nil && r.Body != http.NoBody {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	if _, err := p.ownedStream(r.Context(), ident, streamID, w); err != nil {
		return
	}

	if err := p.storage.DeleteStream(r.Context(), streamID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete stream")
		return
	}

	writeNoContent(w)
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

type subjectManagementBody struct {
	StreamID string          `json:"stream_id"`
	Subject  json.RawMessage `json:"subject"`
	Verified *bool           `json:"verified"`
}

func (p *Plugin) readSubjectManagement(w http.ResponseWriter, r *http.Request) (receiverIdentity, *Stream, subjectClaim, bool) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return receiverIdentity{}, nil, nil, false
	}
	var req subjectManagementBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return receiverIdentity{}, nil, nil, false
	}
	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return receiverIdentity{}, nil, nil, false
	}
	if len(bytes.TrimSpace(req.Subject)) == 0 {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return receiverIdentity{}, nil, nil, false
	}
	claim, err := parseSubjectClaim(req.Subject)
	if err != nil || stringClaim(claim, "format") == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "subject MUST be an RFC 9493 Subject Identifier")
		return receiverIdentity{}, nil, nil, false
	}
	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return receiverIdentity{}, nil, nil, false
	}
	return ident, stream, claim, true
}

// handleAddSubject implements SSF §8.1.3.1. Success is 200 OK with an empty body.
func (p *Plugin) handleAddSubject(w http.ResponseWriter, r *http.Request) {
	_, stream, claim, ok := p.readSubjectManagement(w, r)
	if !ok {
		return
	}
	if err := p.storage.AddStreamSubject(r.Context(), stream.ID, claim); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add subject")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// handleRemoveSubject implements SSF §8.1.3.2. Success is 204 No Content.
func (p *Plugin) handleRemoveSubject(w http.ResponseWriter, r *http.Request) {
	_, stream, claim, ok := p.readSubjectManagement(w, r)
	if !ok {
		return
	}
	if err := p.storage.RemoveStreamSubject(r.Context(), stream.ID, claim); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to remove subject")
		return
	}
	writeNoContent(w)
}

// ====================
// Action Handlers (Interactive Triggers)
// ====================

var errUnknownAction = errors.New("unknown action")

// handleTriggerAction handles all action triggers. A security event is a
// Transmitter-wide fact: every enabled stream that requested the event type
// and still includes the subject receives a SET (push or poll). Looking Glass
// sessions stay isolated from each other.
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

	if sessionID != "" {
		if _, err := p.storage.GetSessionStream(r.Context(), sessionID, p.baseURL, p.receiverEndpoint, p.receiverToken); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get stream")
			return
		}
	}

	streams, err := p.storage.ListStreams(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list streams")
		return
	}

	var (
		primary       *StoredEvent
		primaryStream *Stream
		delivered     int
		hardErr       error
	)
	for i := range streams {
		stream := streams[i]
		if stream.SessionID != "" && stream.SessionID != sessionID {
			continue
		}
		event, triggerErr := p.triggerActionOnStream(r.Context(), action, stream.ID, sessionID, req)
		if triggerErr != nil {
			if errors.Is(triggerErr, errUnknownAction) {
				writeError(w, http.StatusBadRequest, triggerErr.Error())
				return
			}
			if skippableDeliveryErr(triggerErr) {
				continue
			}
			hardErr = triggerErr
			continue
		}
		delivered++
		if primary == nil || stream.SessionID == sessionID {
			primary = event
			s := stream
			primaryStream = &s
		}
	}

	if primary == nil {
		if hardErr != nil {
			writeError(w, http.StatusInternalServerError, hardErr.Error())
			return
		}
		writeError(w, http.StatusNotFound, "no enabled stream accepts this event")
		return
	}

	metadata := GetEventMetadata(primary.EventType)
	writeJSON(w, http.StatusOK, ActionResponse{
		EventID:          primary.ID,
		EventType:        primary.EventType,
		EventName:        metadata.Name,
		Category:         string(metadata.Category),
		Subject:          req.SubjectIdentifier,
		Status:           primary.Status,
		DeliveryMethod:   primaryStream.DeliveryMethod,
		ResponseActions:  metadata.ResponseActions,
		ZeroTrustImpact:  metadata.ZeroTrustImpact,
		StreamsDelivered: delivered,
	})
}

func (p *Plugin) triggerActionOnStream(ctx context.Context, action, streamID, sessionID string, req ActionRequest) (*StoredEvent, error) {
	subject := SubjectIdentifier{
		Format: SubjectFormatEmail,
		Email:  req.SubjectIdentifier,
	}

	initiator := req.Initiator
	if initiator == "" {
		initiator = InitiatingEntityAdmin
	}

	switch action {
	case "session-revoked":
		reason := req.Reason
		if reason == "" {
			reason = "Session revoked by administrator"
		}
		return p.transmitter.TriggerSessionRevokedWithSession(ctx, streamID, sessionID, subject, reason, initiator)

	case "credential-change":
		credType := req.CredentialType
		if credType == "" {
			credType = CredentialTypePassword
		}
		changeType := req.ChangeType
		if changeType == "" {
			changeType = "update" // CAEP §3.3 default
		}
		return p.transmitter.TriggerCredentialChangeWithSession(ctx, streamID, sessionID, subject, credType, changeType, initiator)

	case "device-compliance-change":
		current := req.CurrentStatus
		previous := req.PreviousStatus
		if current == "" {
			current = ComplianceStatusNonCompliant
		}
		if previous == "" {
			previous = ComplianceStatusCompliant
		}
		return p.transmitter.TriggerDeviceComplianceChangeWithSession(ctx, streamID, sessionID, subject, current, previous)

	case "credential-compromise":
		reason := req.Reason
		if reason == "" {
			reason = "Credentials potentially exposed in data breach"
		}
		credType := req.CredentialType
		if credType == "" {
			credType = CredentialTypePassword
		}
		return p.transmitter.TriggerCredentialCompromiseWithSession(ctx, streamID, sessionID, subject, reason, credType)

	case "account-disabled":
		return p.transmitter.TriggerAccountDisabledWithSession(ctx, streamID, sessionID, subject, req.Reason, initiator)

	case "account-enabled":
		return p.transmitter.TriggerAccountEnabledWithSession(ctx, streamID, sessionID, subject, initiator)

	case "account-purged":
		return p.transmitter.TriggerAccountPurgedWithSession(ctx, streamID, sessionID, subject, initiator)

	case "identifier-changed":
		newValue := req.NewValue
		if newValue == "" {
			newValue = "updated-" + req.SubjectIdentifier
		}
		return p.transmitter.TriggerIdentifierChangedWithSession(ctx, streamID, sessionID, subject,
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
		return p.transmitter.TriggerAssuranceLevelChangeWithSession(ctx, streamID, sessionID, subject, current, previous, namespace)

	case "token-claims-change":
		claims := map[string]interface{}{
			"role":  "viewer",
			"group": []string{"security-team"},
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		}
		if req.CurrentStatus != "" {
			claims["role"] = req.CurrentStatus
		}
		return p.transmitter.TriggerTokenClaimsChangeWithSession(ctx, streamID, sessionID, subject, claims)

	case "identifier-recycled":
		oldValue := req.SubjectIdentifier
		newValue := req.NewValue
		if newValue == "" {
			newValue = "recycled-" + req.SubjectIdentifier
		}
		return p.transmitter.TriggerIdentifierRecycledWithSession(ctx, streamID, sessionID, subject, oldValue, newValue)

	case "account-credential-change-required":
		reason := req.Reason
		if reason == "" {
			reason = "Credential rotation policy triggered"
		}
		return p.transmitter.TriggerAccountCredentialChangeRequiredWithSession(ctx, streamID, sessionID, subject, reason, initiator)

	case "sessions-revoked":
		reason := req.Reason
		if reason == "" {
			reason = "All sessions revoked due to security incident"
		}
		return p.transmitter.TriggerSessionsRevokedWithSession(ctx, streamID, sessionID, subject, reason, initiator)

	default:
		return nil, fmt.Errorf("%w: %s", errUnknownAction, action)
	}
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
	EventID          string   `json:"event_id"`
	EventType        string   `json:"event_type"`
	EventName        string   `json:"event_name"`
	Category         string   `json:"category"`
	Subject          string   `json:"subject"`
	Status           string   `json:"status"`
	DeliveryMethod   string   `json:"delivery_method"`
	ResponseActions  []string `json:"response_actions"`
	ZeroTrustImpact  string   `json:"zero_trust_impact"`
	StreamsDelivered int      `json:"streams_delivered"`
}

// ====================
// Event Delivery
// ====================

// handlePoll handles RFC 8936 poll requests for the stream identified by the
// Transmitter-supplied poll URL (SSF §6.1.2). Acks belong in this POST body.
func (p *Plugin) handlePoll(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFRead)
	if !ok {
		return
	}

	streamID := strings.TrimSpace(chi.URLParam(r, "streamID"))
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}
	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	var req PollRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if ct != "" && !strings.Contains(ct, "application/json") {
			writeError(w, http.StatusBadRequest, "Content-Type MUST be application/json (RFC 8936 §2.2)")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
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

	if len(sets) > 0 && strings.HasPrefix(ident.ID, "session:") {
		p.receiverService.ProcessPollResponse(r.Context(), sets, sessionIDs)
	}

	writeJSON(w, http.StatusOK, PollResponse{
		Sets:          sets,
		MoreAvailable: moreAvailable,
	})
}

// ====================
// Stream Verification (SSF §7)
// ====================

// handleVerification triggers a verification SET per SSF §8.1.4.2.
// Success is 204 No Content with an empty body. stream_id is REQUIRED.
func (p *Plugin) handleVerification(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	var req struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}

	streamID := requestStreamID(r, req.StreamID)
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	interval := stream.MinVerificationSecs
	if interval <= 0 {
		interval = p.minVerifyInt
	}
	if interval > 0 && stream.LastVerificationAt != nil {
		elapsed := time.Since(*stream.LastVerificationAt)
		if elapsed < time.Duration(interval)*time.Second {
			writeError(w, http.StatusTooManyRequests, "verification requests exceed min_verification_interval")
			return
		}
	}

	if _, err := p.transmitter.TriggerVerification(r.Context(), stream.ID, req.State, getSessionID(r)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = p.storage.RecordVerification(r.Context(), stream.ID, time.Now())

	writeNoContent(w)
}

// ====================
// Stream Status (SSF §6)
// ====================

// handleGetStatus returns the current stream status per SSF §6.
func (p *Plugin) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFRead)
	if !ok {
		return
	}

	streamID := strings.TrimSpace(r.URL.Query().Get("stream_id"))
	if streamID == "" {
		writeSSFError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	writeStreamJSON(w, http.StatusOK, map[string]interface{}{
		"stream_id": stream.ID,
		"status":    stream.Status,
	})
}

// handleUpdateStatus updates the stream status per SSF §6.
// Accepts: enabled, paused, disabled.
func (p *Plugin) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ident, ok := p.authenticateReceiver(w, r, ScopeSSFManage)
	if !ok {
		return
	}

	var req struct {
		StreamID string `json:"stream_id"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
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

	switch req.Status {
	case StreamStatusEnabled, StreamStatusPaused, StreamStatusDisabled:
	default:
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("Invalid status: %q (must be enabled, paused, or disabled)", req.Status))
		return
	}

	stream, err := p.ownedStream(r.Context(), ident, streamID, w)
	if err != nil {
		return
	}

	stream.Status = req.Status
	if err := p.storage.UpdateStream(r.Context(), *stream); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update stream status")
		return
	}

	writeStreamJSON(w, http.StatusOK, map[string]interface{}{
		"stream_id": stream.ID,
		"status":    stream.Status,
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

func generateStreamID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
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
