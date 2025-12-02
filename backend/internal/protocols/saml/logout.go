package saml

import (
	"encoding/xml"
	"fmt"
	"sync"
)

// ============================================================================
// Single Logout (SLO) Handler
// ============================================================================

// SLOState tracks the state of a Single Logout operation
type SLOState struct {
	mu             sync.Mutex
	RequestID      string
	InitiatorSP    string
	NameID         string
	NameIDFormat   string
	SessionIndexes []string
	RelayState     string
	
	// Track which SPs have been notified and responded
	PendingSPs   map[string]bool   // SP EntityID -> sent logout request
	CompletedSPs map[string]bool   // SP EntityID -> received logout response
	FailedSPs    map[string]string // SP EntityID -> error message
	
	// Final status
	Complete bool
	Success  bool
}

// NewSLOState creates a new SLO state tracker
func NewSLOState(requestID, initiatorSP, nameID, nameIDFormat string, sessionIndexes []string, relayState string) *SLOState {
	return &SLOState{
		RequestID:      requestID,
		InitiatorSP:    initiatorSP,
		NameID:         nameID,
		NameIDFormat:   nameIDFormat,
		SessionIndexes: sessionIndexes,
		RelayState:     relayState,
		PendingSPs:     make(map[string]bool),
		CompletedSPs:   make(map[string]bool),
		FailedSPs:      make(map[string]string),
	}
}

// AddPendingSP adds an SP to the pending list
func (s *SLOState) AddPendingSP(entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingSPs[entityID] = true
}

// MarkSPComplete marks an SP logout as completed
func (s *SLOState) MarkSPComplete(entityID string, success bool, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	delete(s.PendingSPs, entityID)
	
	if success {
		s.CompletedSPs[entityID] = true
	} else {
		s.FailedSPs[entityID] = errorMsg
	}
	
	// Check if all SPs have responded
	if len(s.PendingSPs) == 0 {
		s.Complete = true
		s.Success = len(s.FailedSPs) == 0
	}
}

// IsComplete checks if the SLO operation is complete
func (s *SLOState) IsComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Complete
}

// GetStatus returns the current status of the SLO operation
func (s *SLOState) GetStatus() (complete bool, success bool, pending int, failed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Complete, s.Success, len(s.PendingSPs), len(s.FailedSPs)
}

// ============================================================================
// Logout Request/Response Processing
// ============================================================================

// LogoutRequestInfo contains parsed information from a LogoutRequest
type LogoutRequestInfo struct {
	ID             string
	Issuer         string
	NameID         string
	NameIDFormat   string
	SessionIndexes []string
	Destination    string
	NotOnOrAfter   string
	Reason         string
}

// ParseLogoutRequest parses a LogoutRequest XML into structured info
func ParseLogoutRequest(xmlData []byte) (*LogoutRequestInfo, error) {
	var request LogoutRequest
	if err := xml.Unmarshal(xmlData, &request); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LogoutRequest: %w", err)
	}
	
	info := &LogoutRequestInfo{
		ID:             request.ID,
		Destination:    request.Destination,
		NotOnOrAfter:   request.NotOnOrAfter,
		Reason:         request.Reason,
		SessionIndexes: request.SessionIndex,
	}
	
	if request.Issuer != nil {
		info.Issuer = request.Issuer.Value
	}
	
	if request.NameID != nil {
		info.NameID = request.NameID.Value
		info.NameIDFormat = request.NameID.Format
	}
	
	return info, nil
}

// LogoutResponseInfo contains parsed information from a LogoutResponse
type LogoutResponseInfo struct {
	ID           string
	Issuer       string
	InResponseTo string
	Destination  string
	StatusCode   string
	StatusMessage string
	Success      bool
}

// ParseLogoutResponse parses a LogoutResponse XML into structured info
func ParseLogoutResponse(xmlData []byte) (*LogoutResponseInfo, error) {
	var response LogoutResponse
	if err := xml.Unmarshal(xmlData, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LogoutResponse: %w", err)
	}
	
	info := &LogoutResponseInfo{
		ID:           response.ID,
		InResponseTo: response.InResponseTo,
		Destination:  response.Destination,
	}
	
	if response.Issuer != nil {
		info.Issuer = response.Issuer.Value
	}
	
	if response.Status != nil {
		info.StatusCode = response.Status.StatusCode.Value
		info.StatusMessage = response.Status.StatusMessage
		info.Success = response.Status.StatusCode.Value == StatusSuccess
	}
	
	return info, nil
}

// ============================================================================
// SLO Manager
// ============================================================================

// SLOManager manages Single Logout operations
type SLOManager struct {
	mu       sync.RWMutex
	states   map[string]*SLOState // RequestID -> State
	byNameID map[string][]string  // NameID -> list of active SLO RequestIDs
}

// NewSLOManager creates a new SLO manager
func NewSLOManager() *SLOManager {
	return &SLOManager{
		states:   make(map[string]*SLOState),
		byNameID: make(map[string][]string),
	}
}

// StartSLO starts a new Single Logout operation
func (m *SLOManager) StartSLO(state *SLOState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.states[state.RequestID] = state
	m.byNameID[state.NameID] = append(m.byNameID[state.NameID], state.RequestID)
}

// GetState retrieves an SLO state by request ID
func (m *SLOManager) GetState(requestID string) *SLOState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.states[requestID]
}

// GetStatesByNameID retrieves all SLO states for a given NameID
func (m *SLOManager) GetStatesByNameID(nameID string) []*SLOState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	requestIDs := m.byNameID[nameID]
	states := make([]*SLOState, 0, len(requestIDs))
	for _, id := range requestIDs {
		if state := m.states[id]; state != nil {
			states = append(states, state)
		}
	}
	return states
}

// CompleteSLO marks an SLO operation as complete and removes it
func (m *SLOManager) CompleteSLO(requestID string) *SLOState {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	state := m.states[requestID]
	if state != nil {
		delete(m.states, requestID)
		
		// Remove from nameID index
		if ids, ok := m.byNameID[state.NameID]; ok {
			for i, id := range ids {
				if id == requestID {
					m.byNameID[state.NameID] = append(ids[:i], ids[i+1:]...)
					break
				}
			}
			if len(m.byNameID[state.NameID]) == 0 {
				delete(m.byNameID, state.NameID)
			}
		}
	}
	
	return state
}

// HandleLogoutResponse processes a logout response from an SP
func (m *SLOManager) HandleLogoutResponse(responseInfo *LogoutResponseInfo) (*SLOState, error) {
	state := m.GetState(responseInfo.InResponseTo)
	if state == nil {
		return nil, fmt.Errorf("no SLO state found for response to: %s", responseInfo.InResponseTo)
	}
	
	errorMsg := ""
	if !responseInfo.Success {
		errorMsg = responseInfo.StatusMessage
		if errorMsg == "" {
			errorMsg = responseInfo.StatusCode
		}
	}
	
	state.MarkSPComplete(responseInfo.Issuer, responseInfo.Success, errorMsg)
	
	return state, nil
}

// ============================================================================
// Logout Reason Constants
// ============================================================================

const (
	LogoutReasonUser          = "urn:oasis:names:tc:SAML:2.0:logout:user"
	LogoutReasonAdmin         = "urn:oasis:names:tc:SAML:2.0:logout:admin"
	LogoutReasonGlobalTimeout = "urn:oasis:names:tc:SAML:2.0:logout:global-timeout"
	LogoutReasonSPTimeout     = "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout"
)

// ============================================================================
// SLO Session Participant
// ============================================================================

// SessionParticipant represents an SP that participated in a session
type SessionParticipant struct {
	EntityID     string
	SLOURL       string
	NameID       string
	NameIDFormat string
	SessionIndex string
	Binding      BindingType
}

// CreateLogoutRequestForParticipant creates a LogoutRequest for a session participant
func CreateLogoutRequestForParticipant(issuer string, participant *SessionParticipant, reason string) *LogoutRequest {
	sessionIndexes := []string{}
	if participant.SessionIndex != "" {
		sessionIndexes = append(sessionIndexes, participant.SessionIndex)
	}
	
	return NewLogoutRequest(
		issuer,
		participant.SLOURL,
		participant.NameID,
		participant.NameIDFormat,
		sessionIndexes,
	)
}

