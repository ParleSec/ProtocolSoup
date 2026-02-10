package ssf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// MockIdPActionExecutor executes SSF response actions against persisted state
type MockIdPActionExecutor struct {
	baseURL          string
	storage          *Storage
	receiverEndpoint string
	receiverToken    string
}

// UserSecurityState tracks the security state of a user
type UserSecurityState struct {
	Email                 string    `json:"email"`
	SessionID             string    `json:"session_id,omitempty"`
	SessionsActive        int       `json:"sessions_active"`
	AccountEnabled        bool      `json:"account_enabled"`
	PasswordResetRequired bool      `json:"password_reset_required"`
	TokensValid           bool      `json:"tokens_valid"`
	LastModified          time.Time `json:"last_modified"`
	ModifiedBy            string    `json:"modified_by"`
}

// NewMockIdPActionExecutor creates a new action executor
func NewMockIdPActionExecutor(storage *Storage, baseURL, receiverEndpoint, receiverToken string) *MockIdPActionExecutor {
	return &MockIdPActionExecutor{
		baseURL:          baseURL,
		storage:          storage,
		receiverEndpoint: receiverEndpoint,
		receiverToken:    receiverToken,
	}
}

func (e *MockIdPActionExecutor) streamForSession(ctx context.Context, sessionID string) (*Stream, error) {
	if sessionID != "" {
		return e.storage.GetSessionStream(ctx, sessionID, e.baseURL, e.receiverEndpoint, e.receiverToken)
	}
	return e.storage.GetDefaultStream(ctx, e.baseURL)
}

func (e *MockIdPActionExecutor) ensureUserState(ctx context.Context, sessionID, streamID, email string, sessions int) {
	if _, err := e.storage.GetSecurityState(ctx, streamID, email); err == nil {
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		log.Printf("[ActionExecutor] Failed to load security state for %s: %v", redactIdentifier(email), err)
		return
	}

	state := UserSecurityState{
		Email:                 email,
		SessionID:             sessionID,
		SessionsActive:        sessions,
		AccountEnabled:        true,
		PasswordResetRequired: false,
		TokensValid:           true,
		LastModified:          time.Now(),
		ModifiedBy:            "system",
	}

	if err := e.storage.UpsertSecurityState(ctx, streamID, state); err != nil {
		log.Printf("[ActionExecutor] Failed to seed security state for %s: %v", redactIdentifier(email), err)
	}
}

func (e *MockIdPActionExecutor) getOrCreateState(ctx context.Context, sessionID, email string) (*UserSecurityState, string, error) {
	stream, err := e.streamForSession(ctx, sessionID)
	if err != nil {
		return nil, "", err
	}

	state, err := e.storage.GetSecurityState(ctx, stream.ID, email)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, "", err
		}
		state = &UserSecurityState{
			Email:                 email,
			SessionID:             sessionID,
			SessionsActive:        0,
			AccountEnabled:        true,
			PasswordResetRequired: false,
			TokensValid:           true,
			LastModified:          time.Now(),
			ModifiedBy:            "system",
		}
		if err := e.storage.UpsertSecurityState(ctx, stream.ID, *state); err != nil {
			return nil, "", err
		}
	}

	state.SessionID = sessionID
	return state, stream.ID, nil
}

func (e *MockIdPActionExecutor) updateSubjectState(ctx context.Context, streamID, email string, sessionsActive int, accountEnabled bool) {
	subject, err := e.storage.GetSubjectByIdentifier(ctx, streamID, SubjectFormatEmail, email)
	if err != nil {
		return
	}

	subject.ActiveSessions = sessionsActive
	if accountEnabled {
		subject.Status = SubjectStatusActive
	} else {
		subject.Status = SubjectStatusDisabled
	}
	now := time.Now()
	subject.LastActivity = &now
	_ = e.storage.UpdateSubject(ctx, *subject)
}

// InitSessionUserStates initializes security states for demo users in a session
func (e *MockIdPActionExecutor) InitSessionUserStates(sessionID string) {
	ctx := context.Background()
	stream, err := e.streamForSession(ctx, sessionID)
	if err != nil {
		log.Printf("[ActionExecutor] Failed to load stream for session %s: %v", sessionID, err)
		return
	}

	subjects, err := e.storage.ListSubjects(ctx, stream.ID)
	if err != nil {
		log.Printf("[ActionExecutor] Failed to list subjects for session %s: %v", sessionID, err)
		return
	}

	for _, subject := range subjects {
		e.ensureUserState(ctx, sessionID, stream.ID, subject.Identifier, subject.ActiveSessions)
	}
}

// RevokeUserSessions revokes all sessions for a user
func (e *MockIdPActionExecutor) RevokeUserSessions(ctx context.Context, email string) error {
	return e.RevokeUserSessionsForSession(ctx, "", email)
}

// RevokeUserSessionsForSession revokes all sessions for a user in a specific session
func (e *MockIdPActionExecutor) RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error {
	state, streamID, err := e.getOrCreateState(ctx, sessionID, email)
	if err != nil {
		return err
	}

	previousSessions := state.SessionsActive
	state.SessionsActive = 0
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	if err := e.storage.UpsertSecurityState(ctx, streamID, *state); err != nil {
		return err
	}
	e.updateSubjectState(ctx, streamID, email, state.SessionsActive, state.AccountEnabled)

	log.Printf("[ActionExecutor] Revoked %d sessions for %s (session: %s)", previousSessions, redactIdentifier(email), redactSessionID(sessionID))
	return nil
}

// DisableUser disables a user account
func (e *MockIdPActionExecutor) DisableUser(ctx context.Context, email string) error {
	return e.DisableUserForSession(ctx, "", email)
}

// DisableUserForSession disables a user account in a specific session
func (e *MockIdPActionExecutor) DisableUserForSession(ctx context.Context, sessionID, email string) error {
	state, streamID, err := e.getOrCreateState(ctx, sessionID, email)
	if err != nil {
		return err
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = false
	state.SessionsActive = 0
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	if err := e.storage.UpsertSecurityState(ctx, streamID, *state); err != nil {
		return err
	}
	e.updateSubjectState(ctx, streamID, email, state.SessionsActive, state.AccountEnabled)

	log.Printf("[ActionExecutor] Disabled account for %s (was enabled: %v, session: %s)", redactIdentifier(email), wasEnabled, redactSessionID(sessionID))
	return nil
}

// EnableUser enables a user account
func (e *MockIdPActionExecutor) EnableUser(ctx context.Context, email string) error {
	return e.EnableUserForSession(ctx, "", email)
}

// EnableUserForSession enables a user account in a specific session
func (e *MockIdPActionExecutor) EnableUserForSession(ctx context.Context, sessionID, email string) error {
	state, streamID, err := e.getOrCreateState(ctx, sessionID, email)
	if err != nil {
		return err
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = true
	state.TokensValid = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	if err := e.storage.UpsertSecurityState(ctx, streamID, *state); err != nil {
		return err
	}
	e.updateSubjectState(ctx, streamID, email, state.SessionsActive, state.AccountEnabled)

	log.Printf("[ActionExecutor] Enabled account for %s (was enabled: %v, session: %s)", redactIdentifier(email), wasEnabled, redactSessionID(sessionID))
	return nil
}

// ForcePasswordReset forces a password reset for a user
func (e *MockIdPActionExecutor) ForcePasswordReset(ctx context.Context, email string) error {
	return e.ForcePasswordResetForSession(ctx, "", email)
}

// ForcePasswordResetForSession forces a password reset for a user in a specific session
func (e *MockIdPActionExecutor) ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error {
	state, streamID, err := e.getOrCreateState(ctx, sessionID, email)
	if err != nil {
		return err
	}

	state.PasswordResetRequired = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	if err := e.storage.UpsertSecurityState(ctx, streamID, *state); err != nil {
		return err
	}

	log.Printf("[ActionExecutor] Forced password reset for %s (session: %s)", redactIdentifier(email), redactSessionID(sessionID))
	return nil
}

// InvalidateTokens invalidates all tokens for a user
func (e *MockIdPActionExecutor) InvalidateTokens(ctx context.Context, email string) error {
	return e.InvalidateTokensForSession(ctx, "", email)
}

// InvalidateTokensForSession invalidates all tokens for a user in a specific session
func (e *MockIdPActionExecutor) InvalidateTokensForSession(ctx context.Context, sessionID, email string) error {
	state, streamID, err := e.getOrCreateState(ctx, sessionID, email)
	if err != nil {
		return err
	}

	wasValid := state.TokensValid
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	if err := e.storage.UpsertSecurityState(ctx, streamID, *state); err != nil {
		return err
	}

	log.Printf("[ActionExecutor] Invalidated tokens for %s (were valid: %v, session: %s)", redactIdentifier(email), wasValid, redactSessionID(sessionID))
	return nil
}

// GetUserStateForSession returns the current security state for a user in a specific session
func (e *MockIdPActionExecutor) GetUserStateForSession(sessionID, email string) (*UserSecurityState, error) {
	stream, err := e.streamForSession(context.Background(), sessionID)
	if err != nil {
		return nil, err
	}

	state, err := e.storage.GetSecurityState(context.Background(), stream.ID, email)
	if err != nil {
		return nil, fmt.Errorf("user not found: %s (session: %s)", email, sessionID)
	}
	state.SessionID = sessionID
	return state, nil
}

// GetAllUserStatesForSession returns security states for users in a specific session
func (e *MockIdPActionExecutor) GetAllUserStatesForSession(sessionID string) map[string]*UserSecurityState {
	stream, err := e.streamForSession(context.Background(), sessionID)
	if err != nil {
		return map[string]*UserSecurityState{}
	}

	states, err := e.storage.ListSecurityStates(context.Background(), stream.ID)
	if err != nil {
		return map[string]*UserSecurityState{}
	}

	for _, state := range states {
		state.SessionID = sessionID
	}
	return states
}

// ResetUserStateForSession resets a user's security state in a specific session
func (e *MockIdPActionExecutor) ResetUserStateForSession(sessionID, email string, sessions int) {
	ctx := context.Background()
	stream, err := e.streamForSession(ctx, sessionID)
	if err != nil {
		return
	}

	state := UserSecurityState{
		Email:                 email,
		SessionID:             sessionID,
		SessionsActive:        sessions,
		AccountEnabled:        true,
		PasswordResetRequired: false,
		TokensValid:           true,
		LastModified:          time.Now(),
		ModifiedBy:            "system-reset",
	}
	_ = e.storage.UpsertSecurityState(ctx, stream.ID, state)
	e.updateSubjectState(ctx, stream.ID, email, sessions, true)
}

// CleanupOldSessions removes states for sessions not accessed recently
func (e *MockIdPActionExecutor) CleanupOldSessions(maxAge time.Duration) int {
	count, err := e.storage.CleanupSecurityStates(context.Background(), maxAge)
	if err != nil {
		log.Printf("[ActionExecutor] Cleanup failed: %v", err)
		return 0
	}
	return count
}

func redactIdentifier(identifier string) string {
	if identifier == "" {
		return "<redacted>"
	}
	parts := strings.SplitN(identifier, "@", 2)
	if len(parts) != 2 {
		return "<redacted>"
	}
	local := parts[0]
	domain := parts[1]
	if len(local) <= 2 {
		return "***@" + domain
	}
	return local[:2] + "***@" + domain
}

func redactSessionID(sessionID string) string {
	if sessionID == "" {
		return "<none>"
	}
	if len(sessionID) <= 6 {
		return "***"
	}
	return sessionID[:6] + "..."
}
