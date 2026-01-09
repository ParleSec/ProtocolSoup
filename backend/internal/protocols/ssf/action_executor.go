package ssf

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MockIdPActionExecutor executes SSF response actions against the mock IdP
type MockIdPActionExecutor struct {
	idpBaseURL string
	httpClient *http.Client

	// Session-based state tracking - key is "sessionID:email"
	userStates map[string]*UserSecurityState
	stateMu    sync.RWMutex
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
func NewMockIdPActionExecutor(idpBaseURL string) *MockIdPActionExecutor {
	executor := &MockIdPActionExecutor{
		idpBaseURL: idpBaseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		userStates: make(map[string]*UserSecurityState),
	}

	return executor
}

// stateKey generates a session-namespaced key for user state
func stateKey(sessionID, email string) string {
	if sessionID == "" {
		return email // Fallback for legacy/non-session requests
	}
	return sessionID + ":" + email
}

// InitSessionUserStates initializes security states for demo users in a session
func (e *MockIdPActionExecutor) InitSessionUserStates(sessionID string) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	demoUsers := []struct {
		email    string
		sessions int
	}{
		{"alice@example.com", 3},
		{"bob@example.com", 2},
		{"charlie@example.com", 1},
	}

	for _, u := range demoUsers {
		key := stateKey(sessionID, u.email)
		// Only init if not exists
		if _, ok := e.userStates[key]; !ok {
			e.userStates[key] = &UserSecurityState{
				Email:                 u.email,
				SessionID:             sessionID,
				SessionsActive:        u.sessions,
				AccountEnabled:        true,
				PasswordResetRequired: false,
				TokensValid:           true,
				LastModified:          time.Now(),
				ModifiedBy:            "system",
			}
		}
	}
}

// RevokeUserSessions revokes all sessions for a user
func (e *MockIdPActionExecutor) RevokeUserSessions(ctx context.Context, email string) error {
	return e.RevokeUserSessionsForSession(ctx, "", email)
}

// RevokeUserSessionsForSession revokes all sessions for a user in a specific session
func (e *MockIdPActionExecutor) RevokeUserSessionsForSession(ctx context.Context, sessionID, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			SessionID:      sessionID,
			SessionsActive: 0,
			AccountEnabled: true,
			TokensValid:    true,
		}
		e.userStates[key] = state
	}

	previousSessions := state.SessionsActive
	state.SessionsActive = 0
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Revoked %d sessions for %s (session: %s)", previousSessions, email, sessionID)

	return nil
}

// DisableUser disables a user account
func (e *MockIdPActionExecutor) DisableUser(ctx context.Context, email string) error {
	return e.DisableUserForSession(ctx, "", email)
}

// DisableUserForSession disables a user account in a specific session
func (e *MockIdPActionExecutor) DisableUserForSession(ctx context.Context, sessionID, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			SessionID:      sessionID,
			AccountEnabled: false,
		}
		e.userStates[key] = state
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = false
	state.SessionsActive = 0 // Disabling also revokes sessions
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Disabled account for %s (was enabled: %v, session: %s)", email, wasEnabled, sessionID)

	return nil
}

// EnableUser enables a user account
func (e *MockIdPActionExecutor) EnableUser(ctx context.Context, email string) error {
	return e.EnableUserForSession(ctx, "", email)
}

// EnableUserForSession enables a user account in a specific session
func (e *MockIdPActionExecutor) EnableUserForSession(ctx context.Context, sessionID, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			SessionID:      sessionID,
			AccountEnabled: true,
		}
		e.userStates[key] = state
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = true
	state.TokensValid = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Enabled account for %s (was enabled: %v, session: %s)", email, wasEnabled, sessionID)

	return nil
}

// ForcePasswordReset forces a password reset for a user
func (e *MockIdPActionExecutor) ForcePasswordReset(ctx context.Context, email string) error {
	return e.ForcePasswordResetForSession(ctx, "", email)
}

// ForcePasswordResetForSession forces a password reset for a user in a specific session
func (e *MockIdPActionExecutor) ForcePasswordResetForSession(ctx context.Context, sessionID, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		state = &UserSecurityState{
			Email:                 email,
			SessionID:             sessionID,
			AccountEnabled:        true,
			PasswordResetRequired: true,
		}
		e.userStates[key] = state
	}

	state.PasswordResetRequired = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Forced password reset for %s (session: %s)", email, sessionID)

	return nil
}

// InvalidateTokens invalidates all tokens for a user
func (e *MockIdPActionExecutor) InvalidateTokens(ctx context.Context, email string) error {
	return e.InvalidateTokensForSession(ctx, "", email)
}

// InvalidateTokensForSession invalidates all tokens for a user in a specific session
func (e *MockIdPActionExecutor) InvalidateTokensForSession(ctx context.Context, sessionID, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		state = &UserSecurityState{
			Email:       email,
			SessionID:   sessionID,
			TokensValid: false,
		}
		e.userStates[key] = state
	}

	wasValid := state.TokensValid
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Invalidated tokens for %s (were valid: %v, session: %s)", email, wasValid, sessionID)

	return nil
}

// GetUserState returns the current security state for a user (legacy, no session)
func (e *MockIdPActionExecutor) GetUserState(email string) (*UserSecurityState, error) {
	return e.GetUserStateForSession("", email)
}

// GetUserStateForSession returns the current security state for a user in a specific session
func (e *MockIdPActionExecutor) GetUserStateForSession(sessionID, email string) (*UserSecurityState, error) {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()

	key := stateKey(sessionID, email)
	state, ok := e.userStates[key]
	if !ok {
		return nil, fmt.Errorf("user not found: %s (session: %s)", email, sessionID)
	}

	// Return a copy
	stateCopy := *state
	return &stateCopy, nil
}

// GetAllUserStates returns security states for all tracked users (legacy, all sessions)
func (e *MockIdPActionExecutor) GetAllUserStates() map[string]*UserSecurityState {
	return e.GetAllUserStatesForSession("")
}

// GetAllUserStatesForSession returns security states for users in a specific session
func (e *MockIdPActionExecutor) GetAllUserStatesForSession(sessionID string) map[string]*UserSecurityState {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()

	result := make(map[string]*UserSecurityState)
	prefix := sessionID + ":"
	if sessionID == "" {
		// Return all if no session specified (for legacy compatibility)
		for k, v := range e.userStates {
			stateCopy := *v
			result[k] = &stateCopy
		}
		return result
	}

	for k, v := range e.userStates {
		// Filter by session prefix
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			// Use email as key in result (strip session prefix)
			stateCopy := *v
			result[v.Email] = &stateCopy
		}
	}
	return result
}

// ResetUserState resets a user's security state (legacy, no session)
func (e *MockIdPActionExecutor) ResetUserState(email string, sessions int) {
	e.ResetUserStateForSession("", email, sessions)
}

// ResetUserStateForSession resets a user's security state in a specific session
func (e *MockIdPActionExecutor) ResetUserStateForSession(sessionID, email string, sessions int) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	key := stateKey(sessionID, email)
	e.userStates[key] = &UserSecurityState{
		Email:                 email,
		SessionID:             sessionID,
		SessionsActive:        sessions,
		AccountEnabled:        true,
		PasswordResetRequired: false,
		TokensValid:           true,
		LastModified:          time.Now(),
		ModifiedBy:            "system-reset",
	}
}

// CleanupOldSessions removes states for sessions not accessed recently
func (e *MockIdPActionExecutor) CleanupOldSessions(maxAge time.Duration) int {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	count := 0

	for k, v := range e.userStates {
		// Only clean session-based keys (contain ":")
		if strings.Contains(k, ":") && v.LastModified.Before(cutoff) {
			delete(e.userStates, k)
			count++
		}
	}

	return count
}
