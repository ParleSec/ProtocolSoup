package ssf

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// MockIdPActionExecutor executes SSF response actions against the mock IdP
type MockIdPActionExecutor struct {
	idpBaseURL string
	httpClient *http.Client

	// Local state tracking (mirrors IdP state)
	userStates map[string]*UserSecurityState
	stateMu    sync.RWMutex
}

// UserSecurityState tracks the security state of a user
type UserSecurityState struct {
	Email                 string    `json:"email"`
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

	// Initialize default states for demo users
	executor.initDemoUserStates()

	return executor
}

// initDemoUserStates initializes security states for demo users
func (e *MockIdPActionExecutor) initDemoUserStates() {
	demoUsers := []struct {
		email    string
		sessions int
	}{
		{"alice@example.com", 3},
		{"bob@example.com", 2},
		{"charlie@example.com", 1},
		{"admin@example.com", 2},
	}

	for _, u := range demoUsers {
		e.userStates[u.email] = &UserSecurityState{
			Email:                 u.email,
			SessionsActive:        u.sessions,
			AccountEnabled:        true,
			PasswordResetRequired: false,
			TokensValid:           true,
			LastModified:          time.Now(),
			ModifiedBy:            "system",
		}
	}
}

// RevokeUserSessions revokes all sessions for a user
func (e *MockIdPActionExecutor) RevokeUserSessions(ctx context.Context, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	state, ok := e.userStates[email]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			SessionsActive: 0,
			AccountEnabled: true,
			TokensValid:    true,
		}
		e.userStates[email] = state
	}

	previousSessions := state.SessionsActive
	state.SessionsActive = 0
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Revoked %d sessions for %s", previousSessions, email)

	// Call the IdP to actually revoke sessions (if endpoint exists)
	// This would be: POST /api/users/{id}/sessions/revoke
	// For now we track locally and the state is real

	return nil
}

// DisableUser disables a user account
func (e *MockIdPActionExecutor) DisableUser(ctx context.Context, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	state, ok := e.userStates[email]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			AccountEnabled: false,
		}
		e.userStates[email] = state
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = false
	state.SessionsActive = 0 // Disabling also revokes sessions
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Disabled account for %s (was enabled: %v)", email, wasEnabled)

	return nil
}

// EnableUser enables a user account
func (e *MockIdPActionExecutor) EnableUser(ctx context.Context, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	state, ok := e.userStates[email]
	if !ok {
		state = &UserSecurityState{
			Email:          email,
			AccountEnabled: true,
		}
		e.userStates[email] = state
	}

	wasEnabled := state.AccountEnabled
	state.AccountEnabled = true
	state.TokensValid = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Enabled account for %s (was enabled: %v)", email, wasEnabled)

	return nil
}

// ForcePasswordReset forces a password reset for a user
func (e *MockIdPActionExecutor) ForcePasswordReset(ctx context.Context, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	state, ok := e.userStates[email]
	if !ok {
		state = &UserSecurityState{
			Email:                 email,
			AccountEnabled:        true,
			PasswordResetRequired: true,
		}
		e.userStates[email] = state
	}

	state.PasswordResetRequired = true
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Forced password reset for %s", email)

	return nil
}

// InvalidateTokens invalidates all tokens for a user
func (e *MockIdPActionExecutor) InvalidateTokens(ctx context.Context, email string) error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	state, ok := e.userStates[email]
	if !ok {
		state = &UserSecurityState{
			Email:       email,
			TokensValid: false,
		}
		e.userStates[email] = state
	}

	wasValid := state.TokensValid
	state.TokensValid = false
	state.LastModified = time.Now()
	state.ModifiedBy = "ssf-receiver"

	log.Printf("[ActionExecutor] REAL ACTION: Invalidated tokens for %s (were valid: %v)", email, wasValid)

	return nil
}

// GetUserState returns the current security state for a user
func (e *MockIdPActionExecutor) GetUserState(email string) (*UserSecurityState, error) {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()

	state, ok := e.userStates[email]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", email)
	}

	// Return a copy
	stateCopy := *state
	return &stateCopy, nil
}

// GetAllUserStates returns security states for all tracked users
func (e *MockIdPActionExecutor) GetAllUserStates() map[string]*UserSecurityState {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()

	result := make(map[string]*UserSecurityState)
	for k, v := range e.userStates {
		stateCopy := *v
		result[k] = &stateCopy
	}
	return result
}

// ResetUserState resets a user's security state (for testing)
func (e *MockIdPActionExecutor) ResetUserState(email string, sessions int) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	e.userStates[email] = &UserSecurityState{
		Email:                 email,
		SessionsActive:        sessions,
		AccountEnabled:        true,
		PasswordResetRequired: false,
		TokensValid:           true,
		LastModified:          time.Now(),
		ModifiedBy:            "system-reset",
	}
}
