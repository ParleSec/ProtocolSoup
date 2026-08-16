package ssf

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// ====================
// Shared Types (used by ReceiverService and handlers)
// ====================

// ReceivedEvent represents an event received by the receiver
type ReceivedEvent struct {
	ID             string      `json:"id"`
	ReceivedAt     time.Time   `json:"received_at"`
	DeliveryMethod string      `json:"delivery_method"`
	SET            *DecodedSET `json:"set"`
	Verified       bool        `json:"verified"`
	VerifyError    string      `json:"verify_error,omitempty"`
	Processed      bool        `json:"processed"`
	ProcessedAt    *time.Time  `json:"processed_at,omitempty"`
}

// ResponseAction represents an automated response action taken
type ResponseAction struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	ExecutedAt  time.Time `json:"executed_at"`
	SessionID   string    `json:"session_id,omitempty"`
}

// Response action status
const (
	ResponseStatusExecuted      = "executed"
	ResponseStatusPending       = "pending"
	ResponseStatusFailed        = "failed"
	ResponseStatusLogged        = "logged"
	ResponseStatusNotApplicable = "not_applicable"
)

// ReceiverEvent represents events in the receiver pipeline
type ReceiverEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	EventID   string      `json:"event_id"`
	SessionID string      `json:"session_id,omitempty"`
	Data      interface{} `json:"data"`
}

// Receiver event types
const (
	ReceiverEventReceived       = "event_received"
	ReceiverEventVerified       = "event_verified"
	ReceiverEventVerifyFailed   = "event_verify_failed"
	ReceiverEventProcessing     = "event_processing"
	ReceiverEventProcessed      = "event_processed"
	ReceiverEventResponseAction = "response_action"
	ReceiverEventHTTPExchange   = "http_exchange"
)

// SetStatus represents the processing status of a SET
type SetStatus struct {
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	Err         string `json:"err,omitempty"` // RFC 8935 §2.4 / RFC 8936 §2.4 err keyword
}

func failedSET(errCode, description string) SetStatus {
	return SetStatus{Status: "failed", Description: description, Err: errCode}
}

// PollRequest represents an SSF poll request (RFC 8936 §2).
// maxEvents 0 is acknowledge-only. Omitted maxEvents defaults at the handler.
type PollRequest struct {
	Ack               []string           `json:"ack,omitempty"`
	SetErrs           map[string]SETError `json:"setErrs,omitempty"`
	MaxEvents         *int               `json:"maxEvents,omitempty"`
	ReturnImmediately *bool              `json:"returnImmediately,omitempty"`
}

// SETError is an RFC 8936 §2.4 setErrs entry.
type SETError struct {
	Err         string `json:"err"`
	Description string `json:"description,omitempty"`
}

// PollResponse represents an SSF poll response (RFC 8936 §2)
type PollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// ====================
// Shared Event Processing (used by ReceiverService)
// ====================

// ExecuteResponseActions executes security response actions for a decoded event.
// Only actions that mutate RP state are marked executed. Generic strings
// (alert security team, re-evaluate policy) are logged or not_applicable.
func ExecuteResponseActions(executor ActionExecutor, eventID string, event DecodedEvent, subjectEmail, sessionID string) []ResponseAction {
	metadata := event.Metadata
	var actions []ResponseAction

	ctx := context.Background()
	var mutateErr error
	mutated := false
	if executor != nil && subjectEmail != "" {
		switch event.Type {
		case EventTypeSessionRevoked:
			log.Printf("[SSF Receiver] Executing: Revoke sessions for %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
			mutated = true
		case EventTypeAccountDisabled:
			log.Printf("[SSF Receiver] Executing: Disable user %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			mutated = true
		case EventTypeAccountEnabled:
			log.Printf("[SSF Receiver] Executing: Enable user %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.EnableUserForSession(ctx, sessionID, subjectEmail)
			mutated = true
		case EventTypeCredentialCompromise, EventTypeAccountCredentialChangeRequired:
			log.Printf("[SSF Receiver] Executing: Force password reset for %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.ForcePasswordResetForSession(ctx, sessionID, subjectEmail)
			if mutateErr == nil {
				mutateErr = executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
			}
			if mutateErr == nil {
				mutateErr = executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
			}
			mutated = true
		case EventTypeCredentialChange:
			log.Printf("[SSF Receiver] Executing: Invalidate tokens for %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
			mutated = true
		case EventTypeAccountPurged:
			log.Printf("[SSF Receiver] Executing: Disable and revoke for purged %s (session: %s)", subjectEmail, sessionID)
			mutateErr = executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			mutated = true
		}
	}

	primaryMarked := false
	for i, actionDesc := range metadata.ResponseActions {
		executedAt := time.Now()
		status := actionStatusForDescription(actionDesc)
		if mutated && isPrimaryMutationAction(actionDesc) && !primaryMarked {
			if mutateErr != nil {
				status = ResponseStatusFailed
			} else {
				status = ResponseStatusExecuted
			}
			primaryMarked = true
		}

		actions = append(actions, ResponseAction{
			ID:          fmt.Sprintf("%s-action-%d", eventID, i),
			EventID:     eventID,
			EventType:   event.Type,
			Action:      actionDesc,
			Description: fmt.Sprintf("Automated response: %s (session: %s)", actionDesc, sessionID),
			Status:      status,
			ExecutedAt:  executedAt,
			SessionID:   sessionID,
		})
	}

	if mutateErr != nil {
		log.Printf("[SSF Receiver] Action failed: %v", mutateErr)
	}

	return actions
}

func isPrimaryMutationAction(desc string) bool {
	lower := strings.ToLower(desc)
	return containsAnyOf(lower, "terminate") ||
		containsAnyOf(lower, "disable") ||
		containsAnyOf(lower, "suspend") ||
		containsAnyOf(lower, "enable", "reactivate") ||
		containsAnyOf(lower, "password") ||
		(containsAnyOf(lower, "revoke") && containsAnyOf(lower, "token")) ||
		(containsAnyOf(lower, "invalidate") && containsAnyOf(lower, "token"))
}

func actionStatusForDescription(desc string) string {
	lower := strings.ToLower(desc)
	if containsAnyOf(lower, "alert", "notify", "mfa", "quarantine", "isolate", "archive", "audit") {
		return ResponseStatusNotApplicable
	}
	return ResponseStatusLogged
}

// containsAnyOf checks if the already-lowered string s contains any of the substrings.
func containsAnyOf(sLower string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(sLower, sub) {
			return true
		}
	}
	return false
}

// truncateToken returns a truncated preview of a token
