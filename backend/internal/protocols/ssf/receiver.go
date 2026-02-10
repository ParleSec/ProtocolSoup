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
	ResponseStatusExecuted = "executed"
	ResponseStatusPending  = "pending"
	ResponseStatusFailed   = "failed"
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
}

// PollRequest represents an SSF poll request (RFC 8936 §2)
type PollRequest struct {
	Ack               []string `json:"ack,omitempty"`
	MaxEvents         int      `json:"maxEvents,omitempty"`
	ReturnImmediately bool     `json:"returnImmediately,omitempty"`
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
func ExecuteResponseActions(executor ActionExecutor, eventID string, event DecodedEvent, subjectEmail, sessionID string) []ResponseAction {
	metadata := event.Metadata
	var actions []ResponseAction

	for i, actionDesc := range metadata.ResponseActions {
		executedAt := time.Now()
		status := ResponseStatusExecuted

		// Execute real actions if we have an executor
		if executor != nil && subjectEmail != "" {
			ctx := context.Background()
			var err error
			lower := strings.ToLower(actionDesc)
			switch {
			case containsAnyOf(lower, "terminate", "revoke", "session"):
				log.Printf("[SSF Receiver] Executing: Revoke sessions for %s (session: %s)", subjectEmail, sessionID)
				err = executor.RevokeUserSessionsForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "disable", "suspend"):
				log.Printf("[SSF Receiver] Executing: Disable user %s (session: %s)", subjectEmail, sessionID)
				err = executor.DisableUserForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "enable", "reactivate"):
				log.Printf("[SSF Receiver] Executing: Enable user %s (session: %s)", subjectEmail, sessionID)
				err = executor.EnableUserForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "password", "reset"):
				log.Printf("[SSF Receiver] Executing: Force password reset for %s (session: %s)", subjectEmail, sessionID)
				err = executor.ForcePasswordResetForSession(ctx, sessionID, subjectEmail)
			case containsAnyOf(lower, "invalidate", "token"):
				log.Printf("[SSF Receiver] Executing: Invalidate tokens for %s (session: %s)", subjectEmail, sessionID)
				err = executor.InvalidateTokensForSession(ctx, sessionID, subjectEmail)
			default:
				log.Printf("[SSF Receiver] Executing: %s (generic action)", actionDesc)
			}
			if err != nil {
				log.Printf("[SSF Receiver] Action failed: %v", err)
				status = ResponseStatusFailed
			}
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

	return actions
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
