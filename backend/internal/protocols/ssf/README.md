# Shared Signals Framework (SSF) Implementation

A standards-based implementation of the [OpenID Shared Signals Framework](https://openid.net/specs/openid-sse-framework-1_0.html) for real-time security event sharing between identity providers and relying parties.

## Overview

This implementation provides:

- **Transmitter**: Generates and delivers Security Event Tokens (SETs) to receivers
- **Receiver**: Validates, processes, and executes response actions based on received SETs
- **Action Executor**: Performs real security state changes (session revocation, account disabling, etc.)
- **Session Isolation**: Each user session gets an isolated sandbox for demonstration purposes

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SSF Architecture                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐         SET (JWT)          ┌─────────────────────────┐ │
│  │   TRANSMITTER   │ ─────────────────────────> │       RECEIVER          │ │
│  │   (Port 8080)   │         Push/Poll          │   (Internal Endpoint)   │ │
│  │                 │                            │                         │ │
│  │ • Event Gen     │                            │ • JWKS Fetch            │ │
│  │ • SET Signing   │                            │ • Signature Verify      │ │
│  │ • Delivery      │                            │ • Session Extraction    │ │
│  └────────┬────────┘                            └───────────┬─────────────┘ │
│           │                                                 │               │
│           │                                                 │               │
│           V                                                 V               │
│  ┌─────────────────┐                            ┌─────────────────────────┐ │
│  │    STORAGE      │                            │   ACTION EXECUTOR       │ │
│  │   (SQLite)      │                            │   (Mock IdP)            │ │
│  │                 │                            │                         │ │
│  │ • Streams       │                            │ • Session Revocation    │ │
│  │ • Subjects      │                            │ • Account Disable/Enable│ │
│  │ • Events        │                            │ • Token Invalidation    │ │
│  │ • Sessions      │                            │ • Password Reset        │ │
│  └─────────────────┘                            └─────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Session-Based Isolation

Each frontend user session gets an isolated sandbox:

1. **Session ID Generation**: Frontend generates a unique session ID stored in `localStorage`
2. **Header Propagation**: All requests include `X-SSF-Session` header
3. **SET Claims**: Session ID is embedded in the SET as `ssf_session_id` claim
4. **State Isolation**: Action executor uses `sessionID:email` composite keys for state

```
Frontend                    Backend                     Receiver
   │                           │                           │
   │  X-SSF-Session: sess_abc  │                           │
   │ ─────────────────────────>│                           │
   │                           │                           │
   │                           │  SET with ssf_session_id  │
   │                           │ ─────────────────────────>│
   │                           │                           │
   │                           │                           │ Extract sessionID
   │                           │                           │ from SET claims
   │                           │                           │
   │                           │                           │ Update state for
   │                           │                           │ "sess_abc:alice@..."
   │                           │                           │
```

## Supported Events

### CAEP (Continuous Access Evaluation Profile)

| Event | URI | Description |
|-------|-----|-------------|
| Session Revoked | `session-revoked` | Single session terminated |
| Token Claims Change | `token-claims-change` | Token claims modified |
| Credential Change | `credential-change` | User credentials updated |
| Assurance Level Change | `assurance-level-change` | Authentication assurance changed |
| Device Compliance Change | `device-compliance-change` | Device compliance status changed |

### RISC (Risk Incident Sharing and Coordination)

| Event | URI | Description |
|-------|-----|-------------|
| Sessions Revoked | `sessions-revoked` | All sessions terminated |
| Account Disabled | `account-disabled` | Account suspended |
| Account Enabled | `account-enabled` | Account reactivated |
| Account Purged | `account-purged` | Account permanently deleted |
| Identifier Changed | `identifier-changed` | Primary identifier modified |
| Credential Compromise | `credential-compromise` | Credentials potentially exposed |

## API Endpoints

### Configuration & Discovery

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/info` | GET | Plugin information |
| `/ssf/.well-known/ssf-configuration` | GET | SSF transmitter metadata |
| `/ssf/jwks` | GET | Public keys for SET verification |

### Stream Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/stream` | GET | Get stream configuration |
| `/ssf/stream` | PUT | Update stream configuration |

### Subject Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/subjects` | GET | List all subjects |
| `/ssf/subjects` | POST | Add a new subject |
| `/ssf/subjects/{id}` | DELETE | Remove a subject |

### Event Triggers

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/actions/{action}` | POST | Trigger a security event |

**Request Body:**
```json
{
  "subject_identifier": "alice@example.com",
  "reason": "Optional reason for the action",
  "initiator": "admin"
}
```

### Event Delivery

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/push` | POST | Push delivery endpoint (receiver) |
| `/ssf/poll` | POST | Poll for pending events |
| `/ssf/ack` | POST | Acknowledge received events |

### Event History & Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/events` | GET | Get event history |
| `/ssf/received-events` | GET | Get received events log |
| `/ssf/response-actions` | GET | Get response actions log |

### Security State

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/security-states` | GET | Get all user security states |
| `/ssf/security-state/{email}` | GET | Get security state for user |
| `/ssf/security-state/{email}/reset` | POST | Reset user security state |

### SET Inspection

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ssf/decode` | POST | Decode a SET token |
| `/ssf/event-types` | GET | Get all supported event types |

## Code Structure

```
ssf/
├── plugin.go           # Main plugin, registers routes, manages lifecycle
├── storage.go          # SQLite persistence for streams, subjects, events
├── transmitter.go      # Event generation and delivery
├── receiver.go         # Legacy in-process receiver
├── receiver_service.go # Standalone receiver service (production-like)
├── action_executor.go  # Executes real security state changes
├── handlers.go         # HTTP request handlers
├── set.go              # SET encoding/decoding (RFC 8417)
├── events.go           # Event type definitions and metadata
└── README.md           # This file
```

## Key Components

### Storage (`storage.go`)

SQLite-based persistence with session support:

```go
// Session-specific stream
stream, err := storage.GetSessionStream(ctx, sessionID, baseURL)

// Seed demo data for a session
storage.SeedSessionDemoData(ctx, sessionID, baseURL)

// Cleanup old sessions
storage.CleanupOldSessions(24 * time.Hour)
```

### Transmitter (`transmitter.go`)

Generates and delivers SETs:

```go
// Trigger with session isolation
event, err := transmitter.TriggerSessionsRevokedWithSession(
    ctx, streamID, sessionID, subject, reason, initiator,
)

// Delivery methods
// - Push: HTTP POST to receiver endpoint
// - Poll: Events queued for retrieval
```

### Receiver (`receiver.go`, `receiver_service.go`)

Validates and processes incoming SETs:

```go
// Process push delivery
response, err := receiver.ProcessPushDelivery(ctx, body)

// Session ID extracted from SET claims
sessionID := decoded.SessionID

// Execute real actions
actionExecutor.RevokeUserSessionsForSession(ctx, sessionID, email)
```

### Action Executor (`action_executor.go`)

Performs real security state changes:

```go
type ActionExecutor interface {
    // Session-aware methods
    RevokeUserSessionsForSession(ctx, sessionID, email string) error
    DisableUserForSession(ctx, sessionID, email string) error
    EnableUserForSession(ctx, sessionID, email string) error
    ForcePasswordResetForSession(ctx, sessionID, email string) error
    InvalidateTokensForSession(ctx, sessionID, email string) error
    
    // State management
    GetUserStateForSession(sessionID, email string) (*UserSecurityState, error)
    ResetUserStateForSession(sessionID, email string, sessions int)
    InitSessionUserStates(sessionID string)
}
```

### SET Token Structure (`set.go`)

RFC 8417 compliant Security Event Token:

```json
{
  "iss": "https://protocolsoup.com",
  "aud": ["https://protocolsoup.com/ssf/push"],
  "iat": 1704825600,
  "jti": "unique-event-id",
  "sub_id": {
    "format": "email",
    "email": "alice@example.com"
  },
  "ssf_session_id": "sess_abc123",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked": {
      "subject": { "format": "email", "email": "alice@example.com" },
      "event_timestamp": 1704825600,
      "reason": "Security incident detected",
      "initiating_entity": "admin"
    }
  }
}
```

## Testing

### Manual API Test

```bash
# Set session header
SESSION_ID="test-session-123"

# 1. Initialize session (get subjects)
curl -H "X-SSF-Session: $SESSION_ID" http://localhost:8080/ssf/subjects

# 2. Check initial state
curl -H "X-SSF-Session: $SESSION_ID" \
  http://localhost:8080/ssf/security-state/alice%40example.com

# 3. Trigger event
curl -X POST -H "X-SSF-Session: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{"subject_identifier": "alice@example.com"}' \
  http://localhost:8080/ssf/actions/sessions-revoked

# 4. Verify state changed
curl -H "X-SSF-Session: $SESSION_ID" \
  http://localhost:8080/ssf/security-state/alice%40example.com
```

### Expected Flow

1. **Event Trigger** → Transmitter creates SecurityEvent with sessionID
2. **SET Generation** → Encoder embeds `ssf_session_id` in JWT claims
3. **Push Delivery** → HTTP POST to internal `/ssf/push` endpoint
4. **SET Verification** → Receiver validates signature via JWKS
5. **Session Extraction** → `ssf_session_id` extracted from decoded SET
6. **Action Execution** → ActionExecutor updates session-scoped state
7. **State Query** → Frontend fetches updated state with session header

## Specifications

- [RFC 8417 - Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sse-framework-1_0.html)
- [CAEP - Continuous Access Evaluation Profile](https://openid.net/specs/openid-caep-1_0.html)
- [RISC - Risk Incident Sharing and Coordination](https://openid.net/specs/openid-risc-1_0.html)

## License

Part of the ProtocolLens/Protocol Soup project.
