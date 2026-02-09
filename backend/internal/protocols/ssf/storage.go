package ssf

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Storage handles persistence for SSF streams, subjects, and events
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new SSF storage instance
func NewStorage(dataDir string) (*Storage, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "ssf.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	storage := &Storage{db: db}
	if err := storage.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// initSchema creates the database tables
func (s *Storage) initSchema() error {
	schema := `
	-- Event Streams
	CREATE TABLE IF NOT EXISTS streams (
		id TEXT PRIMARY KEY,
		issuer TEXT NOT NULL,
		audience TEXT NOT NULL,
		events_supported TEXT NOT NULL,
		events_requested TEXT NOT NULL,
		delivery_method TEXT NOT NULL,
		delivery_endpoint TEXT,
		bearer_token TEXT,
		status TEXT NOT NULL DEFAULT 'enabled',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Subjects being tracked
	CREATE TABLE IF NOT EXISTS subjects (
		id TEXT PRIMARY KEY,
		stream_id TEXT NOT NULL,
		format TEXT NOT NULL,
		identifier TEXT NOT NULL,
		display_name TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		active_sessions INTEGER DEFAULT 0,
		last_activity DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (stream_id) REFERENCES streams(id) ON DELETE CASCADE,
		UNIQUE(stream_id, format, identifier)
	);

	-- Security state tracking (persisted IdP actions)
	CREATE TABLE IF NOT EXISTS security_states (
		stream_id TEXT NOT NULL,
		identifier TEXT NOT NULL,
		sessions_active INTEGER NOT NULL,
		account_enabled INTEGER NOT NULL,
		password_reset_required INTEGER NOT NULL,
		tokens_valid INTEGER NOT NULL,
		last_modified DATETIME NOT NULL,
		modified_by TEXT NOT NULL,
		PRIMARY KEY (stream_id, identifier),
		FOREIGN KEY (stream_id) REFERENCES streams(id) ON DELETE CASCADE
	);

	-- Event log
	CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY,
		stream_id TEXT NOT NULL,
		subject_id TEXT,
		event_type TEXT NOT NULL,
		event_data TEXT NOT NULL,
		set_token TEXT,
		session_id TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		delivered_at DATETIME,
		acknowledged_at DATETIME,
		FOREIGN KEY (stream_id) REFERENCES streams(id) ON DELETE CASCADE,
		FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL
	);

	-- Delivery attempts
	CREATE TABLE IF NOT EXISTS delivery_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id TEXT NOT NULL,
		attempt_number INTEGER NOT NULL,
		status TEXT NOT NULL,
		response_code INTEGER,
		response_body TEXT,
		error_message TEXT,
		attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
	);

	-- Indexes
	CREATE INDEX IF NOT EXISTS idx_events_stream ON events(stream_id);
	CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
	CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
	CREATE INDEX IF NOT EXISTS idx_subjects_stream ON subjects(stream_id);
	CREATE INDEX IF NOT EXISTS idx_security_states_stream ON security_states(stream_id);
	CREATE INDEX IF NOT EXISTS idx_security_states_identifier ON security_states(identifier);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Migration: add session_id column to events if it doesn't already exist (for pre-existing DBs)
	_, _ = s.db.Exec(`ALTER TABLE events ADD COLUMN session_id TEXT NOT NULL DEFAULT ''`)

	return nil
}

// Stream represents an SSF event stream configuration
type Stream struct {
	ID               string    `json:"stream_id"`
	Issuer           string    `json:"iss"`
	Audience         []string  `json:"aud"`
	EventsSupported  []string  `json:"events_supported"`
	EventsRequested  []string  `json:"events_requested"`
	DeliveryMethod   string    `json:"delivery_method"`
	DeliveryEndpoint string    `json:"delivery_endpoint_url,omitempty"`
	BearerToken      string    `json:"bearer_token,omitempty"` // For authenticated push delivery
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Delivery method constants per RFC 8935/8936
const (
	DeliveryMethodPush = "urn:ietf:rfc:8935"
	DeliveryMethodPoll = "urn:ietf:rfc:8936"
)

// Stream status constants
const (
	StreamStatusEnabled  = "enabled"
	StreamStatusPaused   = "paused"
	StreamStatusDisabled = "disabled"
)

// CreateStream creates a new event stream
func (s *Storage) CreateStream(ctx context.Context, stream Stream) error {
	audience, _ := json.Marshal(stream.Audience)
	supported, _ := json.Marshal(stream.EventsSupported)
	requested, _ := json.Marshal(stream.EventsRequested)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO streams (id, issuer, audience, events_supported, events_requested, 
			delivery_method, delivery_endpoint, bearer_token, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stream.ID, stream.Issuer, string(audience), string(supported), string(requested),
		stream.DeliveryMethod, stream.DeliveryEndpoint, stream.BearerToken, stream.Status)
	return err
}

// GetStream retrieves a stream by ID
func (s *Storage) GetStream(ctx context.Context, streamID string) (*Stream, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, issuer, audience, events_supported, events_requested, 
			delivery_method, delivery_endpoint, COALESCE(bearer_token, ''), status, created_at, updated_at
		FROM streams WHERE id = ?`, streamID)

	var stream Stream
	var audience, supported, requested string
	err := row.Scan(&stream.ID, &stream.Issuer, &audience, &supported, &requested,
		&stream.DeliveryMethod, &stream.DeliveryEndpoint, &stream.BearerToken, &stream.Status,
		&stream.CreatedAt, &stream.UpdatedAt)
	if err != nil {
		return nil, err
	}

	_ = json.Unmarshal([]byte(audience), &stream.Audience)
	_ = json.Unmarshal([]byte(supported), &stream.EventsSupported)
	_ = json.Unmarshal([]byte(requested), &stream.EventsRequested)

	return &stream, nil
}

// GetDefaultStream gets or creates a default stream for the sandbox
func (s *Storage) GetDefaultStream(ctx context.Context, issuer string) (*Stream, error) {
	stream, err := s.GetStream(ctx, "default")
	if err == nil {
		return stream, nil
	}

	// Create default stream
	defaultStream := Stream{
		ID:               "default",
		Issuer:           issuer,
		Audience:         []string{issuer + "/receiver"},
		EventsSupported:  GetSupportedEventURIs(),
		EventsRequested:  GetSupportedEventURIs(),
		DeliveryMethod:   DeliveryMethodPush,
		DeliveryEndpoint: issuer + "/ssf/push",
		Status:           StreamStatusEnabled,
	}

	if err := s.CreateStream(ctx, defaultStream); err != nil {
		return nil, err
	}

	return &defaultStream, nil
}

// UpdateStream updates a stream configuration
func (s *Storage) UpdateStream(ctx context.Context, stream Stream) error {
	audience, _ := json.Marshal(stream.Audience)
	supported, _ := json.Marshal(stream.EventsSupported)
	requested, _ := json.Marshal(stream.EventsRequested)

	_, err := s.db.ExecContext(ctx, `
		UPDATE streams SET 
			audience = ?, events_supported = ?, events_requested = ?,
			delivery_method = ?, delivery_endpoint = ?, bearer_token = ?, status = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		string(audience), string(supported), string(requested),
		stream.DeliveryMethod, stream.DeliveryEndpoint, stream.BearerToken, stream.Status, stream.ID)
	return err
}

// DeleteStream removes a stream
func (s *Storage) DeleteStream(ctx context.Context, streamID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM streams WHERE id = ?", streamID)
	return err
}

// Subject represents a tracked subject (user)
type Subject struct {
	ID             string     `json:"id"`
	StreamID       string     `json:"stream_id"`
	Format         string     `json:"format"`
	Identifier     string     `json:"identifier"`
	DisplayName    string     `json:"display_name"`
	Status         string     `json:"status"`
	ActiveSessions int        `json:"active_sessions"`
	LastActivity   *time.Time `json:"last_activity"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Subject status constants
const (
	SubjectStatusActive   = "active"
	SubjectStatusDisabled = "disabled"
	SubjectStatusPurged   = "purged"
)

// AddSubject adds a subject to a stream
func (s *Storage) AddSubject(ctx context.Context, subject Subject) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO subjects (id, stream_id, format, identifier, display_name, status, active_sessions)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		subject.ID, subject.StreamID, subject.Format, subject.Identifier,
		subject.DisplayName, subject.Status, subject.ActiveSessions)
	return err
}

// GetSubject retrieves a subject by ID
func (s *Storage) GetSubject(ctx context.Context, subjectID string) (*Subject, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, stream_id, format, identifier, display_name, status, 
			active_sessions, last_activity, created_at
		FROM subjects WHERE id = ?`, subjectID)

	var subject Subject
	var lastActivity sql.NullTime
	err := row.Scan(&subject.ID, &subject.StreamID, &subject.Format, &subject.Identifier,
		&subject.DisplayName, &subject.Status, &subject.ActiveSessions,
		&lastActivity, &subject.CreatedAt)
	if err != nil {
		return nil, err
	}

	if lastActivity.Valid {
		subject.LastActivity = &lastActivity.Time
	}

	return &subject, nil
}

// GetSubjectByIdentifier finds a subject by format and identifier
func (s *Storage) GetSubjectByIdentifier(ctx context.Context, streamID, format, identifier string) (*Subject, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, stream_id, format, identifier, display_name, status, 
			active_sessions, last_activity, created_at
		FROM subjects WHERE stream_id = ? AND format = ? AND identifier = ?`,
		streamID, format, identifier)

	var subject Subject
	var lastActivity sql.NullTime
	err := row.Scan(&subject.ID, &subject.StreamID, &subject.Format, &subject.Identifier,
		&subject.DisplayName, &subject.Status, &subject.ActiveSessions,
		&lastActivity, &subject.CreatedAt)
	if err != nil {
		return nil, err
	}

	if lastActivity.Valid {
		subject.LastActivity = &lastActivity.Time
	}

	return &subject, nil
}

// ListSubjects returns all subjects in a stream
func (s *Storage) ListSubjects(ctx context.Context, streamID string) ([]Subject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, stream_id, format, identifier, display_name, status, 
			active_sessions, last_activity, created_at
		FROM subjects WHERE stream_id = ? ORDER BY created_at DESC`, streamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subjects []Subject
	for rows.Next() {
		var subject Subject
		var lastActivity sql.NullTime
		err := rows.Scan(&subject.ID, &subject.StreamID, &subject.Format, &subject.Identifier,
			&subject.DisplayName, &subject.Status, &subject.ActiveSessions,
			&lastActivity, &subject.CreatedAt)
		if err != nil {
			return nil, err
		}
		if lastActivity.Valid {
			subject.LastActivity = &lastActivity.Time
		}
		subjects = append(subjects, subject)
	}

	return subjects, nil
}

// UpdateSubject updates a subject
func (s *Storage) UpdateSubject(ctx context.Context, subject Subject) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE subjects SET 
			display_name = ?, status = ?, active_sessions = ?, last_activity = ?
		WHERE id = ?`,
		subject.DisplayName, subject.Status, subject.ActiveSessions,
		subject.LastActivity, subject.ID)
	return err
}

// DeleteSubject removes a subject
func (s *Storage) DeleteSubject(ctx context.Context, subjectID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM subjects WHERE id = ?", subjectID)
	return err
}

// UpsertSecurityState creates or updates a persisted security state
func (s *Storage) UpsertSecurityState(ctx context.Context, streamID string, state UserSecurityState) error {
	lastModified := state.LastModified
	if lastModified.IsZero() {
		lastModified = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO security_states (
			stream_id, identifier, sessions_active, account_enabled, password_reset_required,
			tokens_valid, last_modified, modified_by
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(stream_id, identifier) DO UPDATE SET
			sessions_active = excluded.sessions_active,
			account_enabled = excluded.account_enabled,
			password_reset_required = excluded.password_reset_required,
			tokens_valid = excluded.tokens_valid,
			last_modified = excluded.last_modified,
			modified_by = excluded.modified_by
	`,
		streamID,
		state.Email,
		state.SessionsActive,
		boolToInt(state.AccountEnabled),
		boolToInt(state.PasswordResetRequired),
		boolToInt(state.TokensValid),
		lastModified,
		state.ModifiedBy,
	)
	return err
}

// GetSecurityState retrieves a persisted security state by stream and identifier
func (s *Storage) GetSecurityState(ctx context.Context, streamID, identifier string) (*UserSecurityState, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT identifier, sessions_active, account_enabled, password_reset_required,
			tokens_valid, last_modified, modified_by
		FROM security_states
		WHERE stream_id = ? AND identifier = ?`, streamID, identifier)

	var state UserSecurityState
	var accountEnabled, passwordResetRequired, tokensValid int
	if err := row.Scan(
		&state.Email,
		&state.SessionsActive,
		&accountEnabled,
		&passwordResetRequired,
		&tokensValid,
		&state.LastModified,
		&state.ModifiedBy,
	); err != nil {
		return nil, err
	}

	state.AccountEnabled = intToBool(accountEnabled)
	state.PasswordResetRequired = intToBool(passwordResetRequired)
	state.TokensValid = intToBool(tokensValid)

	return &state, nil
}

// ListSecurityStates returns all security states for a stream
func (s *Storage) ListSecurityStates(ctx context.Context, streamID string) (map[string]*UserSecurityState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT identifier, sessions_active, account_enabled, password_reset_required,
			tokens_valid, last_modified, modified_by
		FROM security_states
		WHERE stream_id = ?
		ORDER BY identifier ASC`, streamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := make(map[string]*UserSecurityState)
	for rows.Next() {
		var state UserSecurityState
		var accountEnabled, passwordResetRequired, tokensValid int
		if err := rows.Scan(
			&state.Email,
			&state.SessionsActive,
			&accountEnabled,
			&passwordResetRequired,
			&tokensValid,
			&state.LastModified,
			&state.ModifiedBy,
		); err != nil {
			return nil, err
		}
		state.AccountEnabled = intToBool(accountEnabled)
		state.PasswordResetRequired = intToBool(passwordResetRequired)
		state.TokensValid = intToBool(tokensValid)
		states[state.Email] = &state
	}

	return states, nil
}

// DeleteSecurityState removes a persisted security state
func (s *Storage) DeleteSecurityState(ctx context.Context, streamID, identifier string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM security_states WHERE stream_id = ? AND identifier = ?`,
		streamID, identifier)
	return err
}

// CleanupSecurityStates removes security states for expired session streams
func (s *Storage) CleanupSecurityStates(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM security_states
		WHERE stream_id IN (
			SELECT id FROM streams WHERE id LIKE 'session-%' AND updated_at < ?
		)`, cutoff)
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}

// StoredEvent represents an event in the database
type StoredEvent struct {
	ID             string     `json:"id"`
	StreamID       string     `json:"stream_id"`
	SubjectID      *string    `json:"subject_id"`
	EventType      string     `json:"event_type"`
	EventData      string     `json:"event_data"`
	SETToken       string     `json:"set_token"`
	SessionID      string     `json:"session_id,omitempty"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	DeliveredAt    *time.Time `json:"delivered_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
}

// Event status constants
const (
	EventStatusPending      = "pending"
	EventStatusDelivering   = "delivering"
	EventStatusDelivered    = "delivered"
	EventStatusAcknowledged = "acknowledged"
	EventStatusFailed       = "failed"
)

// StoreEvent stores an event for delivery
func (s *Storage) StoreEvent(ctx context.Context, event StoredEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (id, stream_id, subject_id, event_type, event_data, set_token, session_id, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.StreamID, event.SubjectID, event.EventType,
		event.EventData, event.SETToken, event.SessionID, event.Status)
	return err
}

// GetPendingEvents retrieves events pending delivery
func (s *Storage) GetPendingEvents(ctx context.Context, streamID string, limit int) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, stream_id, subject_id, event_type, event_data, set_token, session_id, status, 
			created_at, delivered_at, acknowledged_at
		FROM events 
		WHERE stream_id = ? AND status IN ('pending', 'delivering')
		ORDER BY created_at ASC
		LIMIT ?`, streamID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetEvents retrieves events with optional filtering
func (s *Storage) GetEvents(ctx context.Context, streamID string, status string, limit int) ([]StoredEvent, error) {
	var rows *sql.Rows
	var err error

	if status != "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, stream_id, subject_id, event_type, event_data, set_token, session_id, status, 
				created_at, delivered_at, acknowledged_at
			FROM events 
			WHERE stream_id = ? AND status = ?
			ORDER BY created_at DESC
			LIMIT ?`, streamID, status, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, stream_id, subject_id, event_type, event_data, set_token, session_id, status, 
				created_at, delivered_at, acknowledged_at
			FROM events 
			WHERE stream_id = ?
			ORDER BY created_at DESC
			LIMIT ?`, streamID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

// UpdateEventStatus updates the status of an event
func (s *Storage) UpdateEventStatus(ctx context.Context, eventID, status string) error {
	var err error
	switch status {
	case EventStatusDelivered:
		_, err = s.db.ExecContext(ctx,
			"UPDATE events SET status = ?, delivered_at = CURRENT_TIMESTAMP WHERE id = ?",
			status, eventID)
	case EventStatusAcknowledged:
		_, err = s.db.ExecContext(ctx,
			"UPDATE events SET status = ?, acknowledged_at = CURRENT_TIMESTAMP WHERE id = ?",
			status, eventID)
	default:
		_, err = s.db.ExecContext(ctx,
			"UPDATE events SET status = ? WHERE id = ?", status, eventID)
	}
	return err
}

// AcknowledgeEvents marks events as acknowledged
func (s *Storage) AcknowledgeEvents(ctx context.Context, eventIDs []string) error {
	for _, id := range eventIDs {
		if err := s.UpdateEventStatus(ctx, id, EventStatusAcknowledged); err != nil {
			return err
		}
	}
	return nil
}

// RecordDeliveryAttempt records a delivery attempt
func (s *Storage) RecordDeliveryAttempt(ctx context.Context, eventID string, attemptNum int,
	status string, responseCode int, responseBody, errorMsg string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO delivery_attempts (event_id, attempt_number, status, response_code, response_body, error_message)
		VALUES (?, ?, ?, ?, ?, ?)`,
		eventID, attemptNum, status, responseCode, responseBody, errorMsg)
	return err
}

// GetEventHistory retrieves recent events for display
func (s *Storage) GetEventHistory(ctx context.Context, streamID string, limit int) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, stream_id, subject_id, event_type, event_data, set_token, session_id, status, 
			created_at, delivered_at, acknowledged_at
		FROM events 
		WHERE stream_id = ?
		ORDER BY created_at DESC
		LIMIT ?`, streamID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]StoredEvent, error) {
	var events []StoredEvent
	for rows.Next() {
		var event StoredEvent
		var subjectID sql.NullString
		var deliveredAt, acknowledgedAt sql.NullTime
		err := rows.Scan(&event.ID, &event.StreamID, &subjectID, &event.EventType,
			&event.EventData, &event.SETToken, &event.SessionID, &event.Status, &event.CreatedAt,
			&deliveredAt, &acknowledgedAt)
		if err != nil {
			return nil, err
		}
		if subjectID.Valid {
			event.SubjectID = &subjectID.String
		}
		if deliveredAt.Valid {
			event.DeliveredAt = &deliveredAt.Time
		}
		if acknowledgedAt.Valid {
			event.AcknowledgedAt = &acknowledgedAt.Time
		}
		events = append(events, event)
	}
	return events, nil
}

// SeedDemoData adds initial demo subjects
func (s *Storage) SeedDemoData(ctx context.Context, baseURL string) error {
	stream, err := s.GetDefaultStream(ctx, baseURL)
	if err != nil {
		return err
	}

	// Check if we already have subjects
	subjects, err := s.ListSubjects(ctx, stream.ID)
	if err != nil {
		return err
	}
	if len(subjects) > 0 {
		return nil // Already seeded
	}

	// Add demo subjects
	demoSubjects := []Subject{
		{
			ID:             "subject-alice",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "alice@example.com",
			DisplayName:    "Alice Johnson",
			Status:         SubjectStatusActive,
			ActiveSessions: 3,
		},
		{
			ID:             "subject-bob",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "bob@example.com",
			DisplayName:    "Bob Smith",
			Status:         SubjectStatusActive,
			ActiveSessions: 1,
		},
		{
			ID:             "subject-charlie",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "charlie@example.com",
			DisplayName:    "Charlie Brown",
			Status:         SubjectStatusActive,
			ActiveSessions: 2,
		},
	}

	for _, subject := range demoSubjects {
		if err := s.AddSubject(ctx, subject); err != nil {
			// Ignore duplicate errors
			continue
		}
	}

	return nil
}

// GetSessionStream gets or creates a stream for a specific session
func (s *Storage) GetSessionStream(ctx context.Context, sessionID, issuer string) (*Stream, error) {
	streamID := "session-" + sessionID

	stream, err := s.GetStream(ctx, streamID)
	if err == nil {
		return stream, nil
	}

	// Create session-specific stream
	sessionStream := Stream{
		ID:              streamID,
		Issuer:          issuer,
		Audience:        []string{issuer + "/receiver"},
		EventsSupported: GetSupportedEventURIs(),
		EventsRequested: GetSupportedEventURIs(),
		DeliveryMethod:  DeliveryMethodPush,
		DeliveryEndpoint: issuer + "/ssf/push",
		Status:          StreamStatusEnabled,
	}

	if err := s.CreateStream(ctx, sessionStream); err != nil {
		return nil, err
	}

	return &sessionStream, nil
}

// SeedSessionDemoData seeds demo subjects for a specific session
func (s *Storage) SeedSessionDemoData(ctx context.Context, sessionID, baseURL string) error {
	stream, err := s.GetSessionStream(ctx, sessionID, baseURL)
	if err != nil {
		return err
	}

	// Check if we already have subjects
	subjects, err := s.ListSubjects(ctx, stream.ID)
	if err != nil {
		return err
	}
	if len(subjects) > 0 {
		return nil // Already seeded
	}

	// Add demo subjects with session-specific IDs
	demoSubjects := []Subject{
		{
			ID:             sessionID + "-alice",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "alice@example.com",
			DisplayName:    "Alice Johnson",
			Status:         SubjectStatusActive,
			ActiveSessions: 3,
		},
		{
			ID:             sessionID + "-bob",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "bob@example.com",
			DisplayName:    "Bob Smith",
			Status:         SubjectStatusActive,
			ActiveSessions: 1,
		},
		{
			ID:             sessionID + "-charlie",
			StreamID:       stream.ID,
			Format:         SubjectFormatEmail,
			Identifier:     "charlie@example.com",
			DisplayName:    "Charlie Brown",
			Status:         SubjectStatusActive,
			ActiveSessions: 2,
		},
	}

	for _, subject := range demoSubjects {
		if err := s.AddSubject(ctx, subject); err != nil {
			continue
		}
	}

	return nil
}

// CleanupOldSessions removes streams and data older than maxAge
func (s *Storage) CleanupOldSessions(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)

	// First get count of old session streams
	var count int
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM streams 
		WHERE id LIKE 'session-%' AND updated_at < ?`, cutoff)
	if err := row.Scan(&count); err != nil {
		return 0, err
	}

	// Delete old session streams (cascades to subjects and events)
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM streams 
		WHERE id LIKE 'session-%' AND updated_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func intToBool(value int) bool {
	return value != 0
}
