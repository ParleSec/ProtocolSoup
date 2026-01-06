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

	-- Event log
	CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY,
		stream_id TEXT NOT NULL,
		subject_id TEXT,
		event_type TEXT NOT NULL,
		event_data TEXT NOT NULL,
		set_token TEXT,
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
	`

	_, err := s.db.Exec(schema)
	return err
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

// Delivery method constants
const (
	DeliveryMethodPush = "https://schemas.openid.net/secevent/risc/delivery-method/push"
	DeliveryMethodPoll = "https://schemas.openid.net/secevent/risc/delivery-method/poll"
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

// StoredEvent represents an event in the database
type StoredEvent struct {
	ID             string     `json:"id"`
	StreamID       string     `json:"stream_id"`
	SubjectID      *string    `json:"subject_id"`
	EventType      string     `json:"event_type"`
	EventData      string     `json:"event_data"`
	SETToken       string     `json:"set_token"`
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
		INSERT INTO events (id, stream_id, subject_id, event_type, event_data, set_token, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.StreamID, event.SubjectID, event.EventType,
		event.EventData, event.SETToken, event.Status)
	return err
}

// GetPendingEvents retrieves events pending delivery
func (s *Storage) GetPendingEvents(ctx context.Context, streamID string, limit int) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, stream_id, subject_id, event_type, event_data, set_token, status, 
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
			SELECT id, stream_id, subject_id, event_type, event_data, set_token, status, 
				created_at, delivered_at, acknowledged_at
			FROM events 
			WHERE stream_id = ? AND status = ?
			ORDER BY created_at DESC
			LIMIT ?`, streamID, status, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, stream_id, subject_id, event_type, event_data, set_token, status, 
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
		SELECT id, stream_id, subject_id, event_type, event_data, set_token, status, 
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
			&event.EventData, &event.SETToken, &event.Status, &event.CreatedAt,
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
