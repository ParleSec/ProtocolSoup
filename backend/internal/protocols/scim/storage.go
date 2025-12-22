package scim

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var (
	ErrNotFound      = errors.New("resource not found")
	ErrConflict      = errors.New("resource already exists")
	ErrVersionConflict = errors.New("version conflict")
)

// Storage handles SQLite persistence for SCIM resources
type Storage struct {
	db   *sql.DB
	mu   sync.RWMutex
	path string
}

// NewStorage creates a new SQLite-backed storage
func NewStorage(dataDir string) (*Storage, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "scim.db")
	
	// Open SQLite database with modernc.org/sqlite (pure Go, no CGO)
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1) // SQLite only supports one writer
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	storage := &Storage{
		db:   db,
		path: dbPath,
	}

	// Run migrations
	if err := storage.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return storage, nil
}

// migrate runs database schema migrations
func (s *Storage) migrate() error {
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS scim_users (
			id TEXT PRIMARY KEY,
			external_id TEXT,
			user_name TEXT NOT NULL UNIQUE,
			data TEXT NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_external_id ON scim_users(external_id)`,
		`CREATE INDEX IF NOT EXISTS idx_users_user_name ON scim_users(user_name)`,
		`CREATE INDEX IF NOT EXISTS idx_users_updated_at ON scim_users(updated_at)`,

		// Groups table
		`CREATE TABLE IF NOT EXISTS scim_groups (
			id TEXT PRIMARY KEY,
			external_id TEXT,
			display_name TEXT NOT NULL,
			data TEXT NOT NULL,
			version INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_groups_display_name ON scim_groups(display_name)`,
		`CREATE INDEX IF NOT EXISTS idx_groups_updated_at ON scim_groups(updated_at)`,

		// Group membership (for efficient queries)
		`CREATE TABLE IF NOT EXISTS scim_group_members (
			group_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			PRIMARY KEY (group_id, user_id),
			FOREIGN KEY (group_id) REFERENCES scim_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES scim_users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_members_user_id ON scim_group_members(user_id)`,

		// Sync state for SCIM client
		`CREATE TABLE IF NOT EXISTS scim_sync_state (
			target_url TEXT PRIMARY KEY,
			last_sync TEXT,
			cursor TEXT
		)`,

		// Schema version tracking
		`CREATE TABLE IF NOT EXISTS scim_schema_version (
			version INTEGER PRIMARY KEY
		)`,
	}

	for _, migration := range migrations {
		if _, err := s.db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// ================== User Operations ==================

// CreateUser creates a new user
func (s *Storage) CreateUser(ctx context.Context, user *User) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not provided
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now().UTC()
	user.Meta = &Meta{
		ResourceType: "User",
		Created:      &now,
		LastModified: &now,
		Version:      GenerateETag(1),
	}

	// Clear password from stored data for security
	userCopy := *user
	userCopy.Password = ""

	data, err := json.Marshal(userCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO scim_users (id, external_id, user_name, data, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 1, ?, ?)`,
		user.ID, user.ExternalID, user.UserName, string(data), now.Format(time.RFC3339), now.Format(time.RFC3339))

	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &userCopy, nil
}

// GetUser retrieves a user by ID
func (s *Storage) GetUser(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data string
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT data, version FROM scim_users WHERE id = ?`, id).Scan(&data, &version)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	// Update ETag with current version
	if user.Meta != nil {
		user.Meta.Version = GenerateETag(version)
	}

	return &user, nil
}

// GetUserByUserName retrieves a user by userName
func (s *Storage) GetUserByUserName(ctx context.Context, userName string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data string
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT data, version FROM scim_users WHERE user_name = ?`, userName).Scan(&data, &version)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	if user.Meta != nil {
		user.Meta.Version = GenerateETag(version)
	}

	return &user, nil
}

// UpdateUser replaces a user (PUT)
func (s *Storage) UpdateUser(ctx context.Context, id string, user *User, expectedVersion int) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user exists and get current version
	var currentVersion int
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT version, created_at FROM scim_users WHERE id = ?`, id).Scan(&currentVersion, &createdAt)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check version for optimistic locking if provided
	if expectedVersion > 0 && currentVersion != expectedVersion {
		return nil, ErrVersionConflict
	}

	// Update user
	user.ID = id
	now := time.Now().UTC()
	created, _ := time.Parse(time.RFC3339, createdAt)
	newVersion := currentVersion + 1
	
	user.Meta = &Meta{
		ResourceType: "User",
		Created:      &created,
		LastModified: &now,
		Version:      GenerateETag(newVersion),
	}

	// Clear password
	userCopy := *user
	userCopy.Password = ""

	data, err := json.Marshal(userCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`UPDATE scim_users SET external_id = ?, user_name = ?, data = ?, version = ?, updated_at = ?
		 WHERE id = ?`,
		user.ExternalID, user.UserName, string(data), newVersion, now.Format(time.RFC3339), id)

	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &userCopy, nil
}

// DeleteUser deletes a user
func (s *Storage) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM scim_users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListUsers returns users with optional filtering
func (s *Storage) ListUsers(ctx context.Context, filter string, startIndex, count int) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build query with filter
	query := `SELECT data, version FROM scim_users`
	countQuery := `SELECT COUNT(*) FROM scim_users`
	var args []interface{}

	if filter != "" {
		whereClause, filterArgs, err := buildFilterClause(filter, "user")
		if err != nil {
			return nil, 0, err
		}
		if whereClause != "" {
			query += " WHERE " + whereClause
			countQuery += " WHERE " + whereClause
			args = filterArgs
		}
	}

	// Get total count
	var totalCount int
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Add pagination
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", count, startIndex-1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var data string
		var version int
		if err := rows.Scan(&data, &version); err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		var user User
		if err := json.Unmarshal([]byte(data), &user); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal user: %w", err)
		}
		if user.Meta != nil {
			user.Meta.Version = GenerateETag(version)
		}
		users = append(users, &user)
	}

	return users, totalCount, nil
}

// ================== Group Operations ==================

// CreateGroup creates a new group
func (s *Storage) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if group.ID == "" {
		group.ID = uuid.New().String()
	}

	now := time.Now().UTC()
	group.Meta = &Meta{
		ResourceType: "Group",
		Created:      &now,
		LastModified: &now,
		Version:      GenerateETag(1),
	}

	data, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO scim_groups (id, external_id, display_name, data, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 1, ?, ?)`,
		group.ID, group.ExternalID, group.DisplayName, string(data), now.Format(time.RFC3339), now.Format(time.RFC3339))

	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	// Add members
	for _, member := range group.Members {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id) VALUES (?, ?)`,
			group.ID, member.Value)
		if err != nil {
			// Ignore if member doesn't exist
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return group, nil
}

// GetGroup retrieves a group by ID
func (s *Storage) GetGroup(ctx context.Context, id string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data string
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT data, version FROM scim_groups WHERE id = ?`, id).Scan(&data, &version)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	var group Group
	if err := json.Unmarshal([]byte(data), &group); err != nil {
		return nil, fmt.Errorf("failed to unmarshal group: %w", err)
	}

	if group.Meta != nil {
		group.Meta.Version = GenerateETag(version)
	}

	// Get current members
	members, err := s.getGroupMembers(ctx, id)
	if err == nil {
		group.Members = members
	}

	return &group, nil
}

// getGroupMembers retrieves members for a group
func (s *Storage) getGroupMembers(ctx context.Context, groupID string) ([]MemberRef, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.data FROM scim_users u
		 JOIN scim_group_members m ON u.id = m.user_id
		 WHERE m.group_id = ?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []MemberRef
	for rows.Next() {
		var userID, data string
		if err := rows.Scan(&userID, &data); err != nil {
			continue
		}

		var user User
		if err := json.Unmarshal([]byte(data), &user); err != nil {
			continue
		}

		members = append(members, MemberRef{
			Value:   userID,
			Display: user.DisplayName,
			Type:    "User",
		})
	}

	return members, nil
}

// UpdateGroup replaces a group (PUT)
func (s *Storage) UpdateGroup(ctx context.Context, id string, group *Group, expectedVersion int) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var currentVersion int
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT version, created_at FROM scim_groups WHERE id = ?`, id).Scan(&currentVersion, &createdAt)
	
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if expectedVersion > 0 && currentVersion != expectedVersion {
		return nil, ErrVersionConflict
	}

	group.ID = id
	now := time.Now().UTC()
	created, _ := time.Parse(time.RFC3339, createdAt)
	newVersion := currentVersion + 1
	
	group.Meta = &Meta{
		ResourceType: "Group",
		Created:      &created,
		LastModified: &now,
		Version:      GenerateETag(newVersion),
	}

	data, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE scim_groups SET external_id = ?, display_name = ?, data = ?, version = ?, updated_at = ?
		 WHERE id = ?`,
		group.ExternalID, group.DisplayName, string(data), newVersion, now.Format(time.RFC3339), id)

	if err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	// Update members - remove all and re-add
	_, err = tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("failed to clear members: %w", err)
	}

	for _, member := range group.Members {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id) VALUES (?, ?)`,
			id, member.Value)
		if err != nil {
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return group, nil
}

// DeleteGroup deletes a group
func (s *Storage) DeleteGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `DELETE FROM scim_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListGroups returns groups with optional filtering
func (s *Storage) ListGroups(ctx context.Context, filter string, startIndex, count int) ([]*Group, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT data, version FROM scim_groups`
	countQuery := `SELECT COUNT(*) FROM scim_groups`
	var args []interface{}

	if filter != "" {
		whereClause, filterArgs, err := buildFilterClause(filter, "group")
		if err != nil {
			return nil, 0, err
		}
		if whereClause != "" {
			query += " WHERE " + whereClause
			countQuery += " WHERE " + whereClause
			args = filterArgs
		}
	}

	var totalCount int
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	if startIndex < 1 {
		startIndex = 1
	}
	if count < 1 {
		count = 100
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", count, startIndex-1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var data string
		var version int
		if err := rows.Scan(&data, &version); err != nil {
			return nil, 0, fmt.Errorf("failed to scan group: %w", err)
		}

		var group Group
		if err := json.Unmarshal([]byte(data), &group); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal group: %w", err)
		}
		if group.Meta != nil {
			group.Meta.Version = GenerateETag(version)
		}
		groups = append(groups, &group)
	}

	return groups, totalCount, nil
}

// AddGroupMember adds a user to a group
func (s *Storage) AddGroupMember(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify group exists
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM scim_groups WHERE id = ?`, groupID).Scan(&exists)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}

	// Verify user exists
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM scim_users WHERE id = ?`, userID).Scan(&exists)
	if err == sql.ErrNoRows {
		return fmt.Errorf("user not found: %s", userID)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO scim_group_members (group_id, user_id) VALUES (?, ?)`,
		groupID, userID)
	return err
}

// RemoveGroupMember removes a user from a group
func (s *Storage) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?`,
		groupID, userID)
	return err
}

// GetUserGroups returns all groups a user belongs to
func (s *Storage) GetUserGroups(ctx context.Context, userID string) ([]GroupRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT g.id, g.display_name FROM scim_groups g
		 JOIN scim_group_members m ON g.id = m.group_id
		 WHERE m.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []GroupRef
	for rows.Next() {
		var id, displayName string
		if err := rows.Scan(&id, &displayName); err != nil {
			continue
		}
		groups = append(groups, GroupRef{
			Value:   id,
			Display: displayName,
		})
	}

	return groups, nil
}

// ================== Sync State Operations ==================

// GetSyncState retrieves sync state for a target
func (s *Storage) GetSyncState(ctx context.Context, targetURL string) (time.Time, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var lastSync sql.NullString
	var cursor sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT last_sync, cursor FROM scim_sync_state WHERE target_url = ?`, targetURL).Scan(&lastSync, &cursor)
	
	if err == sql.ErrNoRows {
		return time.Time{}, "", nil
	}
	if err != nil {
		return time.Time{}, "", err
	}

	var t time.Time
	if lastSync.Valid {
		t, _ = time.Parse(time.RFC3339, lastSync.String)
	}

	return t, cursor.String, nil
}

// UpdateSyncState updates sync state for a target
func (s *Storage) UpdateSyncState(ctx context.Context, targetURL string, lastSync time.Time, cursor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scim_sync_state (target_url, last_sync, cursor)
		 VALUES (?, ?, ?)
		 ON CONFLICT(target_url) DO UPDATE SET last_sync = ?, cursor = ?`,
		targetURL, lastSync.Format(time.RFC3339), cursor, lastSync.Format(time.RFC3339), cursor)
	return err
}

// ================== Helper Functions ==================

// isUniqueConstraintError checks if error is a unique constraint violation
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "UNIQUE constraint failed") || contains(errStr, "duplicate key")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// buildFilterClause converts SCIM filter to SQL WHERE clause
// This is a simplified implementation - full implementation is in filter.go
func buildFilterClause(filter string, resourceType string) (string, []interface{}, error) {
	if filter == "" {
		return "", nil, nil
	}

	// Parse the filter using the SCIM filter parser
	parsed, err := ParseFilter(filter)
	if err != nil {
		return "", nil, ErrInvalidFilter(err.Error())
	}

	// Translate to SQL using the SQL translator
	translator := NewSQLTranslator(resourceType)
	sql, params, err := translator.Translate(parsed)
	if err != nil {
		return "", nil, ErrInvalidFilter(err.Error())
	}

	return sql, params, nil
}

// SeedDemoData creates initial demo data
func (s *Storage) SeedDemoData(ctx context.Context, baseURL string) error {
	// Check if data already exists
	var count int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_users`).Scan(&count)
	if count > 0 {
		return nil // Already seeded
	}

	// Create demo users
	demoUsers := []*User{
		{
			BaseResource: BaseResource{Schemas: []string{SchemaURNUser}, ExternalID: "ext-alice"},
			UserName:     "alice@example.com",
			DisplayName:  "Alice Johnson",
			Name:         &Name{GivenName: "Alice", FamilyName: "Johnson", Formatted: "Alice Johnson"},
			Active:       boolPtr(true),
			Emails:       []MultiValue{{Value: "alice@example.com", Type: "work", Primary: true}},
			EnterpriseUser: &EnterpriseUser{
				EmployeeNumber: "EMP001",
				Department:     "Engineering",
				Organization:   "Protocol Labs",
			},
		},
		{
			BaseResource: BaseResource{Schemas: []string{SchemaURNUser}, ExternalID: "ext-bob"},
			UserName:     "bob@example.com",
			DisplayName:  "Bob Smith",
			Name:         &Name{GivenName: "Bob", FamilyName: "Smith", Formatted: "Bob Smith"},
			Active:       boolPtr(true),
			Emails:       []MultiValue{{Value: "bob@example.com", Type: "work", Primary: true}},
			EnterpriseUser: &EnterpriseUser{
				EmployeeNumber: "EMP002",
				Department:     "Security",
				Organization:   "Protocol Labs",
			},
		},
		{
			BaseResource: BaseResource{Schemas: []string{SchemaURNUser}, ExternalID: "ext-carol"},
			UserName:     "carol@example.com",
			DisplayName:  "Carol Williams",
			Name:         &Name{GivenName: "Carol", FamilyName: "Williams", Formatted: "Carol Williams"},
			Active:       boolPtr(true),
			Emails:       []MultiValue{{Value: "carol@example.com", Type: "work", Primary: true}},
			EnterpriseUser: &EnterpriseUser{
				EmployeeNumber: "EMP003",
				Department:     "Product",
				Organization:   "Protocol Labs",
			},
		},
	}

	var userIDs []string
	for _, user := range demoUsers {
		created, err := s.CreateUser(ctx, user)
		if err != nil {
			continue
		}
		userIDs = append(userIDs, created.ID)
	}

	// Create demo groups
	if len(userIDs) >= 2 {
		engineeringGroup := &Group{
			BaseResource: BaseResource{Schemas: []string{SchemaURNGroup}},
			DisplayName:  "Engineering",
			Members: []MemberRef{
				{Value: userIDs[0], Type: "User"},
				{Value: userIDs[1], Type: "User"},
			},
		}
		s.CreateGroup(ctx, engineeringGroup)

		allUsersGroup := &Group{
			BaseResource: BaseResource{Schemas: []string{SchemaURNGroup}},
			DisplayName:  "All Users",
		}
		for _, id := range userIDs {
			allUsersGroup.Members = append(allUsersGroup.Members, MemberRef{Value: id, Type: "User"})
		}
		s.CreateGroup(ctx, allUsersGroup)
	}

	return nil
}

func boolPtr(b bool) *bool {
	return &b
}

