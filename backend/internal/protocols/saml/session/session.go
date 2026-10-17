// Package session holds the state a SAML entity keeps between messages:
// security contexts established by SSO, requests awaiting a response, consumed
// assertion IDs, and processed logouts. Each entity owns its own instances.
package session

import (
	"slices"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
)

// Session is one security context established by SSO. The SP keeps one per
// accepted assertion; the IdP keeps one per assertion it issued, which is the
// participant list Single Logout works from.
type Session struct {
	ID           string              `json:"sessionId"`
	PeerEntityID string              `json:"peerEntityId"`
	NameID       string              `json:"nameId"`
	NameIDFormat string              `json:"nameIdFormat"`
	SessionIndex string              `json:"sessionIndex"`
	AuthnInstant string              `json:"authnInstant"`
	AssertionID  string              `json:"assertionId"`
	Attributes   map[string][]string `json:"attributes,omitempty"`
	CreatedAt    time.Time           `json:"createdAt"`
}

// Store is an entity's set of sessions.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{sessions: map[string]*Session{}}
}

// Add records sess, assigning an ID when it has none.
func (s *Store) Add(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == "" {
		sess.ID = message.GenerateID()
	}
	sess.CreatedAt = time.Now()
	s.sessions[sess.ID] = sess
}

// Get returns the session with id.
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// List returns every session.
func (s *Store) List() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

// Remove deletes the session with id.
func (s *Store) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// RemoveMatching deletes the sessions for nameID with peer, limited to the
// listed SessionIndex values when any are given, and returns them.
func (s *Store) RemoveMatching(peer, nameID string, sessionIndexes []string) []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []*Session
	for id, sess := range s.sessions {
		if sess.PeerEntityID != peer || sess.NameID != nameID {
			continue
		}
		if len(sessionIndexes) > 0 && !slices.Contains(sessionIndexes, sess.SessionIndex) {
			continue
		}
		removed = append(removed, sess)
		delete(s.sessions, id)
	}
	return removed
}

// LogoutRecord remembers a LogoutRequest a session participant processed:
// "The session participant MUST apply the logout request message to any
// assertion that meets the following conditions, even if the assertion
// arrives after the logout request" (SAML Core Section 3.7.3.1).
type LogoutRecord struct {
	NameID         string
	SessionIndexes []string // empty means every session of the principal
	Until          time.Time
}

// LogoutRecords holds processed logouts until they expire. The zero value is
// ready to use.
type LogoutRecords struct {
	mu      sync.Mutex
	records []LogoutRecord
}

// Add records a processed logout.
func (l *LogoutRecords) Add(record LogoutRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, record)
}

// Matches reports whether a logout already processed covers an assertion for
// nameID with the given SessionIndex values.
func (l *LogoutRecords) Matches(nameID string, sessionIndexes []string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	kept := l.records[:0]
	found := false
	for _, record := range l.records {
		if now.After(record.Until) {
			continue
		}
		kept = append(kept, record)
		if record.NameID != nameID {
			continue
		}
		if len(record.SessionIndexes) == 0 {
			found = true
		}
		for _, index := range sessionIndexes {
			if slices.Contains(record.SessionIndexes, index) {
				found = true
			}
		}
	}
	l.records = kept
	return found
}
