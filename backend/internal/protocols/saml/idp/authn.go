package idp

import (
	"net/http"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// The IdP's own authentication session: the security context it establishes
// when the principal signs in, and reuses for later <AuthnRequest>s. "The
// ForceAuthn <AuthnRequest> attribute, if present with a value of true,
// obligates the identity provider to freshly establish this identity, rather
// than relying on an existing session it may have with the principal" (SAML
// Profiles Section 4.1.3.4); without it the IdP signs the principal in once and
// answers every later request from the same session. That is single sign-on.

const (
	authnCookieName = "saml_idp_session"
	authnLifetime   = 8 * time.Hour
)

// AuthnSession is the principal's authentication at this IdP.
type AuthnSession struct {
	ID           string
	User         *models.User
	AuthnInstant time.Time
	ExpiresAt    time.Time
}

type authnStore struct {
	mu       sync.Mutex
	sessions map[string]*AuthnSession
}

func newAuthnStore() *authnStore {
	return &authnStore{sessions: map[string]*AuthnSession{}}
}

// start records a fresh authentication and sets the session cookie.
func (s *authnStore) start(w http.ResponseWriter, user *models.User) *AuthnSession {
	now := time.Now()
	sess := &AuthnSession{ID: message.GenerateID(), User: user, AuthnInstant: now, ExpiresAt: now.Add(authnLifetime)}
	s.mu.Lock()
	for id, existing := range s.sessions {
		if now.After(existing.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: authnCookieName, Value: sess.ID, Path: loginCookiePath, Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return sess
}

// lookup returns the live session named by r's cookie, if any.
func (s *authnStore) lookup(r *http.Request) (*AuthnSession, bool) {
	cookie, err := r.Cookie(authnCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, cookie.Value)
		return nil, false
	}
	return sess, true
}

// endFor terminates every session of the principal named nameID, as the
// session authority does on logout (SAML Core Section 3.7.3.2). The cookie the
// browser still holds no longer names a live session.
func (s *authnStore) endFor(nameID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ended := 0
	for id, sess := range s.sessions {
		if sess.User.Email == nameID {
			delete(s.sessions, id)
			ended++
		}
	}
	return ended
}
