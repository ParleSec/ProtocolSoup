package session

import (
	"sync"
	"time"
)

// PendingRequest is a request an entity sent and is waiting to see answered.
type PendingRequest struct {
	ID         string
	RelayState string
	IssuedAt   time.Time
}

// Pending holds sent request IDs so a response's InResponseTo can be matched
// to exactly one request: "The values of the ID attribute in a request and the
// InResponseTo attribute in the corresponding response MUST match" (SAML Core
// Section 3.2.1). Each ID is consumed on first use.
type Pending struct {
	mu      sync.Mutex
	ttl     time.Duration
	pending map[string]PendingRequest
}

// NewPending returns an empty Pending whose entries expire after ttl.
func NewPending(ttl time.Duration) *Pending {
	return &Pending{ttl: ttl, pending: map[string]PendingRequest{}}
}

// Store records a sent request.
func (p *Pending) Store(req PendingRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for id, existing := range p.pending {
		if now.Sub(existing.IssuedAt) > p.ttl {
			delete(p.pending, id)
		}
	}
	req.IssuedAt = now
	p.pending[req.ID] = req
}

// Take returns and removes the outstanding request with id.
func (p *Pending) Take(id string) (PendingRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	req, ok := p.pending[id]
	delete(p.pending, id)
	if !ok || time.Since(req.IssuedAt) > p.ttl {
		return PendingRequest{}, false
	}
	return req, true
}

// ReplayCache records consumed assertion IDs: "The service provider MUST
// ensure that bearer assertions are not replayed, by maintaining the set of
// used ID values for the length of time for which the assertion would be
// considered valid based on the NotOnOrAfter attribute in the
// <SubjectConfirmationData>" (SAML Profiles Section 4.1.4.5).
type ReplayCache struct {
	mu       sync.Mutex
	consumed map[string]time.Time // ID -> keep until
}

// NewReplayCache returns an empty ReplayCache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{consumed: map[string]time.Time{}}
}

// Consume marks id as used until keepUntil and reports whether it was fresh.
func (c *ReplayCache) Consume(id string, keepUntil time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for existing, until := range c.consumed {
		if now.After(until) {
			delete(c.consumed, existing)
		}
	}
	if _, seen := c.consumed[id]; seen {
		return false
	}
	c.consumed[id] = keepUntil
	return true
}
