package dpop

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceIssuer implements the server-supplied nonce mechanism of RFC 9449
// Section 8. It is deliberately per-plugin rather than per-client: the AS
// and RS each own an independent NonceIssuer instance, which is what gives
// them independent nonce spaces per Section 8.2 ("the nonce values used in
// each of these contexts are independent of each other").
//
// A NonceIssuer holds at most two live values -- current and the
// immediately preceding one -- so a proof minted just before a rotation
// is not spuriously rejected by a race with the rotation itself.
type NonceIssuer struct {
	mu        sync.Mutex
	ttl       time.Duration
	current   string
	previous  string
	rotatedAt time.Time
}

// NewNonceIssuer creates a NonceIssuer that rotates its current value after
// ttl has elapsed since the last rotation.
func NewNonceIssuer(ttl time.Duration) *NonceIssuer {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceIssuer{ttl: ttl}
}

// Issue returns a nonce for the caller to send in a DPoP-Nonce header,
// rotating the active value if its ttl has elapsed.
func (n *NonceIssuer) Issue() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotateLocked()
	if n.current == "" {
		n.current = randomNonce()
		n.rotatedAt = time.Now().UTC()
	}
	return n.current
}

// Valid reports whether nonce is the current or immediately preceding
// server-issued value.
func (n *NonceIssuer) Valid(nonce string) bool {
	if nonce == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rotateLocked()
	return constantTimeEqual(nonce, n.current) || (n.previous != "" && constantTimeEqual(nonce, n.previous))
}

func (n *NonceIssuer) rotateLocked() {
	if n.current == "" {
		return
	}
	if time.Since(n.rotatedAt) < n.ttl {
		return
	}
	n.previous = n.current
	n.current = randomNonce()
	n.rotatedAt = time.Now().UTC()
}

func randomNonce() string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}
