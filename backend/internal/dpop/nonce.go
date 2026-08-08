package dpop

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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
	random    io.Reader
}

// NewNonceIssuer creates a NonceIssuer that rotates its current value after
// ttl has elapsed since the last rotation.
func NewNonceIssuer(ttl time.Duration) *NonceIssuer {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceIssuer{ttl: ttl, random: rand.Reader}
}

// Issue returns a nonce for the caller to send in a DPoP-Nonce header,
// rotating the active value if its ttl has elapsed.
func (n *NonceIssuer) Issue() (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.rotateLocked(); err != nil {
		return "", err
	}
	if n.current == "" {
		nonce, err := randomNonce(n.random)
		if err != nil {
			return "", err
		}
		n.current = nonce
		n.rotatedAt = time.Now().UTC()
	}
	return n.current, nil
}

// Valid reports whether nonce is the current or immediately preceding
// server-issued value.
func (n *NonceIssuer) Valid(nonce string) (bool, error) {
	if nonce == "" {
		return false, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.rotateLocked(); err != nil {
		return false, err
	}
	return constantTimeEqual(nonce, n.current) || (n.previous != "" && constantTimeEqual(nonce, n.previous)), nil
}

func (n *NonceIssuer) rotateLocked() error {
	if n.current == "" {
		return nil
	}
	elapsed := time.Since(n.rotatedAt)
	if elapsed < n.ttl {
		return nil
	}
	if elapsed < 2*n.ttl {
		n.previous = n.current
	} else {
		n.previous = ""
	}
	next, err := randomNonce(n.random)
	if err != nil {
		return err
	}
	n.current = next
	n.rotatedAt = time.Now().UTC()
	return nil
}

func randomNonce(source io.Reader) (string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", fmt.Errorf("generate DPoP nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
