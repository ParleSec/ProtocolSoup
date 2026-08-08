package dpop

import (
	"errors"
	"testing"
	"time"
)

type failingNonceReader struct{}

func (failingNonceReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func mustIssueNonce(t *testing.T, issuer *NonceIssuer) string {
	t.Helper()
	nonce, err := issuer.Issue()
	if err != nil {
		t.Fatalf("Issue() returned error: %v", err)
	}
	return nonce
}

func nonceValid(t *testing.T, issuer *NonceIssuer, nonce string) bool {
	t.Helper()
	valid, err := issuer.Valid(nonce)
	if err != nil {
		t.Fatalf("Valid() returned error: %v", err)
	}
	return valid
}

func TestNonceIssuerIssuesValidatableNonce(t *testing.T) {
	issuer := NewNonceIssuer(time.Minute)
	nonce := mustIssueNonce(t, issuer)
	if nonce == "" {
		t.Fatal("Issue() returned empty nonce")
	}
	if !nonceValid(t, issuer, nonce) {
		t.Fatal("freshly issued nonce should validate")
	}
}

func TestNonceIssuerRejectsUnknownNonce(t *testing.T) {
	issuer := NewNonceIssuer(time.Minute)
	mustIssueNonce(t, issuer)
	if nonceValid(t, issuer, "a-nonce-never-issued-by-this-issuer") {
		t.Fatal("an unrelated nonce must not validate")
	}
	if nonceValid(t, issuer, "") {
		t.Fatal("an empty nonce must never validate")
	}
}

func TestNonceIssuerRotatesAfterTTLButAcceptsPreviousDuringGracePeriod(t *testing.T) {
	issuer := NewNonceIssuer(10 * time.Millisecond)
	first := mustIssueNonce(t, issuer)
	time.Sleep(15 * time.Millisecond)
	second := mustIssueNonce(t, issuer)
	if second == first {
		t.Fatal("nonce should rotate after ttl elapses")
	}
	if !nonceValid(t, issuer, first) {
		t.Fatal("the immediately preceding nonce should remain valid through the grace period")
	}
	if !nonceValid(t, issuer, second) {
		t.Fatal("the current nonce should be valid")
	}
}

func TestNonceIssuerEventuallyExpiresThePreviousNonce(t *testing.T) {
	issuer := NewNonceIssuer(10 * time.Millisecond)
	first := mustIssueNonce(t, issuer)
	time.Sleep(15 * time.Millisecond)
	mustIssueNonce(t, issuer) // rotates: first becomes "previous"
	time.Sleep(15 * time.Millisecond)
	mustIssueNonce(t, issuer) // rotates again: first falls out of the two-value window entirely
	if nonceValid(t, issuer, first) {
		t.Fatal("a nonce two rotations old must no longer validate")
	}
}

func TestNonceIssuerRejectsOldNonceAfterLongIdlePeriod(t *testing.T) {
	issuer := NewNonceIssuer(10 * time.Millisecond)
	old := mustIssueNonce(t, issuer)
	time.Sleep(25 * time.Millisecond)
	if nonceValid(t, issuer, old) {
		t.Fatal("a nonce older than the current and grace windows must not validate")
	}
}

func TestNonceIssuerFailsClosedWhenEntropyUnavailable(t *testing.T) {
	issuer := NewNonceIssuer(time.Minute)
	issuer.random = failingNonceReader{}
	if nonce, err := issuer.Issue(); err == nil || nonce != "" {
		t.Fatalf("Issue() = %q, %v; want empty nonce and entropy error", nonce, err)
	}
}

func TestNewNonceIssuerDefaultsTTLWhenNonPositive(t *testing.T) {
	issuer := NewNonceIssuer(0)
	if issuer.ttl != 5*time.Minute {
		t.Fatalf("default ttl = %s, want 5m", issuer.ttl)
	}
}
