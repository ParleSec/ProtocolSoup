package dpop

import (
	"testing"
	"time"
)

func TestNonceIssuerIssuesValidatableNonce(t *testing.T) {
	issuer := NewNonceIssuer(time.Minute)
	nonce := issuer.Issue()
	if nonce == "" {
		t.Fatal("Issue() returned empty nonce")
	}
	if !issuer.Valid(nonce) {
		t.Fatal("freshly issued nonce should validate")
	}
}

func TestNonceIssuerRejectsUnknownNonce(t *testing.T) {
	issuer := NewNonceIssuer(time.Minute)
	issuer.Issue()
	if issuer.Valid("a-nonce-never-issued-by-this-issuer") {
		t.Fatal("an unrelated nonce must not validate")
	}
	if issuer.Valid("") {
		t.Fatal("an empty nonce must never validate")
	}
}

func TestNonceIssuerRotatesAfterTTLButAcceptsPreviousDuringGracePeriod(t *testing.T) {
	issuer := NewNonceIssuer(10 * time.Millisecond)
	first := issuer.Issue()
	time.Sleep(15 * time.Millisecond)
	second := issuer.Issue()
	if second == first {
		t.Fatal("nonce should rotate after ttl elapses")
	}
	if !issuer.Valid(first) {
		t.Fatal("the immediately preceding nonce should remain valid through the grace period")
	}
	if !issuer.Valid(second) {
		t.Fatal("the current nonce should be valid")
	}
}

func TestNonceIssuerEventuallyExpiresThePreviousNonce(t *testing.T) {
	issuer := NewNonceIssuer(10 * time.Millisecond)
	first := issuer.Issue()
	time.Sleep(15 * time.Millisecond)
	issuer.Issue() // rotates: first becomes "previous"
	time.Sleep(15 * time.Millisecond)
	issuer.Issue() // rotates again: first falls out of the two-value window entirely
	if issuer.Valid(first) {
		t.Fatal("a nonce two rotations old must no longer validate")
	}
}

func TestNewNonceIssuerDefaultsTTLWhenNonPositive(t *testing.T) {
	issuer := NewNonceIssuer(0)
	if issuer.ttl != 5*time.Minute {
		t.Fatalf("default ttl = %s, want 5m", issuer.ttl)
	}
}
