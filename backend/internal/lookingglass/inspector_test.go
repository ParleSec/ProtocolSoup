package lookingglass

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine := NewEngine()
	t.Cleanup(engine.Stop)
	return engine
}

func TestSessionOwnerCapabilityAuthorizesOnlyItsSession(t *testing.T) {
	engine := newTestEngine(t)
	first, firstToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	second, secondToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}

	if _, authorized := engine.AuthorizeOwner(first.ID, firstToken); !authorized {
		t.Fatal("first owner capability was rejected")
	}
	if _, authorized := engine.AuthorizeOwner(first.ID, secondToken); authorized {
		t.Fatal("another session's owner capability was accepted")
	}
	if _, authorized := engine.AuthorizeOwner(second.ID, firstToken); authorized {
		t.Fatal("owner capability crossed session boundary")
	}
	if _, authorized := engine.AuthorizeOwner(first.ID, ""); authorized {
		t.Fatal("empty owner capability was accepted")
	}
}

func TestPrivateKeyJWTRegistrationClaimIsAtomicAndOneShot(t *testing.T) {
	engine := newTestEngine(t)
	session, ownerToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}

	var accepted atomic.Int32
	var conflicts atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			claimErr := engine.ClaimPrivateKeyJWTRegistration(session.ID, ownerToken)
			switch {
			case claimErr == nil:
				accepted.Add(1)
			case errors.Is(claimErr, ErrPrivateKeyJWTAlreadyRegistered):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected claim error: %v", claimErr)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || conflicts.Load() != 31 {
		t.Fatalf("accepted = %d, conflicts = %d", accepted.Load(), conflicts.Load())
	}
}

func TestPrivateKeyJWTRegistrationRequiresActiveMatchingSession(t *testing.T) {
	engine := newTestEngine(t)
	wrongFlow, wrongFlowToken, err := engine.CreateSession("oauth2", "authorization_code")
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ClaimPrivateKeyJWTRegistration(wrongFlow.ID, wrongFlowToken); !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("wrong-flow error = %v", err)
	}

	inactive, inactiveToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	inactive.mu.Lock()
	inactive.State = SessionStateComplete
	inactive.mu.Unlock()
	if err := engine.ClaimPrivateKeyJWTRegistration(inactive.ID, inactiveToken); !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("inactive-session error = %v", err)
	}
	if err := engine.ClaimPrivateKeyJWTRegistration(inactive.ID, "wrong"); !errors.Is(err, ErrSessionOwnerUnauthorized) {
		t.Fatalf("wrong-owner error = %v", err)
	}
}
