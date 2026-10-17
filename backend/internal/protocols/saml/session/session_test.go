package session

import (
	"testing"
	"time"
)

func TestPendingRequestIsConsumedOnce(t *testing.T) {
	pending := NewPending(time.Minute)
	pending.Store(PendingRequest{ID: "_a", RelayState: "rs"})
	if req, ok := pending.Take("_a"); !ok || req.RelayState != "rs" {
		t.Fatalf("first Take = %+v, %v", req, ok)
	}
	if _, ok := pending.Take("_a"); ok {
		t.Fatal("request ID matched twice")
	}
}

func TestReplayCache(t *testing.T) {
	cache := NewReplayCache()
	if !cache.Consume("_x", time.Now().Add(time.Minute)) {
		t.Fatal("fresh ID reported as replay")
	}
	if cache.Consume("_x", time.Now().Add(time.Minute)) {
		t.Fatal("replayed ID accepted")
	}
}

func TestLogoutRecordsMatchSessionIndex(t *testing.T) {
	var records LogoutRecords
	records.Add(LogoutRecord{NameID: "alice@example.com", SessionIndexes: []string{"_s1"}, Until: time.Now().Add(time.Minute)})
	if !records.Matches("alice@example.com", []string{"_s1"}) {
		t.Fatal("logout for _s1 not applied")
	}
	if records.Matches("alice@example.com", []string{"_s2"}) {
		t.Fatal("logout for _s1 applied to _s2")
	}
	records.Add(LogoutRecord{NameID: "bob@example.com", Until: time.Now().Add(time.Minute)})
	if !records.Matches("bob@example.com", []string{"_any"}) {
		t.Fatal("logout without SessionIndex must cover every session (SAML Core Section 3.7.3.1)")
	}
	records.Add(LogoutRecord{NameID: "carol@example.com", Until: time.Now().Add(-time.Second)})
	if records.Matches("carol@example.com", nil) {
		t.Fatal("expired logout record still applied")
	}
}

func TestStoreRemoveMatching(t *testing.T) {
	store := NewStore()
	store.Add(&Session{PeerEntityID: "https://sp", NameID: "alice", SessionIndex: "_1"})
	store.Add(&Session{PeerEntityID: "https://sp", NameID: "alice", SessionIndex: "_2"})
	store.Add(&Session{PeerEntityID: "https://other", NameID: "alice", SessionIndex: "_3"})
	if removed := store.RemoveMatching("https://sp", "alice", []string{"_1"}); len(removed) != 1 {
		t.Fatalf("removed %d sessions, want 1", len(removed))
	}
	if removed := store.RemoveMatching("https://sp", "alice", nil); len(removed) != 1 {
		t.Fatalf("removed %d sessions, want the remaining 1", len(removed))
	}
	if len(store.List()) != 1 {
		t.Fatal("a session with another peer was removed")
	}
}
