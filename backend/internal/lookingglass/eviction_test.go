package lookingglass

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestSweepExpiredEvictsIdleSession(t *testing.T) {
	engine := newTestEngine(t)
	session, _, err := engine.CreateSession("oauth2", "authorization_code")
	if err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.UpdatedAt = time.Now().Add(-engine.idleTTL - time.Second)
	session.mu.Unlock()

	engine.sweepExpired(time.Now())
	if _, ok := engine.GetSession(session.ID); ok {
		t.Fatal("idle session was not evicted")
	}
}

func TestSweepExpiredEvictsActiveSessionPastMaxTTL(t *testing.T) {
	engine := newTestEngine(t)
	session, _, err := engine.CreateSession("oauth2", "authorization_code")
	if err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.CreatedAt = time.Now().Add(-engine.maxTTL - time.Second)
	session.UpdatedAt = time.Now()
	session.mu.Unlock()

	engine.sweepExpired(time.Now())
	if _, ok := engine.GetSession(session.ID); ok {
		t.Fatal("session past max TTL was not evicted")
	}
}

func TestSweepExpiredKeepsSessionWithinBothTTLs(t *testing.T) {
	engine := newTestEngine(t)
	session, _, err := engine.CreateSession("oauth2", "authorization_code")
	if err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.CreatedAt = time.Now().Add(-time.Minute)
	session.UpdatedAt = time.Now()
	session.mu.Unlock()

	engine.sweepExpired(time.Now())
	if _, ok := engine.GetSession(session.ID); !ok {
		t.Fatal("in-TTL session was evicted")
	}
}

func TestSweepExpiredClosesConnectedClientWithoutPanic(t *testing.T) {
	engine := newTestEngine(t)
	session, ownerToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engine.HandleWebSocket(w, r, session.ID)
	}))
	t.Cleanup(server.Close)
	webSocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	dialer := websocket.Dialer{
		Subprotocols: []string{WebSocketProtocol, WebSocketOwnerProtocolPrefix + ownerToken},
	}
	conn, response, err := dialer.Dial(webSocketURL, nil)
	if err != nil {
		t.Fatalf("dial: response %#v error %v", response, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for {
		session.mu.Lock()
		registered := len(session.clients) > 0
		session.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("websocket client did not register before eviction")
		}
		time.Sleep(5 * time.Millisecond)
	}

	session.mu.Lock()
	session.UpdatedAt = time.Now().Add(-engine.idleTTL - time.Second)
	session.mu.Unlock()
	engine.sweepExpired(time.Now())

	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, readErr := conn.ReadMessage()
		if readErr == nil {
			continue
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatal("expected websocket close after session eviction")
		}
		break
	}
	if _, ok := engine.GetSession(session.ID); ok {
		t.Fatal("evicted session still present")
	}
}

func TestLookingGlassTTLEnvOverrides(t *testing.T) {
	t.Setenv("LOOKINGGLASS_SESSION_IDLE_TTL", "1s")
	t.Setenv("LOOKINGGLASS_SESSION_MAX_TTL", "2s")
	engine := newTestEngine(t)
	if engine.idleTTL != time.Second {
		t.Fatalf("idleTTL = %s, want 1s", engine.idleTTL)
	}
	if engine.maxTTL != 2*time.Second {
		t.Fatalf("maxTTL = %s, want 2s", engine.maxTTL)
	}
}
