package lookingglass

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestLookingGlassWebSocketRequiresOwnerSubprotocol(t *testing.T) {
	engine := NewEngine()
	t.Cleanup(engine.Stop)
	session, ownerToken, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engine.HandleWebSocket(w, r, session.ID)
	}))
	t.Cleanup(server.Close)
	webSocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	unauthorizedDialer := websocket.Dialer{
		Subprotocols: []string{WebSocketProtocol, WebSocketOwnerProtocolPrefix + "wrong"},
	}
	_, response, err := unauthorizedDialer.Dial(webSocketURL, nil)
	if err == nil {
		t.Fatal("WebSocket accepted an invalid owner capability")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized response = %#v, error = %v", response, err)
	}

	authorizedDialer := websocket.Dialer{
		Subprotocols: []string{WebSocketProtocol, WebSocketOwnerProtocolPrefix + ownerToken},
	}
	connection, response, err := authorizedDialer.Dial(webSocketURL, nil)
	if err != nil {
		t.Fatalf("authorized WebSocket failed: response %#v, error %v", response, err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if connection.Subprotocol() != WebSocketProtocol {
		t.Fatalf("negotiated subprotocol = %q", connection.Subprotocol())
	}
}

func TestSendHistoryStopsWhenClientUnregisters(t *testing.T) {
	engine := NewEngine()
	t.Cleanup(engine.Stop)
	session, _, err := engine.CreateSession("oauth2", "client_credentials")
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		send:    make(chan []byte),
		done:    make(chan struct{}),
		session: session,
	}
	session.registerClient(client)

	historyDone := make(chan struct{})
	go func() {
		client.sendHistory()
		close(historyDone)
	}()

	session.unregisterClient(client)
	session.unregisterClient(client)

	select {
	case <-historyDone:
	case <-time.After(time.Second):
		t.Fatal("sendHistory did not stop after client unregistration")
	}
}
