package lookingglass

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// Client represents a WebSocket client connection
type Client struct {
	conn    *websocket.Conn
	send    chan []byte
	session *Session
}

// Message represents a WebSocket message
type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// HandleWebSocket handles WebSocket connections for looking glass
func (e *Engine) HandleWebSocket(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, exists := e.GetSession(sessionID)
	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		conn:    conn,
		send:    make(chan []byte, 256),
		session: session,
	}

	// Register client with session
	session.registerClient(client)

	// Start client goroutines
	go client.writePump()
	go client.readPump()

	// Send existing events to the new client
	client.sendHistory()
}

func (s *Session) registerClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client] = true
}

func (s *Session) unregisterClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[client]; ok {
		delete(s.clients, client)
		close(client.send)
	}
}

func (s *Session) broadcast(event Event) {
	msg := Message{
		Type:    string(event.Type),
		Payload: event,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for client := range s.clients {
		select {
		case client.send <- data:
		default:
			// Client buffer full, skip
		}
	}
}

func (c *Client) sendHistory() {
	c.session.mu.RLock()
	events := make([]Event, len(c.session.Events))
	copy(events, c.session.Events)
	c.session.mu.RUnlock()

	// Send session info first
	sessionInfo := Message{
		Type: "session.info",
		Payload: map[string]interface{}{
			"id":          c.session.ID,
			"protocol_id": c.session.ProtocolID,
			"flow_id":     c.session.FlowID,
			"state":       c.session.State,
			"created_at":  c.session.CreatedAt,
		},
	}
	data, _ := json.Marshal(sessionInfo)
	c.send <- data

	// Send historical events
	for _, event := range events {
		msg := Message{
			Type:    string(event.Type),
			Payload: event,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		c.send <- data
	}
}

func (c *Client) readPump() {
	defer func() {
		c.session.unregisterClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Handle incoming messages (commands from client)
		c.handleMessage(message)
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current write
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) handleMessage(message []byte) {
	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		return
	}

	switch msg.Type {
	case "session.pause":
		c.session.mu.Lock()
		c.session.State = SessionStatePaused
		c.session.mu.Unlock()
	case "session.resume":
		c.session.mu.Lock()
		c.session.State = SessionStateActive
		c.session.mu.Unlock()
	case "session.complete":
		c.session.mu.Lock()
		c.session.State = SessionStateComplete
		c.session.mu.Unlock()
	}
}

// EventBroadcaster provides a way to broadcast events from protocol plugins
type EventBroadcaster struct {
	engine    *Engine
	sessionID string
	mu        sync.RWMutex //nolint:unused // Reserved for future thread-safe event batching
}

// NewEventBroadcaster creates a broadcaster for a specific session
func (e *Engine) NewEventBroadcaster(sessionID string) *EventBroadcaster {
	return &EventBroadcaster{
		engine:    e,
		sessionID: sessionID,
	}
}

// Emit sends an event to the session
func (b *EventBroadcaster) Emit(eventType EventType, title string, data map[string]interface{}, annotations ...Annotation) {
	b.engine.AddEvent(b.sessionID, Event{
		Type:        eventType,
		Timestamp:   time.Now(),
		Title:       title,
		Data:        data,
		Annotations: annotations,
	})
}

// EmitFlowStep emits a flow step event
func (b *EventBroadcaster) EmitFlowStep(step int, name string, from string, to string, data map[string]interface{}) {
	b.Emit(EventTypeFlowStep, name, map[string]interface{}{
		"step": step,
		"from": from,
		"to":   to,
		"data": data,
	})
}

// EmitTokenIssued emits a token issued event
func (b *EventBroadcaster) EmitTokenIssued(tokenType string, claims map[string]interface{}) {
	b.Emit(EventTypeTokenIssued, "Token Issued: "+tokenType, map[string]interface{}{
		"token_type": tokenType,
		"claims":     claims,
	})
}

// EmitRequest emits an HTTP request event
func (b *EventBroadcaster) EmitRequest(method string, url string, headers map[string]string, body interface{}) {
	b.Emit(EventTypeRequestSent, method+" "+url, map[string]interface{}{
		"method":  method,
		"url":     url,
		"headers": headers,
		"body":    body,
	})
}

// EmitResponse emits an HTTP response event
func (b *EventBroadcaster) EmitResponse(status int, headers map[string]string, body interface{}) {
	b.Emit(EventTypeResponseReceived, "Response "+string(rune(status)), map[string]interface{}{
		"status":  status,
		"headers": headers,
		"body":    body,
	})
}

// EmitHTTPExchange emits a captured HTTP request/response pair
func (b *EventBroadcaster) EmitHTTPExchange(title string, exchange CapturedExchange) {
	b.Emit(EventTypeHTTPExchange, title, map[string]interface{}{
		"exchange": exchange,
	})
}
