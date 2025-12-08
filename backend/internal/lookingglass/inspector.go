package lookingglass

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

// Engine is the main looking glass inspection engine
type Engine struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewEngine creates a new looking glass engine
func NewEngine() *Engine {
	return &Engine{
		sessions: make(map[string]*Session),
	}
}

// Session represents an active looking glass session
type Session struct {
	ID         string       `json:"id"`
	ProtocolID string       `json:"protocol_id"`
	FlowID     string       `json:"flow_id"`
	Events     []Event      `json:"events"`
	State      SessionState `json:"state"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`

	// WebSocket connections for this session
	clients map[*Client]bool
	mu      sync.RWMutex
}

// SessionState represents the state of a looking glass session
type SessionState string

const (
	SessionStateActive   SessionState = "active"
	SessionStatePaused   SessionState = "paused"
	SessionStateComplete SessionState = "complete"
)

// Event represents a protocol event captured by looking glass
type Event struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Annotations []Annotation           `json:"annotations,omitempty"`
}

// EventType categorizes looking glass events
type EventType string

const (
	EventTypeFlowStep       EventType = "flow.step"
	EventTypeTokenIssued    EventType = "token.issued"
	EventTypeTokenValidated EventType = "token.validated"
	EventTypeRequestSent    EventType = "request.sent"
	EventTypeResponseReceived EventType = "response.received"
	EventTypeSecurityWarning EventType = "security.warning"
	EventTypeSecurityInfo    EventType = "security.info"
	EventTypeCryptoOperation EventType = "crypto.operation"
)

// Annotation provides security context for events
type Annotation struct {
	Type        AnnotationType `json:"type"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    string         `json:"severity,omitempty"` // info, warning, error
	Reference   string         `json:"reference,omitempty"` // RFC or spec reference
}

// AnnotationType categorizes annotations
type AnnotationType string

const (
	AnnotationTypeSecurityHint   AnnotationType = "security_hint"
	AnnotationTypeBestPractice   AnnotationType = "best_practice"
	AnnotationTypeRFCReference   AnnotationType = "rfc_reference"
	AnnotationTypeVulnerability  AnnotationType = "vulnerability"
	AnnotationTypeExplanation    AnnotationType = "explanation"
)

// CreateSession creates a new looking glass session
func (e *Engine) CreateSession(protocolID, flowID string) *Session {
	e.mu.Lock()
	defer e.mu.Unlock()

	session := &Session{
		ID:         uuid.New().String(),
		ProtocolID: protocolID,
		FlowID:     flowID,
		Events:     make([]Event, 0),
		State:      SessionStateActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		clients:    make(map[*Client]bool),
	}

	e.sessions[session.ID] = session
	return session
}

// GetSession retrieves a session by ID
func (e *Engine) GetSession(id string) (*Session, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	session, exists := e.sessions[id]
	return session, exists
}

// ListSessions returns all active sessions
func (e *Engine) ListSessions() []*Session {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sessions := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// DeleteSession removes a session
func (e *Engine) DeleteSession(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.sessions, id)
}

// AddEvent adds an event to a session and broadcasts to clients
func (e *Engine) AddEvent(sessionID string, event Event) {
	e.mu.RLock()
	session, exists := e.sessions[sessionID]
	e.mu.RUnlock()

	if !exists {
		return
	}

	event.ID = uuid.New().String()
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	session.mu.Lock()
	session.Events = append(session.Events, event)
	session.UpdatedAt = time.Now()
	session.mu.Unlock()

	// Broadcast to connected clients
	session.broadcast(event)
}

// DecodeToken decodes a token for inspection
func (e *Engine) DecodeToken(tokenString string, keySet *crypto.KeySet) (*TokenInspection, error) {
	decoded, err := crypto.DecodeTokenWithoutValidation(tokenString)
	if err != nil {
		return nil, err
	}

	inspection := &TokenInspection{
		Header:      decoded.Header,
		Payload:     decoded.Payload,
		Signature:   decoded.Signature,
		HeaderRaw:   decoded.HeaderRaw,
		PayloadRaw:  decoded.PayloadRaw,
		Annotations: make([]Annotation, 0),
	}

	// Add annotations based on token contents
	inspection.addTokenAnnotations()

	// Verify signature if key set provided
	if keySet != nil {
		jwtService := crypto.NewJWTService(keySet, "")
		pubKey, alg, err := jwtService.GetPublicKeyForToken(tokenString)
		if err == nil {
			valid, _ := crypto.VerifySignatureWithKey(tokenString, pubKey)
			inspection.SignatureValid = valid
			inspection.Algorithm = alg
		}
	}

	return inspection, nil
}

// TokenInspection represents a decoded and annotated token
type TokenInspection struct {
	Header         map[string]interface{} `json:"header"`
	Payload        map[string]interface{} `json:"payload"`
	Signature      string                 `json:"signature"`
	HeaderRaw      string                 `json:"header_raw"`
	PayloadRaw     string                 `json:"payload_raw"`
	SignatureValid bool                   `json:"signature_valid"`
	Algorithm      string                 `json:"algorithm"`
	Annotations    []Annotation           `json:"annotations"`
}

func (ti *TokenInspection) addTokenAnnotations() {
	// Check for standard claims and add explanations
	if iss, ok := ti.Payload["iss"]; ok {
		ti.Annotations = append(ti.Annotations, Annotation{
			Type:        AnnotationTypeExplanation,
			Title:       "Issuer (iss)",
			Description: formatValue("Identifies the principal that issued the JWT", iss),
			Reference:   "RFC 7519 Section 4.1.1",
		})
	}

	if sub, ok := ti.Payload["sub"]; ok {
		ti.Annotations = append(ti.Annotations, Annotation{
			Type:        AnnotationTypeExplanation,
			Title:       "Subject (sub)",
			Description: formatValue("Identifies the subject of the JWT", sub),
			Reference:   "RFC 7519 Section 4.1.2",
		})
	}

	if aud, ok := ti.Payload["aud"]; ok {
		ti.Annotations = append(ti.Annotations, Annotation{
			Type:        AnnotationTypeExplanation,
			Title:       "Audience (aud)",
			Description: formatValue("Identifies the recipients the JWT is intended for", aud),
			Reference:   "RFC 7519 Section 4.1.3",
		})
	}

	if exp, ok := ti.Payload["exp"]; ok {
		expTime := parseUnixTime(exp)
		if expTime.Before(time.Now()) {
			ti.Annotations = append(ti.Annotations, Annotation{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Token Expired",
				Description: "This token has expired and should not be accepted",
				Severity:    "warning",
			})
		}
	}

	// Check algorithm
	if alg, ok := ti.Header["alg"].(string); ok {
		if alg == "none" {
			ti.Annotations = append(ti.Annotations, Annotation{
				Type:        AnnotationTypeVulnerability,
				Title:       "Insecure Algorithm",
				Description: "The 'none' algorithm provides no signature verification - critical security risk!",
				Severity:    "error",
			})
		} else if alg == "HS256" || alg == "HS384" || alg == "HS512" {
			ti.Annotations = append(ti.Annotations, Annotation{
				Type:        AnnotationTypeBestPractice,
				Title:       "Symmetric Algorithm",
				Description: "HMAC algorithms use symmetric keys. Ensure the secret is kept confidential and is sufficiently strong.",
				Severity:    "info",
			})
		}
	}

	// Check for OIDC specific claims
	if _, ok := ti.Payload["nonce"]; ok {
		ti.Annotations = append(ti.Annotations, Annotation{
			Type:        AnnotationTypeExplanation,
			Title:       "Nonce",
			Description: "OIDC nonce claim - used to mitigate replay attacks",
			Reference:   "OpenID Connect Core 1.0 Section 3.1.2.1",
		})
	}

	if _, ok := ti.Payload["auth_time"]; ok {
		ti.Annotations = append(ti.Annotations, Annotation{
			Type:        AnnotationTypeExplanation,
			Title:       "Authentication Time",
			Description: "Time when the End-User authentication occurred",
			Reference:   "OpenID Connect Core 1.0 Section 2",
		})
	}
}

func formatValue(desc string, value interface{}) string {
	return desc + ": " + formatInterface(value)
}

func formatInterface(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return time.Unix(int64(val), 0).Format(time.RFC3339)
	default:
		return ""
	}
}

func parseUnixTime(v interface{}) time.Time {
	switch val := v.(type) {
	case float64:
		return time.Unix(int64(val), 0)
	case int64:
		return time.Unix(val, 0)
	default:
		return time.Time{}
	}
}

