package ssf

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SETSubject represents the subject identifier in a SET
type SETSubject struct {
	Format      string `json:"format"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Issuer      string `json:"iss,omitempty"`
	Subject     string `json:"sub,omitempty"`
	ID          string `json:"id,omitempty"`
	URI         string `json:"uri,omitempty"`
}

// SETClaims extends jwt.RegisteredClaims with SET-specific fields
type SETClaims struct {
	jwt.RegisteredClaims
	Events        map[string]interface{} `json:"events"`
	SubjectID     *SETSubject            `json:"sub_id,omitempty"`
	TransactionID string                 `json:"txn,omitempty"`
}

// EventPayload represents the payload within an event
type EventPayload struct {
	Subject          *SETSubject `json:"subject,omitempty"`
	EventTimestamp   int64       `json:"event_timestamp,omitempty"`
	Reason           string      `json:"reason,omitempty"`
	InitiatingEntity string      `json:"initiating_entity,omitempty"`
	ReasonAdmin      *ReasonInfo `json:"reason_admin,omitempty"`
	ReasonUser       *ReasonInfo `json:"reason_user,omitempty"`
	CredentialType   string      `json:"credential_type,omitempty"`
	ChangeType       string      `json:"change_type,omitempty"`    // CAEP §3.2: create | revoke | update
	CurrentStatus    string      `json:"current_status,omitempty"` // For device compliance change (CAEP §3.4)
	PreviousStatus   string      `json:"previous_status,omitempty"`
	CurrentLevel     string      `json:"current_level,omitempty"`  // For assurance level change (CAEP §3.3)
	PreviousLevel    string      `json:"previous_level,omitempty"`
	NewValue         string                 `json:"new-value,omitempty"`
	OldValue         string                 `json:"old-value,omitempty"`
	Claims           map[string]interface{} `json:"claims,omitempty"` // CAEP §3.2: changed claims
	State            string                 `json:"state,omitempty"`  // SSF §7: verification event state
}

// SETEncoder handles encoding security events into SET tokens
type SETEncoder struct {
	issuer     string
	privateKey *rsa.PrivateKey
	keyID      string
}

// NewSETEncoder creates a new SET encoder
func NewSETEncoder(issuer string, privateKey *rsa.PrivateKey, keyID string) *SETEncoder {
	return &SETEncoder{
		issuer:     issuer,
		privateKey: privateKey,
		keyID:      keyID,
	}
}

// Encode creates a signed SET from a SecurityEvent.
// The jti parameter is the unique token identifier (RFC 8417 §2.2) and MUST
// match the event ID used in poll responses so receivers can acknowledge by JTI.
func (e *SETEncoder) Encode(event SecurityEvent, audience []string, jti string) (string, error) {
	now := time.Now()

	// Build subject identifier
	subject := &SETSubject{
		Format: event.Subject.Format,
	}
	switch event.Subject.Format {
	case SubjectFormatEmail:
		subject.Email = event.Subject.Email
	case SubjectFormatPhone:
		subject.PhoneNumber = event.Subject.PhoneNumber
	case SubjectFormatIssuerSub:
		subject.Issuer = event.Subject.Issuer
		subject.Subject = event.Subject.Subject
	case SubjectFormatOpaque:
		subject.ID = event.Subject.ID
	case SubjectFormatURI:
		subject.URI = event.Subject.URI
	}

	// Build event payload
	eventPayload := EventPayload{
		Subject:          subject,
		EventTimestamp:   event.EventTimestamp.Unix(),
		InitiatingEntity: event.InitiatingEntity,
	}

	if event.Reason != "" {
		eventPayload.Reason = event.Reason
	}
	if event.ReasonAdmin != nil {
		eventPayload.ReasonAdmin = event.ReasonAdmin
	}
	if event.ReasonUser != nil {
		eventPayload.ReasonUser = event.ReasonUser
	}
	if event.CredentialType != "" {
		eventPayload.CredentialType = event.CredentialType
	}
	if event.ChangeType != "" {
		eventPayload.ChangeType = event.ChangeType
	}
	if event.CurrentStatus != "" {
		eventPayload.CurrentStatus = event.CurrentStatus
	}
	if event.PreviousStatus != "" {
		eventPayload.PreviousStatus = event.PreviousStatus
	}
	if event.CurrentLevel != "" {
		eventPayload.CurrentLevel = event.CurrentLevel
	}
	if event.PreviousLevel != "" {
		eventPayload.PreviousLevel = event.PreviousLevel
	}
	if event.NewValue != "" {
		eventPayload.NewValue = event.NewValue
	}
	if event.OldValue != "" {
		eventPayload.OldValue = event.OldValue
	}
	if len(event.Claims) > 0 {
		eventPayload.Claims = event.Claims
	}
	if event.State != "" {
		eventPayload.State = event.State
	}

	// Create claims
	claims := SETClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   e.issuer,
			Audience: audience,
			IssuedAt: jwt.NewNumericDate(now),
			ID:       jti,
		},
		Events: map[string]interface{}{
			event.EventType: eventPayload,
		},
		SubjectID:     subject,
		TransactionID: event.TransactionID,
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = e.keyID
	token.Header["typ"] = "secevent+jwt"

	signedToken, err := token.SignedString(e.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign SET: %w", err)
	}

	return signedToken, nil
}

// SETDecoder handles decoding and validating SET tokens
type SETDecoder struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// NewSETDecoder creates a new SET decoder
func NewSETDecoder(publicKey *rsa.PublicKey, issuer, audience string) *SETDecoder {
	return &SETDecoder{
		publicKey: publicKey,
		issuer:    issuer,
		audience:  audience,
	}
}

// Decode parses and validates a SET token
func (d *SETDecoder) Decode(tokenString string) (*DecodedSET, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SETClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return d.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		return nil, fmt.Errorf("failed to parse SET: %w", err)
	}

	claims, ok := token.Claims.(*SETClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid SET claims")
	}

	// Validate issuer
	if d.issuer != "" && claims.Issuer != d.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", d.issuer, claims.Issuer)
	}

	// Validate audience
	if d.audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == d.audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid audience: expected %s", d.audience)
		}
	}

	// Extract event information
	decoded := &DecodedSET{
		JTI:           claims.ID,
		Issuer:        claims.Issuer,
		Audience:      claims.Audience,
		IssuedAt:      claims.IssuedAt.Time,
		Subject:       claims.SubjectID,
		TransactionID: claims.TransactionID,
		Events:        []DecodedEvent{},
		RawToken:      tokenString,
		Header:        token.Header,
	}

	// Parse events
	for eventType, payload := range claims.Events {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		var eventPayload EventPayload
		if err := json.Unmarshal(payloadBytes, &eventPayload); err != nil {
			continue
		}

		metadata := GetEventMetadata(eventType)
		decoded.Events = append(decoded.Events, DecodedEvent{
			Type:            eventType,
			Metadata:        metadata,
			Payload:         eventPayload,
			RawPayload:      payload,
		})
	}

	return decoded, nil
}

// DecodeWithoutValidation parses a SET without signature validation (for inspection)
func DecodeWithoutValidation(tokenString string) (*DecodedSET, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &SETClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse SET: %w", err)
	}

	claims, ok := token.Claims.(*SETClaims)
	if !ok {
		return nil, fmt.Errorf("invalid SET claims")
	}

	decoded := &DecodedSET{
		JTI:           claims.ID,
		Issuer:        claims.Issuer,
		Audience:      claims.Audience,
		Subject:       claims.SubjectID,
		TransactionID: claims.TransactionID,
		Events:        []DecodedEvent{},
		RawToken:      tokenString,
		Header:        token.Header,
	}

	if claims.IssuedAt != nil {
		decoded.IssuedAt = claims.IssuedAt.Time
	}

	// Parse events
	for eventType, payload := range claims.Events {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		var eventPayload EventPayload
		if err := json.Unmarshal(payloadBytes, &eventPayload); err != nil {
			continue
		}

		metadata := GetEventMetadata(eventType)
		decoded.Events = append(decoded.Events, DecodedEvent{
			Type:       eventType,
			Metadata:   metadata,
			Payload:    eventPayload,
			RawPayload: payload,
		})
	}

	return decoded, nil
}

// DecodedSET represents a parsed SET token
type DecodedSET struct {
	JTI           string                 `json:"jti"`
	Issuer        string                 `json:"iss"`
	Audience      []string               `json:"aud"`
	IssuedAt      time.Time              `json:"iat"`
	Subject       *SETSubject            `json:"sub_id"`
	TransactionID string                 `json:"txn,omitempty"`
	Events        []DecodedEvent         `json:"events"`
	RawToken      string                 `json:"raw_token"`
	Header        map[string]interface{} `json:"header"`
}

// DecodedEvent represents a parsed event from a SET
type DecodedEvent struct {
	Type       string        `json:"type"`
	Metadata   EventMetadata `json:"metadata"`
	Payload    EventPayload  `json:"payload"`
	RawPayload interface{}   `json:"raw_payload"`
}



