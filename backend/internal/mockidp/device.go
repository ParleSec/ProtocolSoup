package mockidp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// DeviceCodeGrantType is the RFC 8628 Section 3.4 grant_type value.
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuthorizationTTL is the lifetime of device_code and user_code
// (RFC 8628 Section 3.2 expires_in). The RFC example uses 1800 seconds.
const DeviceAuthorizationTTL = 1800 * time.Second

// DeviceAuthorizationInterval is the default polling interval (RFC 8628
// Section 3.2: clients MUST use 5 if none is provided).
const DeviceAuthorizationInterval = 5 * time.Second

// deviceUserCodeAlphabet is the RFC 8628 Section 6.1 base-20 charset:
// "BCDFGHJKLMNPQRSTVWXZ". Eight characters yield roughly 34.5 bits of entropy.
const deviceUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

const maxUserCodeFailures = 5

// DeviceAuthorizationStatus is the RFC 8628 polling/authorization state.
type DeviceAuthorizationStatus string

const (
	DeviceAuthPending    DeviceAuthorizationStatus = "pending"
	DeviceAuthAuthorized DeviceAuthorizationStatus = "authorized"
	DeviceAuthDenied     DeviceAuthorizationStatus = "denied"
	DeviceAuthConsumed   DeviceAuthorizationStatus = "consumed"
)

// DeviceAuthorization is one outstanding RFC 8628 device authorization.
type DeviceAuthorization struct {
	DeviceCode     string
	UserCode       string
	ClientID       string
	Scope          string
	Interval       time.Duration
	ExpiresAt      time.Time
	CreatedAt      time.Time
	LastPollAt     time.Time
	Status         DeviceAuthorizationStatus
	UserID         string
	SessionID      string
	FailedAttempts int
}

// DevicePollOutcome is the RFC 8628 Section 3.5 result of a token poll.
type DevicePollOutcome string

const (
	DevicePollUnknown    DevicePollOutcome = "unknown"
	DevicePollPending    DevicePollOutcome = "authorization_pending"
	DevicePollSlowDown   DevicePollOutcome = "slow_down"
	DevicePollDenied     DevicePollOutcome = "access_denied"
	DevicePollExpired    DevicePollOutcome = "expired_token"
	DevicePollConsumed   DevicePollOutcome = "consumed"
	DevicePollMismatch   DevicePollOutcome = "client_mismatch"
	DevicePollAuthorized DevicePollOutcome = "authorized"
)

// CreateDeviceAuthorization issues a device_code and user_code pair
// (RFC 8628 Sections 3.1–3.2).
func (idp *MockIdP) CreateDeviceAuthorization(clientID, scope, sessionID string, now time.Time) (*DeviceAuthorization, error) {
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	deviceCode, err := newDeviceCode()
	if err != nil {
		return nil, err
	}
	userCode, err := newDeviceUserCode()
	if err != nil {
		return nil, err
	}

	auth := &DeviceAuthorization{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		Interval:   DeviceAuthorizationInterval,
		ExpiresAt:  now.Add(DeviceAuthorizationTTL),
		CreatedAt:  now,
		Status:     DeviceAuthPending,
		SessionID:  sessionID,
	}

	idp.mu.Lock()
	defer idp.mu.Unlock()
	for i := 0; i < 8; i++ {
		if _, exists := idp.deviceAuthByUserCode[normalizeUserCode(auth.UserCode)]; !exists {
			break
		}
		next, genErr := newDeviceUserCode()
		if genErr != nil {
			return nil, genErr
		}
		auth.UserCode = next
	}
	idp.deviceAuthByCode[auth.DeviceCode] = auth
	idp.deviceAuthByUserCode[normalizeUserCode(auth.UserCode)] = auth
	return auth, nil
}

// LookupDeviceAuthorizationByUserCode finds a pending device authorization
// by the end-user code (RFC 8628 Section 3.3). Failed lookups increment a
// per-code counter used for the Section 5.1 brute-force mitigation.
func (idp *MockIdP) LookupDeviceAuthorizationByUserCode(userCode string, now time.Time) (*DeviceAuthorization, bool) {
	normalized := normalizeUserCode(userCode)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	if !exists || auth == nil {
		return nil, false
	}
	if !now.Before(auth.ExpiresAt) || auth.Status != DeviceAuthPending {
		auth.FailedAttempts++
		return nil, false
	}
	if auth.FailedAttempts >= maxUserCodeFailures {
		return nil, false
	}
	return auth, true
}

// PeekDeviceAuthorizationByUserCode returns a copy of the pending device authorization
func (idp *MockIdP) PeekDeviceAuthorizationByUserCode(userCode string) *DeviceAuthorization {
	normalized := normalizeUserCode(userCode)
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	if !exists || auth == nil {
		return nil
	}
	copy := *auth
	return &copy
}

// RecordUserCodeFailure records an unsuccessful user_code interaction
// (RFC 8628 Section 5.1).
func (idp *MockIdP) RecordUserCodeFailure(userCode string) int {
	normalized := normalizeUserCode(userCode)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	if !exists || auth == nil {
		return 0
	}
	auth.FailedAttempts++
	return auth.FailedAttempts
}

// UserCodeLocked reports whether a user_code has exceeded the brute-force budget.
func (idp *MockIdP) UserCodeLocked(userCode string) bool {
	normalized := normalizeUserCode(userCode)
	idp.mu.RLock()
	defer idp.mu.RUnlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	return exists && auth != nil && auth.FailedAttempts >= maxUserCodeFailures
}

// AuthorizeDeviceAuthorization records end-user approval (RFC 8628 Section 3.3).
func (idp *MockIdP) AuthorizeDeviceAuthorization(userCode, userID string, now time.Time) error {
	normalized := normalizeUserCode(userCode)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	if !exists || auth == nil {
		return errors.New("unknown user_code")
	}
	if !now.Before(auth.ExpiresAt) {
		return errors.New("expired user_code")
	}
	if auth.Status != DeviceAuthPending {
		return errors.New("user_code already used")
	}
	if auth.FailedAttempts >= maxUserCodeFailures {
		return errors.New("user_code locked")
	}
	auth.Status = DeviceAuthAuthorized
	auth.UserID = userID
	return nil
}

// DenyDeviceAuthorization records end-user denial (RFC 8628 Section 3.5 access_denied).
func (idp *MockIdP) DenyDeviceAuthorization(userCode string, now time.Time) error {
	normalized := normalizeUserCode(userCode)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	auth, exists := idp.deviceAuthByUserCode[normalized]
	if !exists || auth == nil {
		return errors.New("unknown user_code")
	}
	if !now.Before(auth.ExpiresAt) {
		return errors.New("expired user_code")
	}
	if auth.Status != DeviceAuthPending {
		return errors.New("user_code already used")
	}
	auth.Status = DeviceAuthDenied
	return nil
}

// PollDeviceAuthorization evaluates a token-endpoint poll (RFC 8628 Section 3.5).
// A successful authorized poll consumes the device_code so it cannot be reused.
func (idp *MockIdP) PollDeviceAuthorization(deviceCode, clientID string, now time.Time) (DevicePollOutcome, *DeviceAuthorization) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	auth, exists := idp.deviceAuthByCode[deviceCode]
	if !exists || auth == nil {
		return DevicePollUnknown, nil
	}
	if clientID != "" && auth.ClientID != clientID {
		return DevicePollMismatch, auth
	}
	if !now.Before(auth.ExpiresAt) {
		return DevicePollExpired, auth
	}
	switch auth.Status {
	case DeviceAuthDenied:
		return DevicePollDenied, auth
	case DeviceAuthConsumed:
		return DevicePollConsumed, auth
	case DeviceAuthAuthorized:
		auth.Status = DeviceAuthConsumed
		copy := *auth
		return DevicePollAuthorized, &copy
	case DeviceAuthPending:
		if !auth.LastPollAt.IsZero() && now.Sub(auth.LastPollAt) < auth.Interval {
			auth.Interval += 5 * time.Second
			auth.LastPollAt = now
			copy := *auth
			return DevicePollSlowDown, &copy
		}
		auth.LastPollAt = now
		copy := *auth
		return DevicePollPending, &copy
	default:
		return DevicePollUnknown, auth
	}
}

// ExpireDeviceAuthorization forces a device authorization past its expires_in
// so tests can exercise RFC 8628 Section 3.5 expired_token without waiting.
func (idp *MockIdP) ExpireDeviceAuthorization(deviceCode string, now time.Time) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if auth, exists := idp.deviceAuthByCode[deviceCode]; exists && auth != nil {
		auth.ExpiresAt = now.Add(-time.Second)
	}
}

func newDeviceCode() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newDeviceUserCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, b := range buf {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, deviceUserCodeAlphabet[int(b)%len(deviceUserCodeAlphabet)])
	}
	return string(out), nil
}

func normalizeUserCode(input string) string {
	trimmed := strings.ToUpper(strings.TrimSpace(input))
	var b strings.Builder
	for _, r := range trimmed {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
