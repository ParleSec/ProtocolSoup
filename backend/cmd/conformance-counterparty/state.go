package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// counterparty holds the keys every scenario signs or decrypts with and the
// little state an exchange needs between requests. Keys are generated at
// startup: artefacts record the exchanges they took part in, and no
// scenario depends on a key surviving a restart.
type counterparty struct {
	baseURL string
	host    string

	signingKey *ecdsa.PrivateKey
	signingJWK jose.JSONWebKey
	// encryptionKey is the Credential Request encryption key CW-072
	// advertises in credential_request_encryption.jwks.
	encryptionKey *ecdsa.PrivateKey
	encryptionJWK jose.JSONWebKey

	mu sync.Mutex
	// grants maps a pre-authorized code or an access token to the scenario
	// that issued it and when it stops being valid.
	grants map[string]grant
	// states maps an Authorization Request state to its scenario.
	states map[string]grant
}

type grant struct {
	scenario string
	expires  time.Time
}

const (
	preAuthorizedCodeLifetime = 15 * time.Minute
	accessTokenLifetime       = 5 * time.Minute
)

func newCounterparty(cfg config) (*counterparty, error) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	return &counterparty{
		baseURL:       cfg.baseURL,
		host:          hostOf(cfg.baseURL),
		signingKey:    signingKey,
		signingJWK:    jose.JSONWebKey{Key: &signingKey.PublicKey, KeyID: "request-signing", Algorithm: "ES256", Use: "sig"},
		encryptionKey: encryptionKey,
		encryptionJWK: jose.JSONWebKey{Key: &encryptionKey.PublicKey, KeyID: "credential-request-encryption", Algorithm: "ECDH-ES", Use: "enc"},
		grants:        make(map[string]grant),
		states:        make(map[string]grant),
	}, nil
}

// issue records a fresh single-use value for scenario.
func (c *counterparty) issue(scenario string, lifetime time.Duration) string {
	value := randomToken()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	pruneLocked(c.grants, now)
	c.grants[value] = grant{scenario: scenario, expires: now.Add(lifetime)}
	return value
}

// redeem consumes value if scenario issued it and it has not expired.
func (c *counterparty) redeem(scenario, value string) bool {
	return consume(&c.mu, c.grants, scenario, value)
}

// holds reports, without consuming it, whether value is a live grant of
// scenario.
func (c *counterparty) holds(scenario, value string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	pruneLocked(c.grants, now)
	held, ok := c.grants[value]
	return ok && held.scenario == scenario
}

func (c *counterparty) rememberState(scenario, state string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	pruneLocked(c.states, now)
	c.states[state] = grant{scenario: scenario, expires: now.Add(requestObjectLifetime)}
}

func (c *counterparty) consumeState(scenario, state string) bool {
	return consume(&c.mu, c.states, scenario, state)
}

func consume(mu *sync.Mutex, values map[string]grant, scenario, value string) bool {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	pruneLocked(values, now)
	held, ok := values[value]
	if !ok || held.scenario != scenario {
		return false
	}
	delete(values, value)
	return true
}

func pruneLocked(values map[string]grant, now time.Time) {
	for value, held := range values {
		if now.After(held.expires) {
			delete(values, value)
		}
	}
}
