package dpop

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ReplayKeyPrefix namespaces every DPoP jti reservation, mirroring the
// prefix convention used by clientAssertionReplayKeyPrefix in
// internal/protocols/oauth2/clientassertion_replay.go.
const ReplayKeyPrefix = "protocolsoup:dpop:jti:"

// ReplayStore enforces single-use of a DPoP proof's jti. Reserve is keyed by
// scope + jti rather than by a registered client: RFC 9449 binds a proof to
// a key (jkt), not to a client registration, and a resource server may see
// proofs from clients it has no registration for at all. Callers pass the
// proof's jkt as scope.
type ReplayStore interface {
	Reserve(ctx context.Context, scope, jti string, replayUntil, now time.Time) (bool, error)
	Close() error
}

// memoryReplayStore is the in-memory ReplayStore backing, used in
// development and tests. It performs lazy eviction of expired entries on
// each Reserve call, matching memoryClientAssertionReplayStore.
type memoryReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryReplayStore creates an in-memory DPoP jti replay store.
func NewMemoryReplayStore() ReplayStore {
	return &memoryReplayStore{entries: make(map[string]time.Time)}
}

func (s *memoryReplayStore) Reserve(
	_ context.Context,
	scope string,
	jti string,
	replayUntil time.Time,
	now time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, expiresAt := range s.entries {
		if !expiresAt.After(now) {
			delete(s.entries, key)
		}
	}
	key := replayKey(scope, jti)
	if _, exists := s.entries[key]; exists {
		return false, nil
	}
	if !replayUntil.After(now) {
		return false, nil
	}
	s.entries[key] = replayUntil
	return true, nil
}

func (s *memoryReplayStore) Close() error {
	return nil
}

// redisReplayStore is the production ReplayStore backing, using SetNX with a
// millisecond-rounded TTL so a store outage is distinguishable (by the
// caller wrapping Reserve's error in InfrastructureError) from a genuine
// replay, matching redisClientAssertionReplayStore.
type redisReplayStore struct {
	client *redis.Client
}

// NewRedisReplayStore connects to Redis for DPoP jti replay tracking.
// production enforces rediss:// (TLS) and certificate verification, mirroring
// newRedisClientAssertionReplayStore's production hardening.
func NewRedisReplayStore(ctx context.Context, rawURL string, production bool) (ReplayStore, error) {
	if rawURL == "" {
		return nil, errors.New("dpop: replay Redis URL is required")
	}
	if production && !IsSecureProductionRedisURL(rawURL) {
		return nil, errors.New("dpop: replay Redis URL must use rediss:// or a Fly private Upstash URL in production")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("dpop: parse replay Redis URL: %w", err)
	}
	if production && options.TLSConfig != nil {
		if options.TLSConfig.InsecureSkipVerify {
			return nil, errors.New("dpop: replay Redis URL must verify Redis certificates in production")
		}
		options.TLSConfig.MinVersion = tls.VersionTLS12
	}
	client := redis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("dpop: connect to replay Redis: %w", err)
	}
	return &redisReplayStore{client: client}, nil
}

// IsSecureProductionRedisURL accepts either end-to-end TLS or Fly's private
// Upstash endpoint. The latter is reachable only over Fly's encrypted 6PN
// network and intentionally uses redis:// rather than Redis-level TLS.
func IsSecureProductionRedisURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if strings.EqualFold(parsed.Scheme, "rediss") {
		return true
	}
	hostname := strings.ToLower(parsed.Hostname())
	password, hasPassword := parsed.User.Password()
	return strings.EqualFold(parsed.Scheme, "redis") &&
		strings.HasPrefix(hostname, "fly-") &&
		strings.HasSuffix(hostname, ".upstash.io") &&
		parsed.Port() == "6379" &&
		parsed.User.Username() != "" &&
		hasPassword &&
		password != ""
}

func (s *redisReplayStore) Reserve(
	ctx context.Context,
	scope string,
	jti string,
	replayUntil time.Time,
	now time.Time,
) (bool, error) {
	ttl := replayUntil.Sub(now)
	if ttl <= 0 {
		return false, nil
	}
	// Redis expiration has millisecond precision. Round upward so
	// sub-millisecond NumericDate precision never shortens the accepted
	// replay window.
	if remainder := ttl % time.Millisecond; remainder != 0 {
		ttl += time.Millisecond - remainder
	}
	reserved, err := s.client.SetNX(ctx, replayRedisKey(scope, jti), "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return reserved, nil
}

func (s *redisReplayStore) Close() error {
	return s.client.Close()
}

func replayKey(scope, jti string) string {
	return scope + "\x00" + jti
}

func replayRedisKey(scope, jti string) string {
	digest := sha256.Sum256([]byte(replayKey(scope, jti)))
	return ReplayKeyPrefix + hex.EncodeToString(digest[:])
}

// InfrastructureError distinguishes a replay-store outage from a genuine
// replay finding, matching clientAssertionInfrastructureError. Callers wrap
// a Reserve error in this type so the HTTP layer can fail closed with
// server_error / 500 instead of the misleading "already used" verdict.
type InfrastructureError struct {
	Err error
}

// NewInfrastructureError wraps a replay-store error for a failed-closed
// response.
func NewInfrastructureError(err error) *InfrastructureError {
	return &InfrastructureError{Err: err}
}

func (e *InfrastructureError) Error() string {
	return "dpop replay store unavailable: " + e.Err.Error()
}

func (e *InfrastructureError) Unwrap() error {
	return e.Err
}
