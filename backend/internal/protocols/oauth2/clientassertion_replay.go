package oauth2

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/redis/go-redis/v9"
)

const clientAssertionReplayKeyPrefix = "protocolsoup:oauth2:private_key_jwt:jti:"

type clientAssertionReplayStore interface {
	Reserve(ctx context.Context, clientID, jti string, replayUntil, now time.Time) (bool, error)
	Close() error
}

type memoryClientAssertionReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemoryClientAssertionReplayStore() *memoryClientAssertionReplayStore {
	return &memoryClientAssertionReplayStore{entries: make(map[string]time.Time)}
}

func (s *memoryClientAssertionReplayStore) Reserve(
	_ context.Context,
	clientID string,
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
	key := clientAssertionReplayKey(clientID, jti)
	if _, exists := s.entries[key]; exists {
		return false, nil
	}
	if !replayUntil.After(now) {
		return false, nil
	}
	s.entries[key] = replayUntil
	return true, nil
}

func (s *memoryClientAssertionReplayStore) Close() error {
	return nil
}

type redisClientAssertionReplayStore struct {
	client *redis.Client
}

func newRedisClientAssertionReplayStore(
	ctx context.Context,
	rawURL string,
	production bool,
) (*redisClientAssertionReplayStore, error) {
	if rawURL == "" {
		return nil, errors.New("OAUTH2_REPLAY_REDIS_URL is required")
	}
	if production && !dpop.IsSecureProductionRedisURL(rawURL) {
		return nil, errors.New("OAUTH2_REPLAY_REDIS_URL must use rediss:// or a Fly private Upstash URL in production")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse OAUTH2_REPLAY_REDIS_URL: %w", err)
	}
	if production && options.TLSConfig != nil {
		if options.TLSConfig.InsecureSkipVerify {
			return nil, errors.New("OAUTH2_REPLAY_REDIS_URL must verify Redis certificates in production")
		}
		options.TLSConfig.MinVersion = tls.VersionTLS12
	}
	client := redis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to OAuth2 replay Redis: %w", err)
	}
	return &redisClientAssertionReplayStore{client: client}, nil
}

func (s *redisClientAssertionReplayStore) Reserve(
	ctx context.Context,
	clientID string,
	jti string,
	replayUntil time.Time,
	now time.Time,
) (bool, error) {
	ttl := replayUntil.Sub(now)
	if ttl <= 0 {
		return false, nil
	}
	// Redis expiration has millisecond precision. Round upward so sub-millisecond
	// NumericDate precision never shortens the accepted replay window.
	if remainder := ttl % time.Millisecond; remainder != 0 {
		ttl += time.Millisecond - remainder
	}
	reserved, err := s.client.SetNX(
		ctx,
		clientAssertionReplayRedisKey(clientID, jti),
		"1",
		ttl,
	).Result()
	if err != nil {
		return false, err
	}
	return reserved, nil
}

func (s *redisClientAssertionReplayStore) Close() error {
	return s.client.Close()
}

func clientAssertionReplayRedisKey(clientID, jti string) string {
	digest := sha256.Sum256([]byte(clientAssertionReplayKey(clientID, jti)))
	return clientAssertionReplayKeyPrefix + hex.EncodeToString(digest[:])
}

type clientAssertionInfrastructureError struct {
	err error
}

func (e *clientAssertionInfrastructureError) Error() string {
	return "client assertion infrastructure unavailable: " + e.err.Error()
}

func (e *clientAssertionInfrastructureError) Unwrap() error {
	return e.err
}
