package oauth2

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/alicebob/miniredis/v2"
)

func TestRedisClientAssertionReplayStoreIsSharedAndAtomic(t *testing.T) {
	server := miniredis.RunT(t)
	rawURL := "redis://" + server.Addr() + "/0"
	first, err := newRedisClientAssertionReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := newRedisClientAssertionReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	now := time.Now().UTC()
	until := now.Add(5 * time.Minute)
	stores := []clientAssertionReplayStore{first, second}
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func(store clientAssertionReplayStore) {
			defer wait.Done()
			reserved, reserveErr := store.Reserve(
				context.Background(),
				"shared-client",
				"single-use-jti",
				until,
				now,
			)
			if reserveErr != nil {
				t.Errorf("reserve: %v", reserveErr)
				return
			}
			if reserved {
				accepted.Add(1)
			}
		}(stores[index%len(stores)])
	}
	wait.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted reservations = %d, want 1", accepted.Load())
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := newRedisClientAssertionReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	reserved, err := restarted.Reserve(
		context.Background(),
		"shared-client",
		"single-use-jti",
		until,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reserved {
		t.Fatal("restarted process accepted an already reserved assertion")
	}
}

func TestRedisReplayReservationIsSharedAcrossPluginInstances(t *testing.T) {
	server := miniredis.RunT(t)
	rawURL := "redis://" + server.Addr() + "/0"
	keySet, err := internalcrypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	signer := newAssertionSigner(t, "RS256", "cross-instance")
	idp.RegisterClient(&models.Client{
		ID:                      "cross-instance-client",
		Name:                    "Cross-instance replay client",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKS:                    &internalcrypto.JWKS{Keys: []internalcrypto.JWK{signer.jwk}},
	})
	fixedNow := time.Now().UTC().Truncate(time.Second)
	plugins := []*Plugin{NewPlugin(), NewPlugin()}
	for _, plugin := range plugins {
		store, storeErr := newRedisClientAssertionReplayStore(context.Background(), rawURL, false)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		t.Cleanup(func() { _ = store.Close() })
		plugin.mockIdP = idp
		plugin.baseURL = "https://as.example"
		plugin.now = func() time.Time { return fixedNow }
		plugin.clientAssertionReplay = store
	}
	assertion := signer.sign(t, validAssertionClaims(
		fixedNow,
		"cross-instance-client",
		"https://as.example/oauth2/token",
		"cross-instance-jti",
	), "")

	var accepted atomic.Int32
	var rejected atomic.Int32
	var wait sync.WaitGroup
	for _, plugin := range plugins {
		wait.Add(1)
		go func(plugin *Plugin) {
			defer wait.Done()
			_, _, authenticationErr := plugin.authenticatePrivateKeyJWT(
				"cross-instance-client",
				assertion,
			)
			if authenticationErr == nil {
				accepted.Add(1)
			} else if clientAssertionFailureReason(authenticationErr) == "replayed_jti" {
				rejected.Add(1)
			} else {
				t.Errorf("authentication error = %v", authenticationErr)
			}
		}(plugin)
	}
	wait.Wait()
	if accepted.Load() != 1 || rejected.Load() != 1 {
		t.Fatalf("accepted = %d, rejected = %d", accepted.Load(), rejected.Load())
	}
}

func TestRedisClientAssertionReplayKeysDoNotExposeClaims(t *testing.T) {
	key := clientAssertionReplayRedisKey("sensitive-client", "sensitive-jti")
	if strings.Contains(key, "sensitive-client") || strings.Contains(key, "sensitive-jti") {
		t.Fatalf("Redis key exposes client assertion identifiers: %s", key)
	}
	if !strings.HasPrefix(key, clientAssertionReplayKeyPrefix) {
		t.Fatalf("Redis key prefix = %q", key)
	}
}

func TestRedisClientAssertionReplayStoreRequiresTLSInProduction(t *testing.T) {
	if _, err := newRedisClientAssertionReplayStore(
		context.Background(),
		"redis://127.0.0.1:6379/0",
		true,
	); err == nil || !strings.Contains(err.Error(), "rediss://") {
		t.Fatalf("production plaintext Redis error = %v", err)
	}
}

func TestOAuthPluginRequiresReplayRedisOutsideDevelopmentAndTests(t *testing.T) {
	for _, environment := range []string{"demo", "production"} {
		t.Run(environment, func(t *testing.T) {
			oauthPlugin := NewPlugin()
			err := oauthPlugin.Initialize(context.Background(), plugin.PluginConfig{
				Environment: environment,
				BaseURL:     "https://as.example",
			})
			if err == nil || !strings.Contains(err.Error(), "OAUTH2_REPLAY_REDIS_URL") {
				t.Fatalf("%s initialization error = %v", environment, err)
			}
		})
	}
}
