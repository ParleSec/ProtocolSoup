package dpop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisReplayStoreRejectsDuplicateJTI(t *testing.T) {
	server := miniredis.RunT(t)
	rawURL := "redis://" + server.Addr() + "/0"
	store, err := NewRedisReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	until := now.Add(IatFreshnessWindow)
	first, err := store.Reserve(context.Background(), "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first reservation should succeed")
	}
	second, err := store.Reserve(context.Background(), "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate jti should be rejected")
	}
}

func TestRedisReplayReservationIsSharedAndAtomicAcrossInstances(t *testing.T) {
	server := miniredis.RunT(t)
	rawURL := "redis://" + server.Addr() + "/0"
	first, err := NewRedisReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewRedisReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	now := time.Now().UTC()
	until := now.Add(IatFreshnessWindow)
	stores := []ReplayStore{first, second}
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func(store ReplayStore) {
			defer wait.Done()
			reserved, reserveErr := store.Reserve(context.Background(), "shared-jkt", "single-use-jti", until, now)
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
}

func TestRedisReplayStoreRequiresTLSInProduction(t *testing.T) {
	if _, err := NewRedisReplayStore(
		context.Background(),
		"redis://127.0.0.1:6379/0",
		true,
	); err == nil || !strings.Contains(err.Error(), "rediss://") {
		t.Fatalf("production plaintext Redis error = %v", err)
	}
}

func TestRedisReplayKeysDoNotExposeScopeOrJTI(t *testing.T) {
	key := replayRedisKey("sensitive-jkt", "sensitive-jti")
	if strings.Contains(key, "sensitive-jkt") || strings.Contains(key, "sensitive-jti") {
		t.Fatalf("Redis key exposes DPoP identifiers: %s", key)
	}
	if !strings.HasPrefix(key, ReplayKeyPrefix) {
		t.Fatalf("Redis key prefix = %q", key)
	}
}

func TestMemoryReplayStoreRejectsDuplicateJTI(t *testing.T) {
	store := NewMemoryReplayStore()
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	until := now.Add(IatFreshnessWindow)

	first, err := store.Reserve(context.Background(), "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first reservation should succeed")
	}
	second, err := store.Reserve(context.Background(), "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate jti should be rejected")
	}
}

func TestMemoryReplayStoreEvictsExpiredEntries(t *testing.T) {
	store := NewMemoryReplayStore()
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	shortLived := now.Add(time.Millisecond)

	reserved, err := store.Reserve(context.Background(), "jkt-1", "short-lived-jti", shortLived, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reserved {
		t.Fatal("first reservation should succeed")
	}

	// After the entry's own expiry, the same jti must be reservable again --
	// eviction happened, it was not simply left dangling forever.
	later := now.Add(time.Hour)
	reReserved, err := store.Reserve(context.Background(), "jkt-1", "short-lived-jti", later.Add(time.Minute), later)
	if err != nil {
		t.Fatal(err)
	}
	if !reReserved {
		t.Fatal("expired entry should be evicted and become reservable again")
	}
}

func TestNewRedisReplayStoreRejectsEmptyURL(t *testing.T) {
	if _, err := NewRedisReplayStore(context.Background(), "", false); err == nil {
		t.Fatal("expected empty Redis URL rejection")
	}
}

func TestNewRedisReplayStoreRejectsMalformedURL(t *testing.T) {
	if _, err := NewRedisReplayStore(context.Background(), "not-a-valid-redis-url", false); err == nil {
		t.Fatal("expected malformed Redis URL rejection")
	}
}

func TestRedisReplayStoreReserveWithNonPositiveTTLReturnsFalse(t *testing.T) {
	server := miniredis.RunT(t)
	rawURL := "redis://" + server.Addr() + "/0"
	store, err := NewRedisReplayStore(context.Background(), rawURL, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	// replayUntil at or before now means the proof is already outside its
	// own freshness window -- Reserve must decline without erroring or
	// writing a zero/negative TTL key to Redis.
	reserved, err := store.Reserve(context.Background(), "jkt-1", "already-stale-jti", now, now)
	if err != nil {
		t.Fatal(err)
	}
	if reserved {
		t.Fatal("a non-positive TTL reservation must not be accepted")
	}
}

func TestInfrastructureErrorWrapsUnderlyingReplayStoreFailure(t *testing.T) {
	underlying := errors.New("connection refused")
	wrapped := NewInfrastructureError(underlying)
	if !errors.Is(wrapped, underlying) {
		t.Fatal("InfrastructureError must unwrap to the underlying store error")
	}
	if !strings.Contains(wrapped.Error(), "connection refused") {
		t.Fatalf("error message = %q", wrapped.Error())
	}
}
