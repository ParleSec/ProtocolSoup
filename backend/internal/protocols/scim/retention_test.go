package scim

import (
	"context"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

func TestPurgeExpiredDeletesOldRecordsAndKeepsRecent(t *testing.T) {
	storage, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	defer storage.Close()
	ctx := context.Background()

	oldUser := NewUser()
	oldUser.UserName = "old@example.com"
	createdOld, err := storage.CreateUser(ctx, oldUser)
	if err != nil {
		t.Fatalf("create old user: %v", err)
	}
	recentUser := NewUser()
	recentUser.UserName = "recent@example.com"
	createdRecent, err := storage.CreateUser(ctx, recentUser)
	if err != nil {
		t.Fatalf("create recent user: %v", err)
	}

	oldTime := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if _, err := storage.db.ExecContext(ctx, `UPDATE scim_users SET updated_at = ? WHERE id = ?`, oldTime, createdOld.ID); err != nil {
		t.Fatalf("age old user: %v", err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	users, groups, err := storage.PurgeExpired(ctx, cutoff)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if users != 1 || groups != 0 {
		t.Fatalf("purged users=%d groups=%d, want 1 and 0", users, groups)
	}
	if _, err := storage.GetUser(ctx, createdOld.ID); err != ErrNotFound {
		t.Fatalf("old user error = %v, want ErrNotFound", err)
	}
	if _, err := storage.GetUser(ctx, createdRecent.ID); err != nil {
		t.Fatalf("recent user should remain: %v", err)
	}
}

func TestPurgeExpiredCascadesGroupMembership(t *testing.T) {
	storage, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	defer storage.Close()
	ctx := context.Background()

	user := NewUser()
	user.UserName = "member@example.com"
	createdUser, err := storage.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	group := NewGroup()
	group.DisplayName = "Aged Group"
	group.Members = []MemberRef{{Value: createdUser.ID, Type: "User"}}
	createdGroup, err := storage.CreateGroup(ctx, group)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	oldTime := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if _, err := storage.db.ExecContext(ctx, `UPDATE scim_groups SET updated_at = ? WHERE id = ?`, oldTime, createdGroup.ID); err != nil {
		t.Fatalf("age group: %v", err)
	}

	if _, _, err := storage.PurgeExpired(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := storage.GetGroup(ctx, createdGroup.ID); err != ErrNotFound {
		t.Fatalf("aged group error = %v, want ErrNotFound", err)
	}
	var memberCount int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scim_group_members WHERE group_id = ?`, createdGroup.ID).Scan(&memberCount); err != nil {
		t.Fatalf("count members: %v", err)
	}
	if memberCount != 0 {
		t.Fatalf("membership rows = %d, want 0 after cascade", memberCount)
	}
	if _, err := storage.GetUser(ctx, createdUser.ID); err != nil {
		t.Fatalf("user should remain after group purge: %v", err)
	}
}

func TestPurgeExpiredThenSeedDemoDataRestoresDemoSet(t *testing.T) {
	storage, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	defer storage.Close()
	ctx := context.Background()

	if err := storage.SeedDemoData(ctx, "http://localhost:8080"); err != nil {
		t.Fatalf("initial seed: %v", err)
	}
	cutoff := time.Now().UTC().Add(time.Hour)
	if _, _, err := storage.PurgeExpired(ctx, cutoff); err != nil {
		t.Fatalf("purge everything: %v", err)
	}
	if err := storage.SeedDemoData(ctx, "http://localhost:8080"); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if _, err := storage.GetUserByUserName(ctx, "alice@example.com"); err != nil {
		t.Fatalf("demo user missing after re-seed: %v", err)
	}
}

func TestSCIMRetentionZeroLeavesReaperStopped(t *testing.T) {
	t.Setenv("SCIM_RETENTION", "0")
	t.Setenv("SCIM_DATA_DIR", t.TempDir())
	p := NewPlugin()
	if err := p.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:     "http://localhost:8080",
		Environment: "test",
	}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	if p.retentionStop != nil {
		t.Fatal("retention reaper started despite SCIM_RETENTION=0")
	}
}
