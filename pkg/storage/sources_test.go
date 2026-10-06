package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newSourceRepo(t *testing.T) *Repository {
	t.Helper()
	db, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRepository(db)
}

func TestSourceEnableDisable(t *testing.T) {
	ctx := context.Background()
	repo := newSourceRepo(t)
	now := time.Now().UnixMilli()
	id, err := repo.CreateTokenSource(ctx, "app", "hash-app", nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSource(ctx, id); !s.Enabled || s.RevokedAt != nil {
		t.Fatalf("new source = %+v", s)
	}

	if err := repo.SetSourceEnabled(ctx, id, false, now); err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSource(ctx, id); s.Enabled || s.RevokedAt == nil {
		t.Errorf("disabled source = %+v", s)
	}
	if _, err := repo.FindActiveToken(ctx, "hash-app"); !errors.Is(err, ErrSourceNotFound) {
		t.Errorf("disabled token found: %v", err)
	}
	// Disabling again keeps the first time.
	if err := repo.SetSourceEnabled(ctx, id, false, now+5000); err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSource(ctx, id); *s.RevokedAt != now {
		t.Errorf("disabled time changed to %d", *s.RevokedAt)
	}

	if err := repo.SetSourceEnabled(ctx, id, true, now); err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSource(ctx, id); !s.Enabled || s.RevokedAt != nil {
		t.Errorf("enabled source = %+v", s)
	}
	if _, err := repo.FindActiveToken(ctx, "hash-app"); err != nil {
		t.Errorf("enabled token not found: %v", err)
	}

	// Only access tokens can be switched; built-ins and missing ids are refused.
	syslog, _ := repo.BuiltinSource(ctx, SourceSyslog)
	if err := repo.SetSourceEnabled(ctx, syslog.ID, false, now); !errors.Is(err, ErrBuiltinSource) {
		t.Errorf("disable built-in = %v", err)
	}
	if err := repo.SetSourceEnabled(ctx, 9999, false, now); !errors.Is(err, ErrSourceNotFound) {
		t.Errorf("disable missing = %v", err)
	}
}

func TestDeleteSource(t *testing.T) {
	ctx := context.Background()
	repo := newSourceRepo(t)
	now := time.Now().UnixMilli()
	id, _ := repo.CreateTokenSource(ctx, "app", "hash-app", nil, false, now)
	keep, _ := repo.CreateTokenSource(ctx, "keep", "hash-keep", nil, false, now)

	// A limited user can see the source; deleting it removes that row too.
	uid, err := repo.CreateUser(ctx, "sam", "x", "standard", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB().Write.Exec(`INSERT INTO user_sources (user_id, source_id) VALUES (?, ?), (?, ?)`, uid, id, uid, keep); err != nil {
		t.Fatal(err)
	}
	if err := repo.InsertBatch(ctx, []Record{
		{Timestamp: now, Message: "from app", RawData: "from app", SourceID: id},
		{Timestamp: now, Message: "from keep", RawData: "from keep", SourceID: keep},
		{Timestamp: now, Message: "no source", RawData: "no source"},
	}); err != nil {
		t.Fatal(err)
	}

	// An alert rule scoped to the source blocks the delete.
	ruleID, err := repo.SaveRule(ctx, Rule{Name: "App failures", Enabled: true, Severity: 3, SourceID: &id, Threshold: 1, WindowMinutes: 5}, now)
	if err != nil {
		t.Fatal(err)
	}
	err = repo.DeleteSource(ctx, id)
	var inUse *SourceInUseError
	if !errors.As(err, &inUse) || len(inUse.Rules) != 1 || inUse.Rules[0] != "App failures" {
		t.Fatalf("delete with a rule = %v", err)
	}
	if _, err := repo.GetSource(ctx, id); err != nil {
		t.Errorf("source gone after a refused delete: %v", err)
	}
	if ru, _ := repo.GetRule(ctx, ruleID); ru.SourceID == nil || *ru.SourceID != id {
		t.Errorf("rule lost its source: %+v", ru)
	}

	if err := repo.DeleteRule(ctx, ruleID); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteSource(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSource(ctx, id); !errors.Is(err, ErrSourceNotFound) {
		t.Errorf("deleted source still there: %v", err)
	}
	if _, err := repo.FindActiveToken(ctx, "hash-app"); !errors.Is(err, ErrSourceNotFound) {
		t.Errorf("deleted token still works: %v", err)
	}
	var n int
	repo.DB().Write.QueryRow(`SELECT COUNT(*) FROM user_sources WHERE source_id = ?`, id).Scan(&n)
	if n != 0 {
		t.Errorf("user_sources rows left: %d", n)
	}
	repo.DB().Write.QueryRow(`SELECT COUNT(*) FROM user_sources WHERE source_id = ?`, keep).Scan(&n)
	if n != 1 {
		t.Errorf("other source's user_sources rows = %d, want 1", n)
	}

	// The events stay; the deleted source's show its place by a plain name.
	recs, err := repo.Search(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range recs {
		got[r.Message] = r.SourceName
	}
	if got["from app"] != "Deleted source" || got["from keep"] != "keep" || got["no source"] != "" || len(got) != 3 {
		t.Errorf("source names = %v", got)
	}
	ov, err := repo.Overview(ctx, now-60000, now+60000, 60000, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	top := map[string]int64{}
	for _, s := range ov.TopSources {
		top[s.Name] = s.Count
	}
	if top["Deleted source"] != 1 || top["keep"] != 1 || top["Unknown"] != 1 {
		t.Errorf("top sources = %v", top)
	}

	// Built-in and missing sources are refused.
	syslog, _ := repo.BuiltinSource(ctx, SourceSyslog)
	if err := repo.DeleteSource(ctx, syslog.ID); !errors.Is(err, ErrBuiltinSource) {
		t.Errorf("delete built-in = %v", err)
	}
	if err := repo.DeleteSource(ctx, id); !errors.Is(err, ErrSourceNotFound) {
		t.Errorf("delete twice = %v", err)
	}
}
