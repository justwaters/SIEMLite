package retention_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/retention"
	"siemlite/pkg/storage"
)

func TestCleanerDeletesExpiredAndKeepsFTSInSync(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)

	now := time.Now()
	var recs []storage.Record
	for i := range 25 {
		age := 60 * 24 * time.Hour // expired
		if i%5 == 0 {
			age = time.Hour // fresh
		}
		recs = append(recs, storage.Record{
			Timestamp: now.Add(-age).UnixMilli(), CategoryUID: 3, ClassUID: 3002,
			SeverityID: 1, RawData: "login attempt for tester",
		})
	}
	if err := repo.InsertBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}

	// BatchSize 7 forces several delete/vacuum rounds.
	n, err := retention.New(repo, retention.Config{RetentionDays: 30, BatchSize: 7}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 {
		t.Fatalf("deleted %d, want 20", n)
	}

	got, err := repo.Search(ctx, storage.Filter{Match: "tester", Limit: 100})
	if err != nil {
		t.Fatalf("fts search after delete: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("fts returned %d rows, want 5", len(got))
	}
}
