package storage_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"siemlite/pkg/alerts"
	"siemlite/pkg/storage"
)

// TestEventNumberedEarlierButStoredLater: another process (a command) numbers
// a batch, then the server numbers and stores a later one and the alert engine
// checks it, and only then does the command's batch commit, with a number
// below the engine's checkpoint. Its event must still be evaluated, once.
func TestEventNumberedEarlierButStoredLater(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "siemlite.db")
	a, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	server := storage.NewRepository(a)
	now := time.Now().UnixMilli()
	rec := func(msg string) []storage.Record {
		return []storage.Record{{Timestamp: now, CategoryUID: 3, ClassUID: 3002, SeverityID: 3, Message: msg, RawData: msg}}
	}
	// Today's file exists before the command opens the files, so both know it.
	if err := server.InsertBatch(ctx, rec("warm up")); err != nil {
		t.Fatal(err)
	}
	b, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	command := storage.NewRepository(b)

	if _, err := server.SaveRule(ctx, storage.Rule{Name: "needle", Enabled: true, Severity: 3, Query: "needle",
		Threshold: 1, WindowMinutes: 5}, now); err != nil {
		t.Fatal(err)
	}
	eng := alerts.New(server, nil)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}

	numbered, release := make(chan struct{}), make(chan struct{})
	storage.SetAfterAllocate(b, func() {
		close(numbered)
		<-release
	})
	done := make(chan error, 1)
	go func() { done <- command.InsertBatch(ctx, rec("needle in the haystack")) }()
	<-numbered
	// The server stores a later-numbered batch and checks it while the
	// command's batch is still on its way.
	if err := server.InsertBatch(ctx, rec("hay")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	list, _, err := server.ListAlerts(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RuleName != "needle" || list[0].Count != 1 {
		t.Fatalf("alerts after the late commit = %+v, want one needle alert counting 1", list)
	}
	// Checked again, nothing is counted twice.
	if err := server.InsertBatch(ctx, rec("more hay")); err != nil {
		t.Fatal(err)
	}
	if res, err := eng.Check(ctx); err != nil || res.Opened+res.Updated != 0 {
		t.Fatalf("second check: %+v, %v", res, err)
	}
	if list, _, _ = server.ListAlerts(ctx, "", 10); len(list) != 1 || list[0].Count != 1 {
		t.Fatalf("alerts after checking again = %+v", list)
	}
}

// TestStaleReservationIsIgnored: a batch numbered by a process that died
// before storing it holds the engine back only until it is stale.
func TestStaleReservationIsIgnored(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "siemlite.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	now := time.Now().UnixMilli()
	r := []storage.Record{{Timestamp: now, CategoryUID: 3, ClassUID: 3002, SeverityID: 3, RawData: "x"}}
	if err := repo.InsertBatch(ctx, r); err != nil {
		t.Fatal(err)
	}
	// A reservation of seq 2 made now, as by a process still storing it.
	if _, err := db.Write.ExecContext(ctx, `UPDATE settings SET value = '2' WHERE key = 'event_seq'`); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetSetting(ctx, "event_seq_pending:2", strconv.FormatInt(now, 10)); err != nil {
		t.Fatal(err)
	}
	if err := repo.InsertBatch(ctx, r); err != nil { // seq 3
		t.Fatal(err)
	}
	if got, _ := repo.MaxEventSeq(ctx); got != 1 {
		t.Errorf("with seq 2 in flight: MaxEventSeq = %d, want 1", got)
	}
	// The same reservation, long ago: its process died.
	if err := repo.SetSetting(ctx, "event_seq_pending:2", strconv.FormatInt(now-time.Hour.Milliseconds(), 10)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.MaxEventSeq(ctx); got != 3 {
		t.Errorf("with a stale reservation: MaxEventSeq = %d, want 3", got)
	}
	if got, _ := repo.TopEventSeq(ctx); got != 3 {
		t.Errorf("TopEventSeq = %d, want 3", got)
	}
}
