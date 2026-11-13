package ingest

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// Events far from now are refused, so senders can't make a file for every
// day there is; ones within the window are stored.
func TestTimeWindow(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w := New(storage.NewRepository(db), Config{FlushInterval: 10 * time.Millisecond, MaxAge: 30 * 24 * time.Hour})
	defer w.Close()
	now := time.Now()
	for _, tc := range []struct {
		at time.Time
		ok bool
	}{
		{now, true},
		{now.Add(-29 * 24 * time.Hour), true},
		{now.Add(20 * time.Hour), true}, // a clock running ahead
		{now.Add(-31 * 24 * time.Hour), false},
		{now.Add(25 * time.Hour), false},
		{time.Date(2150, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{time.Date(1971, 1, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		err := w.Submit(ctx, &ocsf.Event{Time: tc.at.UnixMilli(), CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "x"})
		var verr *ocsf.ValidationError
		if tc.ok != (err == nil) || (!tc.ok && !errors.As(err, &verr)) {
			t.Errorf("event at %s: %v", tc.at.Format(time.RFC3339), err)
		}
	}
	w.Drain(ctx)
	if days := db.Days(); len(days) > 3 {
		t.Errorf("day files = %v", days)
	}
}

// Values an event's parser left unmapped are stored as its fields; a field the
// parser named explicitly wins over one with the same name.
func TestUnmappedValuesAreStoredAsFields(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	w := New(repo, Config{FlushInterval: 10 * time.Millisecond})
	defer w.Close()
	ev := &ocsf.Event{Time: time.Now().UnixMilli(), CategoryUID: 6, ClassUID: 6003, SeverityID: 1, Message: "m", RawData: "raw",
		Unmapped: map[string]any{"reason": "from the line", "entity": "deal"}}
	if err := w.SubmitWith(ctx, ev, SubmitOptions{Fields: map[string]string{"reason": "from the parser"}}); err != nil {
		t.Fatal(err)
	}
	w.Drain(ctx)
	recs, err := repo.Search(ctx, storage.Filter{Limit: 10})
	if err != nil || len(recs) != 1 {
		t.Fatalf("search = %v, %v", recs, err)
	}
	if got := string(recs[0].Fields); got != `{"entity":"deal","reason":"from the parser"}` {
		t.Errorf("fields = %s", got)
	}
}

// partialSink stores what it is given, but fails the first batch after taking
// its first record, as a write that succeeded for one day and failed for the next.
type partialSink struct {
	stored []storage.Record
	failed bool
}

func (s *partialSink) InsertBatch(ctx context.Context, recs []storage.Record) error {
	if !s.failed && len(recs) > 1 {
		s.failed = true
		s.stored = append(s.stored, recs[0])
		return &storage.PartialBatchError{Remaining: recs[1:], Err: errors.New("database is locked")}
	}
	s.stored = append(s.stored, recs...)
	return nil
}

// A batch stored for some days and failed for the rest is tried again with the
// rest only, so no event is stored twice.
func TestPartialBatchRetriesOnlyTheRest(t *testing.T) {
	sink := &partialSink{}
	w := New(sink, Config{})
	batch := []storage.Record{{Timestamp: 1}, {Timestamp: 2}, {Timestamp: 3}}
	w.flush(batch)
	if len(sink.stored) != 3 {
		t.Fatalf("stored %d records, want 3 (each once): %+v", len(sink.stored), sink.stored)
	}
	for i, r := range sink.stored {
		if r.Timestamp != int64(i+1) {
			t.Errorf("record %d has timestamp %d", i, r.Timestamp)
		}
	}
}
