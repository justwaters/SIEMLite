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
