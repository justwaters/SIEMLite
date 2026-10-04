package storage

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// TestRawLinesGoADayAfterArrival: an original line is removed 24 hours after
// the event arrived, whatever time the event itself carries; the parsed event
// and its search stay.
func TestRawLinesGoADayAfterArrival(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	ev := func(ts time.Time, word string) Record {
		return Record{Timestamp: ts.UnixMilli(), CategoryUID: 1, ClassUID: 1001, SeverityID: 1,
			Message: "parsed " + word, RawData: "raw line " + word, Host: "web-1", UserName: "alice",
			SrcIP: "10.1.2.3", DstIP: "10.9.9.9", Fields: []byte(`{"action":"auth.fail"}`)}
	}
	// Arriving at t0: a current event, a late one with an old time, and one dated in the future.
	if err := repo.InsertBatch(ctx, []Record{ev(t0, "current"), ev(t0.Add(-5*24*time.Hour), "late"), ev(t0.Add(3*time.Hour), "ahead")}); err != nil {
		t.Fatal(err)
	}
	raw := func() map[string]string {
		t.Helper()
		recs, err := repo.Search(ctx, Filter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range recs {
			out[r.Message] = r.RawData
		}
		return out
	}
	purge := func(at time.Time) int64 {
		t.Helper()
		n, err := repo.PurgeRawLines(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	purge(t0) // records where arrival numbers stood at t0
	// An hour later more arrive; nothing is old enough yet.
	t1 := t0.Add(time.Hour)
	if err := repo.InsertBatch(ctx, []Record{ev(t1, "next")}); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{t1, t0.Add(23 * time.Hour)} {
		if n := purge(at); n != 0 {
			t.Fatalf("at %v removed %d lines, want 0", at, n)
		}
	}
	if got := raw(); len(got) != 4 || got["parsed late"] != "raw line late" || got["parsed next"] != "raw line next" {
		t.Fatalf("lines before 24 hours = %v", got)
	}
	// Just over a day after t0: the first three go, the one that arrived at t1 stays.
	if n := purge(t0.Add(24*time.Hour + time.Minute)); n != 3 {
		t.Fatalf("removed %d lines at 24h, want 3", n)
	}
	got := raw()
	for _, w := range []string{"current", "late", "ahead"} {
		if r, ok := got["parsed "+w]; !ok || r != "" {
			t.Errorf("%s: raw line %q (found %v), want removed", w, r, ok)
		}
	}
	if got["parsed next"] != "raw line next" {
		t.Errorf("next lost its line early: %q", got["parsed next"])
	}
	// Twice is a no-op, and the second wave goes when it is due.
	if n := purge(t0.Add(24*time.Hour + 2*time.Minute)); n != 0 {
		t.Errorf("a second run removed %d lines", n)
	}
	if n := purge(t1.Add(24*time.Hour + time.Minute)); n != 1 {
		t.Errorf("removed %d lines for the second batch, want 1", n)
	}
	// What the parser made stays searchable and readable.
	for _, match := range []string{"parsed", "web", "alice", `"10.1.2.3"`, `"10.9.9.9"`, `"auth.fail"`} {
		recs, err := repo.Search(ctx, Filter{Match: match, Limit: 100})
		if err != nil || len(recs) != 4 {
			t.Errorf("search %q after removal found %d, %v; want 4", match, len(recs), err)
		}
	}
	recs, _ := repo.Search(ctx, Filter{Match: "late", Limit: 10})
	if len(recs) != 1 || recs[0].Message != "parsed late" || recs[0].RawData != "" || string(recs[0].Fields) != `{"action":"auth.fail"}` || recs[0].UserName != "alice" {
		t.Errorf("event after removal = %+v", recs)
	}
	checkIndex(t, db)
}

// TestSearchFindsParsedColumnsWithoutRawLine: host, user, address and a parsed
// field are searchable when the original line is gone (or never existed).
func TestSearchFindsParsedColumnsWithoutRawLine(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	now := time.Now().UnixMilli()
	var recs []Record
	for i := range 30 {
		recs = append(recs, Record{Timestamp: now - int64(i)*1000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1,
			Message: fmt.Sprintf("session %d opened", i), Source: "sshd", Host: fmt.Sprintf("bastion-%d", i%3),
			UserName: fmt.Sprintf("user%d", i%5), SrcIP: fmt.Sprintf("192.0.2.%d", i), DstIP: "198.51.100.7",
			Fields: []byte(fmt.Sprintf(`{"action":"auth.success%d"}`, i%2))})
	}
	if err := repo.InsertBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if _, err := db.days.shard(dayOf(now), false).writerOrDie(t).Exec(`UPDATE events SET raw_data = ''`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		match string
		want  int
	}{
		{"bastion", 30}, {`"bastion-1"`, 10}, {"user3", 6}, {`"192.0.2.17"`, 1}, {`"198.51.100.7"`, 30},
		{"success1", 15}, {"sshd", 30}, {`"session 4 opened"`, 1}, {"zeta", 0},
	} {
		got, err := repo.Search(ctx, Filter{Match: c.match, Limit: 100})
		if err != nil || len(got) != c.want {
			t.Errorf("search %q found %d, %v; want %d", c.match, len(got), err, c.want)
		}
	}
	checkIndex(t, db)
}

func (s *shard) writerOrDie(t *testing.T) *sql.DB {
	t.Helper()
	w, err := s.writer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return w
}
