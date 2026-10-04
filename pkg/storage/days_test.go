package storage

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// oracle is every event in one in-memory table, searched the way a single
// database file was before day files.
type oracle struct{ db *sql.DB }

func newOracle(t *testing.T) *oracle {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp INTEGER, severity_id INTEGER, message TEXT, source TEXT, host TEXT,
			user_name TEXT, src_ip TEXT, dst_ip TEXT, fields TEXT, raw_data TEXT, source_id INTEGER)`,
		`CREATE VIRTUAL TABLE events_fts USING fts5(` + ftsCols + `, content='events', content_rowid='id')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return &oracle{db}
}

func (o *oracle) add(t *testing.T, recs []Record) {
	t.Helper()
	for _, r := range recs {
		res, err := o.db.Exec(`INSERT INTO events (timestamp, severity_id, message, source, host, user_name, src_ip, dst_ip, fields, raw_data, source_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Timestamp, r.SeverityID, cmp.Or(r.Message, r.RawData), nullable(r.Source), nullable(r.Host), nullable(r.UserName),
			nullable(r.SrcIP), nullable(r.DstIP), nullable(string(r.Fields)), r.RawData, r.SourceID)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		if _, err := o.db.Exec(`INSERT INTO events_fts (rowid, `+ftsCols+`) SELECT id, `+ftsCols+` FROM events WHERE id = ?`, id); err != nil {
			t.Fatal(err)
		}
	}
}

// page returns "time raw host" for a page of a filter, newest first.
func (o *oracle) page(t *testing.T, f Filter) []string {
	t.Helper()
	where, args := filterWhere(f)
	from := "events e"
	if f.Match != "" {
		from = "events_fts JOIN events e ON e.id = events_fts.rowid"
		where = append([]string{"events_fts MATCH ?"}, where...)
		args = append([]any{f.Match}, args...)
	}
	rows, err := o.db.Query(`SELECT e.timestamp, e.raw_data, e.host FROM `+from+whereSQL(where)+
		` ORDER BY e.timestamp DESC, e.id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ts int64
		var raw, host string
		rows.Scan(&ts, &raw, &host)
		out = append(out, fmt.Sprintf("%d %s %s", ts, raw, host))
	}
	return out
}

func keys(recs []Record) []string {
	out := []string{}
	for _, r := range recs {
		out = append(out, fmt.Sprintf("%d %s %s", r.Timestamp, r.RawData, r.Host))
	}
	return out
}

func openTemp(t *testing.T) (*DB, *Repository) {
	t.Helper()
	db, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "siemlite.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, NewRepository(db)
}

// randomEvents makes events over several days, arriving out of order (late
// arrivals, clocks ahead, backfills) in several batches.
func randomEvents(rng *rand.Rand, n int, base int64) []Record {
	words := []string{"alpha", "beta", "gamma", "delta"}
	var recs []Record
	for i := 0; i < n; i++ {
		ts := base + int64(rng.IntN(6))*dayMs + int64(rng.IntN(int(dayMs)))
		if rng.IntN(10) == 0 {
			ts = base + int64(i%7)*dayMs - 1 // the last moment of a day: ties across midnight
		}
		recs = append(recs, Record{Timestamp: ts, CategoryUID: 1, ClassUID: 1001, SeverityID: rng.IntN(7),
			RawData: words[rng.IntN(4)] + " " + words[rng.IntN(4)] + fmt.Sprintf(" n%d", i%50),
			Host:    fmt.Sprintf("h%d", rng.IntN(3)), SourceID: int64(1 + rng.IntN(3))})
	}
	return recs
}

// TestSearchAcrossDaysMatchesOneFile checks every search, filter and page
// across day files against the same events in one table.
func TestSearchAcrossDaysMatchesOneFile(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	o := newOracle(t)
	rng := rand.New(rand.NewPCG(5, 5))
	base := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC).UnixMilli()
	n := 4000
	if raceEnabled {
		n = 1200
	}
	all := randomEvents(rng, n, base)
	for i := 0; i < len(all); i += 300 {
		batch := all[i:min(i+300, len(all))]
		if err := repo.InsertBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
		o.add(t, batch)
	}
	if got := len(db.Days()); got < 6 {
		t.Fatalf("events landed in %d days, want at least 6", got)
	}
	sev := 3
	for _, f := range []Filter{
		{},
		{Match: "alpha"},
		{Match: "alpha OR beta"},
		{Match: `"gamma delta"`},
		{Match: "n7"},
		{Host: "h1"},
		{SeverityID: &sev},
		{Match: "beta", Host: "h2"},
		{StartMs: base + dayMs + 5000, EndMs: base + 3*dayMs},
		{Match: "delta", StartMs: base + 2*dayMs - 1, EndMs: base + 2*dayMs},
		{StartMs: base + 4*dayMs},
		{EndMs: base + dayMs},
		{Restrict: true, AllowedSources: []int64{2}},
		{Match: "alpha", Restrict: true, AllowedSources: []int64{1, 3}},
		{Restrict: true},
		{Match: "zeta"},
	} {
		for _, page := range [][2]int{{10, 0}, {100, 0}, {50, 37}, {7, 900}, {1000, 0}, {20, 3990}, {5, 10000}} {
			f.Limit, f.Offset = page[0], page[1]
			for _, dense := range []bool{false, true} {
				denseMatches, denseFactor = 1_000_000, 20
				if dense {
					denseMatches, denseFactor = 1, 0
				}
				got, err := repo.Search(ctx, f)
				denseMatches, denseFactor = 2000, 20
				if err != nil {
					t.Fatal(err)
				}
				if want := o.page(t, f); !slices.Equal(keys(got), want) {
					t.Fatalf("%+v (dense %v): got %d events, want %d\\n got %v\\nwant %v",
						f, dense, len(got), len(want), head(keys(got)), head(want))
				}
			}
		}
	}
	// Ids are unique across days, and sort the same way as the events.
	recs, _ := repo.Search(ctx, Filter{Limit: 1000})
	seen := map[int64]bool{}
	for i, r := range recs {
		if seen[r.ID] || (i > 0 && r.Timestamp == recs[i-1].Timestamp && r.ID > recs[i-1].ID) {
			t.Fatalf("event %d: id %d repeated or out of order", i, r.ID)
		}
		seen[r.ID] = true
		if r.ID >= 1<<53 {
			t.Fatalf("id %d is beyond what JavaScript holds exactly", r.ID)
		}
	}
}

func head[T any](s []T) []T { return s[:min(len(s), 4)] }

// TestOverviewAcrossDays checks the dashboard adds up days correctly.
func TestOverviewAcrossDays(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	o := newOracle(t)
	rng := rand.New(rand.NewPCG(6, 6))
	base := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC).UnixMilli()
	all := randomEvents(rng, 3000, base)
	repo.InsertBatch(ctx, all)
	o.add(t, all)
	start, end := base+dayMs/2, base+5*dayMs+dayMs/3
	ov, err := repo.Overview(ctx, start, end, 6*3600_000, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	o.db.QueryRow(`SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?`, start, end).Scan(&total)
	var sum int64
	for _, b := range ov.Buckets {
		sum += b.Count
	}
	var bySev int64
	for _, n := range ov.BySeverity {
		bySev += n
	}
	if ov.Total != total || sum != total || bySev != total {
		t.Errorf("total %d, buckets %d, by severity %d; want %d", ov.Total, sum, bySev, total)
	}
	var src int64
	for _, s := range ov.TopSources {
		src += s.Count
	}
	if src != total {
		t.Errorf("sources add up to %d, want %d", src, total)
	}
}

// TestRetentionDeletesWholeDays: days before the cutoff go as files, the day
// it falls in loses only its older events.
func TestRetentionDeletesWholeDays(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	var recs []Record
	for d := 0; d < 10; d++ {
		for h := 0; h < 24; h++ {
			recs = append(recs, Record{Timestamp: base + int64(d)*dayMs + int64(h)*3600_000, CategoryUID: 1, ClassUID: 1001,
				SeverityID: 1, RawData: fmt.Sprintf("day %d hour %d", d, h)})
		}
	}
	repo.InsertBatch(ctx, recs)
	cutoff := base + 6*dayMs + 12*3600_000 // noon on the 7th day
	var removed int64
	for {
		n, err := repo.DeleteOlderThan(ctx, cutoff, 5)
		if err != nil {
			t.Fatal(err)
		}
		removed += n
		if n < 5 {
			break
		}
	}
	if removed != 6*24+12 {
		t.Errorf("removed %d events, want %d", removed, 6*24+12)
	}
	if days := db.Days(); len(days) != 4 || days[0] != "2026-09-07" {
		t.Errorf("days left = %v", days)
	}
	if n, _ := db.CountEvents(ctx, "e.timestamp < ?", cutoff); n != 0 {
		t.Errorf("%d events older than the cutoff remain", n)
	}
	if st, _ := repo.Stats(ctx); st.Events != 4*24-12 || st.Days != 4 {
		t.Errorf("stats = %+v", st)
	}
}

// TestMoveWhileSearching moves events out of the main database in small
// batches while searches run: each search sees every event exactly once.
func TestMoveWhileSearching(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	buildAt(t, path, 10) // 50 events in the main database, as v0.7 left them
	db, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	// More events, so there are many batches.
	var extra []Record
	for i := 0; i < 2000; i++ {
		extra = append(extra, Record{ID: int64(1000 + i), Timestamp: int64(i) * 3_600_000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1,
			RawData: fmt.Sprintf("chain extra %d", i)})
	}
	for _, r := range extra {
		db.Write.Exec(`INSERT INTO events (id, timestamp, category_uid, class_uid, severity_id, raw_data) VALUES (?, ?, 1, 1001, 1, ?)`,
			r.ID, r.Timestamp, r.RawData)
	}
	db.days.move.Lock()
	db.days.legacy = &shard{day: 0, path: path, read: db.Read, write: db.Write} // it now holds more
	db.days.move.Unlock()
	moveBatch = 37
	defer func() { moveBatch = 5000 }()

	var wg sync.WaitGroup
	done := make(chan struct{})
	var bad []string
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			recs, err := repo.Search(ctx, Filter{Match: "chain", Limit: 1000, Offset: 1000})
			first, err2 := repo.Search(ctx, Filter{Match: "chain", Limit: 1000})
			n, err3 := db.CountEvents(ctx, "e.raw_data LIKE 'chain%'")
			mu.Lock()
			switch {
			case err != nil || err2 != nil || err3 != nil:
				bad = append(bad, fmt.Sprint(err, err2, err3))
			default:
				uniq := map[string]bool{}
				for _, r := range append(first, recs...) {
					uniq[r.RawData] = true
				}
				// 2050 events: two full pages, none twice, none missing.
				if len(first) != 1000 || len(recs) != 1000 || len(uniq) != 2000 || n != 2050 {
					bad = append(bad, fmt.Sprintf("pages %d+%d with %d different, count %d", len(first), len(recs), len(uniq), n))
				}
			}
			mu.Unlock()
		}
	}()
	err = db.MoveLegacyEvents(ctx, nil)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("searches during the move went wrong %d times, e.g. %s", len(bad), strings.Join(head(bad), "; "))
	}
	if n, _ := db.CountEvents(ctx, "e.raw_data LIKE 'chain%'"); n != 2050 || db.MovingEvents() {
		t.Errorf("after moving: %d events, still moving %v", n, db.MovingEvents())
	}
}

// TestSeqAcrossProcesses: two handles on the same files (the server and a
// command) never give two events the same arrival number.
func TestSeqAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "siemlite.db")
	a, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	for _, db := range []*DB{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			repo := NewRepository(db)
			for i := 0; i < 50; i++ {
				if err := repo.InsertBatch(ctx, []Record{{Timestamp: time.Now().UnixMilli(), CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "x"},
					{Timestamp: 86_400_000 * 20000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "y"}}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	var dup int64
	total, _ := a.CountEvents(ctx, "1")
	distinct := map[int64]bool{}
	for _, day := range a.Days() {
		f, _ := sql.Open("sqlite", "file:"+filepath.Join(EventsDir(path), day+".db"))
		rows, _ := f.Query(`SELECT seq FROM events`)
		for rows.Next() {
			var s int64
			rows.Scan(&s)
			if distinct[s] {
				dup++
			}
			distinct[s] = true
		}
		rows.Close()
		f.Close()
	}
	if total != 200 || dup != 0 {
		t.Errorf("%d events, %d repeated arrival numbers", total, dup)
	}
}

// TestRetentionWhileStoring deletes an old day again and again while batches
// that include late events for that day keep arriving: no batch may fail.
func TestRetentionWhileStoring(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	now := time.Now().UnixMilli()
	old := now - 40*dayMs
	var wg sync.WaitGroup
	var failed []error
	var mu sync.Mutex
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				// Many late events, so the old day's batch is still being
				// written when retention comes for it.
				batch := []Record{{Timestamp: now, CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "current"}}
				for j := 0; j < 50; j++ {
					batch = append(batch, Record{Timestamp: old + int64(j), CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "late"})
				}
				if err := repo.InsertBatch(ctx, batch); err != nil {
					mu.Lock()
					failed = append(failed, err)
					mu.Unlock()
				}
			}
		}()
	}
	go func() { wg.Wait(); close(stop) }()
	for done := false; !done; {
		select {
		case <-stop:
			done = true
		default:
			if _, err := repo.DeleteOlderThan(ctx, now-30*dayMs, 1000); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(failed) > 0 {
		t.Errorf("%d batches failed, e.g. %v", len(failed), failed[0])
	}
	if n, _ := db.CountEvents(ctx, "e.raw_data = 'current'"); n != 400 {
		t.Errorf("current events stored = %d, want 400", n)
	}
}

// TestSearchIndexStaysExact: with text indexed once per batch, every stored
// event is indexed exactly once, through new batches, copies of moved events
// made twice, deletes, and a day file from before (which had a per-row
// trigger).
func TestSearchIndexStaysExact(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	day := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC).UnixMilli()

	// A version 1 day file, with its trigger and an event in it.
	old := buildOldDay(t, filepath.Join(EventsDir(db.Path()), "2026-10-03.db"), 1)
	if _, err := old.Exec(`CREATE TRIGGER events_ai AFTER INSERT ON events BEGIN
		INSERT INTO events_fts(rowid, raw_data) VALUES (new.id, new.raw_data); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO events (seq, timestamp, category_uid, class_uid, severity_id, raw_data)
		VALUES (1, ?, 1, 1001, 1, 'older word')`, day-dayMs/2); err != nil {
		t.Fatal(err)
	}
	old.Close()
	db.Close()
	db, err := Open(ctx, Options{Path: db.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo = NewRepository(db)

	var recs []Record
	for i := 0; i < 1234; i++ {
		recs = append(recs, Record{Timestamp: day - dayMs/2 + int64(i)*60_000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1,
			RawData: fmt.Sprintf("word%d common", i%10)})
	}
	for i := 0; i < len(recs); i += 400 {
		if err := repo.InsertBatch(ctx, recs[i:min(i+400, len(recs))]); err != nil {
			t.Fatal(err)
		}
	}
	// Moved events copied twice (a move resumed after a crash).
	moved := []Record{{ID: 9001, Timestamp: day + 1000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1, RawData: "moved common"}}
	for range 2 {
		if err := db.days.insert(ctx, moved, true); err != nil {
			t.Fatal(err)
		}
	}
	repo.DeleteOlderThan(ctx, day-dayMs/2+100*60_000, 50)

	total, _ := db.CountEvents(ctx, "1")
	common, _ := db.CountEvents(ctx, "e.raw_data LIKE '%common%'")
	if found, _ := repo.Search(ctx, Filter{Match: "common", Limit: 1000, Offset: 0}); len(found) != int(min(common, 1000)) {
		t.Errorf("search for common found %d, want %d", len(found), min(common, 1000))
	}
	var indexed int64
	for _, day := range db.Days() {
		f, _ := sql.Open("sqlite", "file:"+filepath.Join(EventsDir(db.Path()), day+".db"))
		if _, err := f.Exec(`INSERT INTO events_fts(events_fts) VALUES ('integrity-check')`); err != nil {
			t.Errorf("%s: search index: %v", day, err)
		}
		var n int64
		f.QueryRow(`SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'common OR older'`).Scan(&n)
		indexed += n
		var trig int
		f.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'events_ai'`).Scan(&trig)
		if trig != 0 {
			t.Errorf("%s still has the per-row trigger", day)
		}
		f.Close()
	}
	if indexed != total {
		t.Errorf("%d events indexed, %d stored", indexed, total)
	}
}

// buildOldDay creates a day file as versions 1 and 2 made it: the original
// line in raw_data (required), a search index over it, and no message. The
// caller adds events and closes it.
func buildOldDay(t *testing.T, path string, version int) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dayDSN(path, false))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	stmts := []string{`CREATE TABLE events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, seq INTEGER NOT NULL, legacy_id INTEGER, timestamp INTEGER NOT NULL,
		category_uid INTEGER NOT NULL, class_uid INTEGER NOT NULL, severity_id INTEGER NOT NULL,
		src_ip TEXT, dst_ip TEXT, user_name TEXT, raw_data TEXT NOT NULL, source TEXT, host TEXT,
		src_country TEXT, dst_country TEXT, src_asn INTEGER, dst_asn INTEGER, threat INTEGER NOT NULL DEFAULT 0,
		enrichment TEXT, source_id INTEGER, fields TEXT)`}
	for _, s := range daySchema { // the indexes have not changed
		if strings.Contains(s, "INDEX") {
			stmts = append(stmts, s)
		}
	}
	stmts = append(stmts,
		`CREATE VIRTUAL TABLE events_fts USING fts5(raw_data, content='events', content_rowid='id')`,
		`CREATE TRIGGER events_ad AFTER DELETE ON events BEGIN
			INSERT INTO events_fts(events_fts, rowid, raw_data) VALUES ('delete', old.id, old.raw_data); END`)
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// finishOldDay indexes what was added to a day made by buildOldDay and gives
// it its version, as the previous release left it.
func finishOldDay(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	for _, s := range []string{
		`INSERT INTO events_fts (rowid, raw_data) SELECT id, raw_data FROM events`,
		fmt.Sprintf(`PRAGMA user_version = %d`, version),
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
}

// checkIndex fails the test unless every day file's search index is
// consistent with its events.
func checkIndex(t *testing.T, db *DB) {
	t.Helper()
	for _, day := range db.Days() {
		f, err := sql.Open("sqlite", "file:"+filepath.Join(EventsDir(db.Path()), day+".db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Exec(`INSERT INTO events_fts(events_fts) VALUES ('integrity-check')`); err != nil {
			t.Errorf("%s: search index: %v", day, err)
		}
		f.Close()
	}
}

// TestOldDayFilesAreUpgraded: day files from versions 1 and 2 (the original
// line only, indexed) open as version 3: the message is the line, the index
// covers the parsed columns, and nothing is lost.
func TestOldDayFilesAreUpgraded(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	path := db.Path()
	db.Close()
	dir := EventsDir(path)
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).UnixMilli()
	for i, version := range []int{1, 2} {
		name := dayName(dayOf(day) - i)
		old := buildOldDay(t, filepath.Join(dir, name+".db"), version)
		for n := range 20 {
			if _, err := old.Exec(`INSERT INTO events (seq, timestamp, category_uid, class_uid, severity_id, raw_data, host)
				VALUES (?, ?, 1, 1001, 1, ?, 'web-1')`, i*20+n+1, day-int64(i)*dayMs+int64(n)*1000, fmt.Sprintf("<34>sshd: version%d line%d", version, n)); err != nil {
				t.Fatal(err)
			}
		}
		finishOldDay(t, old, version)
	}
	db, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	for _, c := range []struct {
		match string
		want  int
	}{{"version1", 20}, {"version2", 20}, {"line7", 2}, {"web", 40}, {`"web-1"`, 40}} {
		recs, err := repo.Search(ctx, Filter{Match: c.match, Limit: 100})
		if err != nil {
			t.Fatalf("%s: %v", c.match, err)
		}
		if len(recs) != c.want {
			t.Errorf("search %q found %d events, want %d", c.match, len(recs), c.want)
		}
	}
	recs, _ := repo.Search(ctx, Filter{Match: "line3 AND version2", Limit: 10})
	if len(recs) != 1 || recs[0].Message != "<34>sshd: version2 line3" || recs[0].RawData != recs[0].Message {
		t.Errorf("upgraded event = %+v", recs)
	}
	checkIndex(t, db)
	for _, d := range db.Days() {
		f, _ := sql.Open("sqlite", "file:"+filepath.Join(dir, d+".db"))
		var v int
		f.QueryRow(`PRAGMA user_version`).Scan(&v)
		var trig int
		f.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'events_ai'`).Scan(&trig)
		f.Close()
		if v != dayVersion || trig != 0 {
			t.Errorf("%s: version %d (want %d), per-row trigger %d", d, v, dayVersion, trig)
		}
	}
	// New events go in beside the old ones, and deleting keeps the index exact.
	if err := repo.InsertBatch(ctx, []Record{{Timestamp: day + 5000, CategoryUID: 1, ClassUID: 1001, SeverityID: 1, Message: "fresh message", Host: "web-9"}}); err != nil {
		t.Fatal(err)
	}
	repo.DeleteOlderThan(ctx, day-dayMs/2, 1000)
	checkIndex(t, db)
	if recs, _ := repo.Search(ctx, Filter{Match: "fresh", Limit: 10}); len(recs) != 1 {
		t.Errorf("fresh event not found: %v", recs)
	}
}
