package storage

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Events are stored one SQLite file per UTC day, by the time the event
// happened, in a folder next to the main database: siemlite.db keeps users,
// sources, rules, alerts and settings, and siemlite-events/2026-10-04.db that
// day's events. Retention deletes whole files, each day's indexes stay small
// so storing stays fast as history grows, and a search with dates only opens
// the days it covers.
//
// Databases from before day files kept events in the main database's events
// table. Opening one with Options.MoveEvents copies them into day files in the
// background (MoveLegacyEvents); until then that table is searched as one more
// "legacy" shard.

const (
	dayMs   = int64(24 * time.Hour / time.Millisecond)
	idShift = 37 // event id = day<<idShift | row id: unique, ordered, and within JavaScript's 2^53
	maxDay  = 1<<(53-idShift) - 1
)

// dayOf is the day number (days since 1970-01-01 UTC) an event time belongs
// to. Times outside what ids can hold are filed in the first or last day.
func dayOf(ms int64) int {
	d := ms / dayMs
	if ms < 0 && ms%dayMs != 0 {
		d--
	}
	return int(min(max(d, 1), maxDay))
}

func dayStart(day int) int64 { return int64(day) * dayMs }
func dayEnd(day int) int64   { return dayStart(day + 1) } // exclusive

func dayName(day int) string { return time.UnixMilli(dayStart(day)).UTC().Format("2006-01-02") }

var dayFileRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\.db$`)

func parseDayFile(name string) (int, bool) {
	m := dayFileRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	t, err := time.Parse("2006-01-02", m[1])
	if err != nil {
		return 0, false
	}
	d := dayOf(t.UnixMilli())
	return d, dayName(d) == m[1]
}

// eventID makes the id shown for an event; legacy events (day 0) keep theirs.
func eventID(day int, rowid int64) int64 { return int64(day)<<idShift | rowid }

// EventsDir is the folder that holds a database's day files.
func EventsDir(dbPath string) string {
	return strings.TrimSuffix(dbPath, filepath.Ext(dbPath)) + "-events"
}

// daySchema is the schema of a day file.
var daySchema = []string{
	`CREATE TABLE IF NOT EXISTS events (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		seq          INTEGER NOT NULL, -- order of arrival across all days, for the alert engine
		legacy_id    INTEGER,          -- id in the main database, for events moved from it
		timestamp    INTEGER NOT NULL,
		category_uid INTEGER NOT NULL,
		class_uid    INTEGER NOT NULL,
		severity_id  INTEGER NOT NULL,
		src_ip       TEXT,
		dst_ip       TEXT,
		user_name    TEXT,
		message      TEXT NOT NULL DEFAULT '', -- the parsed message, kept for the whole retention period
		raw_data     TEXT,                     -- the original line; '' once removed (see PurgeRawLines)
		source       TEXT,
		host         TEXT,
		src_country  TEXT,
		dst_country  TEXT,
		src_asn      INTEGER,
		dst_asn      INTEGER,
		threat       INTEGER NOT NULL DEFAULT 0,
		enrichment   TEXT,
		source_id    INTEGER,
		fields       TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_lookup ON events(timestamp DESC, category_uid, severity_id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_seq ON events(seq)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_legacy ON events(legacy_id) WHERE legacy_id IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_events_threat ON events(timestamp DESC) WHERE threat = 1`,
	`CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id, timestamp DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip, timestamp DESC) WHERE src_ip IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip, timestamp DESC) WHERE dst_ip IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_name, timestamp DESC) WHERE user_name IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_events_host ON events(host, timestamp DESC) WHERE host IS NOT NULL`,
	ftsTable,
	// Text is indexed once per batch (see insertDay), not row by row: with
	// multi-row inserts and large transactions that stores events several
	// times faster.
	ftsDeleteTrigger,
	`PRAGMA user_version = 3`,
}

// dayVersion is the day file format. Version 3 stores the parsed message and
// indexes the parsed event instead of the original line, which is removed
// after a day (versions 1 and 2 indexed the original line).
const dayVersion = 3

// ftsCols are the columns of events the search index covers: what the parser
// made of the line, so searching still works after the original is removed.
// The delete trigger must pass exactly these values.
const ftsCols = `message, source, host, user_name, src_ip, dst_ip, fields`

const (
	ftsTable = `CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(` + ftsCols + `, content='events', content_rowid='id')`

	ftsDeleteTrigger = `CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
		INSERT INTO events_fts(events_fts, rowid, ` + ftsCols + `) VALUES ('delete', old.id, old.message, old.source, old.host, old.user_name, old.src_ip, old.dst_ip, old.fields);
	END`
)

// migrateDay brings a day file from version 1 or 2 up to the current one:
// every event's message becomes its original line (all that was kept), and
// the search index is rebuilt over the parsed columns. It runs in one write
// transaction that checks the version again once it holds the lock, so two
// processes opening the same files migrate it once.
func migrateDay(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", dayDSN(path, false))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var v int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v >= dayVersion {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil) // takes the write lock
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v >= dayVersion {
		return nil // another process got there first
	}
	var hasMessage int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'message'`).Scan(&hasMessage); err != nil {
		return err
	}
	stmts := []string{
		`DROP TRIGGER IF EXISTS events_ai`, // version 1 indexed row by row
		`DROP TRIGGER IF EXISTS events_ad`,
		`DROP TABLE IF EXISTS events_fts`,
	}
	if hasMessage == 0 {
		stmts = append(stmts, `ALTER TABLE events ADD COLUMN message TEXT NOT NULL DEFAULT ''`)
	}
	stmts = append(stmts, `UPDATE events SET message = raw_data WHERE message = ''`)
	stmts = append(stmts, ftsTable, ftsDeleteTrigger, `INSERT INTO events_fts(events_fts) VALUES ('rebuild')`)
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("upgrade day file %s: %.40s: %w", filepath.Base(path), stmt, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, dayVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// shard is one place events are kept: a day file, or (day 0) the main
// database's events table while it still holds events.
type shard struct {
	day  int
	path string

	mu          sync.Mutex
	read, write *sql.DB // opened on first use; the legacy shard borrows the main database's

	count atomic.Int64 // cached number of events; -1 when unknown
}

func dayDSN(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		// Take the write lock when a transaction begins, so another process
		// writing the same day (a command sending an audit event) is waited
		// for rather than reported as "database is locked".
		q.Set("_txlock", "immediate")
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
		q.Add("_pragma", "cache_size(-16384)")
		// Checkpoint the write-ahead log every 40 MB rather than 4: storing
		// is much faster, and the log is truncated when the day is closed.
		q.Add("_pragma", "wal_autocheckpoint(10000)")
	}
	return "file:" + path + "?" + q.Encode()
}

// writer returns the shard's write pool, creating the file and its schema
// the first time.
func (s *shard) writer(ctx context.Context) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.write != nil {
		return s.write, nil
	}
	db, err := sql.Open("sqlite", dayDSN(s.path, false))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(5 * time.Minute) // past days are rarely written; let them close
	for _, stmt := range daySchema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("day file %s: %w", filepath.Base(s.path), err)
		}
	}
	s.write = db
	return db, nil
}

// reader returns the shard's read pool.
func (s *shard) reader() (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.read != nil {
		return s.read, nil
	}
	db, err := sql.Open("sqlite", dayDSN(s.path, true))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(time.Minute)
	s.read = db
	return db, nil
}

func (s *shard) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.day == 0 {
		return // the main database's pools
	}
	if s.read != nil {
		s.read.Close()
		s.read = nil
	}
	if s.write != nil {
		_, _ = s.write.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		s.write.Close()
		s.write = nil
	}
}

// seqCol is the column holding the arrival order: legacy events use their id.
func (s *shard) seqCol() string {
	if s.day == 0 {
		return "e.id"
	}
	return "e.seq"
}

// globalID turns a row id in this shard into an event id.
func (s *shard) globalID(rowid int64) int64 { return eventID(s.day, rowid) }

// days manages the day files.
type days struct {
	dir  string
	main *DB

	mu     sync.Mutex
	shards map[int]*shard // every day file that exists

	// writeMu serializes storing events, so arrival numbers (seq) are
	// committed in order and the alert engine never passes one that isn't
	// visible yet.
	writeMu sync.Mutex
	seq     atomic.Int64 // highest seq committed by this process

	// While events are being moved out of the main database, a batch's copy
	// and the legacy shard's new starting point change together (move.Lock);
	// readers hold move.RLock so they never see an event twice.
	move         sync.RWMutex
	legacy       *shard // nil once the main database holds no events
	movedThrough int64  // legacy events with ids up to this are in day files
}

func openDays(ctx context.Context, main *DB) (*days, error) {
	d := &days{dir: EventsDir(main.path), main: main, shards: map[int]*shard{}}
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return nil, fmt.Errorf("events folder: %w", err)
	}
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if day, ok := parseDayFile(e.Name()); ok && !e.IsDir() {
			if err := migrateDay(ctx, filepath.Join(d.dir, e.Name())); err != nil {
				return nil, err
			}
			d.shards[day] = d.newShard(day)
		}
	}
	var seq, moved int64
	if err := main.Read.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'event_seq'), 0),
		COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'legacy_moved_through'), 0)`).Scan(&seq, &moved); err != nil {
		return nil, fmt.Errorf("read event counters: %w", err)
	}
	d.seq.Store(seq)
	d.movedThrough = moved
	var left bool
	if err := main.Read.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE id > ?)`, moved).Scan(&left); err != nil {
		return nil, fmt.Errorf("check for events to move: %w", err)
	}
	if left {
		d.legacy = &shard{day: 0, path: main.path, read: main.Read, write: main.Write}
		d.legacy.count.Store(-1)
	}
	return d, nil
}

func (d *days) newShard(day int) *shard {
	s := &shard{day: day, path: filepath.Join(d.dir, dayName(day)+".db")}
	s.count.Store(-1)
	return s
}

// shard returns the shard for a day, creating it when create is set.
func (d *days) shard(day int, create bool) *shard {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.shards[day]
	if !ok && create {
		s = d.newShard(day)
		d.shards[day] = s
	}
	return s
}

// writable returns a day's shard, creating its file and schema first when
// the day is new, so a day is only listed (and backed up) once it is
// complete. Callers hold writeMu.
func (d *days) writable(ctx context.Context, day int) (*shard, error) {
	if s := d.shard(day, false); s != nil {
		return s, nil
	}
	s := d.newShard(day)
	if _, err := s.writer(ctx); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.shards[day] = s
	d.mu.Unlock()
	return s, nil
}

// span returns the shards that can hold events in [startMs, endMs] (0 means
// unbounded), newest first, with the legacy shard (which spans every day)
// first while it exists. Callers hold move.RLock.
func (d *days) span(startMs, endMs int64) []*shard {
	d.mu.Lock()
	var out []*shard
	for day, s := range d.shards {
		if (startMs > 0 && dayEnd(day) <= startMs) || (endMs > 0 && dayStart(day) > endMs) {
			continue
		}
		out = append(out, s)
	}
	d.mu.Unlock()
	slices.SortFunc(out, func(a, b *shard) int { return b.day - a.day })
	if d.legacy != nil {
		out = append([]*shard{d.legacy}, out...)
	}
	return out
}

// legacyWhere is the condition that leaves out legacy events already moved.
func (d *days) legacyWhere(s *shard) (string, []any) {
	if s.day != 0 {
		return "", nil
	}
	return "e.id > ?", []any{d.movedThrough}
}

// allocate reserves n arrival numbers in the main database (so processes
// sharing the files never reuse one) and returns the first.
func (d *days) allocate(ctx context.Context, n int) (int64, error) {
	var last int64
	err := d.main.Write.QueryRowContext(ctx, `INSERT INTO settings (key, value) VALUES ('event_seq', ?)
		ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + ? RETURNING CAST(value AS INTEGER)`, n, n).Scan(&last)
	if err != nil {
		return 0, fmt.Errorf("number events: %w", err)
	}
	return last - int64(n) + 1, nil
}

const insertCols = `seq, legacy_id, timestamp, category_uid, class_uid, severity_id, src_ip, dst_ip, user_name, message, raw_data,
	source, host, src_country, dst_country, src_asn, dst_asn, threat, enrichment, source_id, fields`

// insert stores records in their days' files, one transaction per day.
// legacy is set when moving events from the main database: they keep their
// id as both seq and legacy_id, and copying one twice is a no-op.
func (d *days) insert(ctx context.Context, recs []Record, legacy bool) error {
	if len(recs) == 0 {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	var first int64
	if !legacy {
		var err error
		if first, err = d.allocate(ctx, len(recs)); err != nil {
			return err
		}
	}
	byDay := map[int][]int{}
	for i := range recs {
		day := dayOf(recs[i].Timestamp)
		byDay[day] = append(byDay[day], i)
	}
	verb := "INSERT"
	if legacy {
		verb = "INSERT OR IGNORE"
	}
	for day, idx := range byDay {
		s, err := d.writable(ctx, day)
		if err != nil {
			return err
		}
		w, err := s.writer(ctx)
		if err != nil {
			return err
		}
		if err := insertDay(ctx, w, recs, idx, verb, first, legacy); err != nil {
			return err
		}
		s.count.Store(-1)
	}
	if !legacy {
		d.seq.Store(first + int64(len(recs)) - 1)
	}
	return nil
}

// rowsPerInsert is how many events go in one INSERT statement (each has 21
// values; SQLite allows 32766).
const rowsPerInsert = 200

// insertDay stores one day's share of a batch in a single transaction:
// multi-row INSERTs, then the batch's text indexed with one statement.
func insertDay(ctx context.Context, w *sql.DB, recs []Record, idx []int, verb string, first int64, legacy bool) error {
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	defer tx.Rollback()
	// Row ids only grow (AUTOINCREMENT), and the write lock is held from the
	// start, so this batch's rows are exactly those above the current top.
	var top int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&top); err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	stmts := map[int]*sql.Stmt{}
	defer func() {
		for _, st := range stmts {
			st.Close()
		}
	}()
	row := "(" + strings.TrimSuffix(strings.Repeat("?, ", 21), ", ") + ")"
	args := make([]any, 0, rowsPerInsert*21)
	for start := 0; start < len(idx); start += rowsPerInsert {
		chunk := idx[start:min(start+rowsPerInsert, len(idx))]
		stmt, ok := stmts[len(chunk)]
		if !ok {
			if stmt, err = tx.PrepareContext(ctx, verb+` INTO events (`+insertCols+`) VALUES `+
				strings.TrimSuffix(strings.Repeat(row+", ", len(chunk)), ", ")); err != nil {
				return fmt.Errorf("prepare insert: %w", err)
			}
			stmts[len(chunk)] = stmt
		}
		args = args[:0]
		for _, i := range chunk {
			rec := &recs[i]
			seq, legacyID := first+int64(i), any(nil)
			if legacy {
				seq, legacyID = rec.ID, rec.ID
			}
			args = append(args, seq, legacyID,
				rec.Timestamp, rec.CategoryUID, rec.ClassUID, rec.SeverityID,
				nullable(rec.SrcIP), nullable(rec.DstIP), nullable(rec.UserName), cmp.Or(rec.Message, rec.RawData), rec.RawData,
				nullable(rec.Source), nullable(rec.Host), nullable(rec.SrcCountry), nullable(rec.DstCountry),
				nullableInt(rec.SrcASN), nullableInt(rec.DstASN), rec.Threat, nullable(string(rec.Enrichment)),
				nullableInt64(rec.SourceID), nullable(string(rec.Fields)))
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return fmt.Errorf("insert records %d-%d: %w", chunk[0], chunk[len(chunk)-1], err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events_fts (rowid, `+ftsCols+`) SELECT id, `+ftsCols+` FROM events WHERE id > ?`, top); err != nil {
		return fmt.Errorf("index batch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// remove closes a day and deletes its files.
func (d *days) remove(day int) error {
	d.mu.Lock()
	s, ok := d.shards[day]
	delete(d.shards, day)
	d.mu.Unlock()
	if !ok {
		return nil
	}
	s.close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(s.path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (d *days) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.shards {
		s.close()
	}
}

// count returns a shard's number of events, from cache when nothing changed.
func (d *days) countShard(ctx context.Context, s *shard) (int64, error) {
	if n := s.count.Load(); n >= 0 && s.day != 0 {
		return n, nil
	}
	db, err := s.reader()
	if err != nil {
		return 0, err
	}
	where, args := d.legacyWhere(s)
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events e`+whereSQL(nonEmpty(where)), args...).Scan(&n); err != nil {
		return 0, err
	}
	s.count.Store(n)
	return n, nil
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// fileSize is the size of a day file and its write-ahead log.
func fileSize(path string) int64 {
	var n int64
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(path + suffix); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// Days lists the days that have a file, oldest first (for backups and tests).
func (d *DB) Days() []string {
	d.days.mu.Lock()
	defer d.days.mu.Unlock()
	var nums []int
	for day := range d.days.shards {
		nums = append(nums, day)
	}
	slices.Sort(nums)
	out := make([]string, len(nums))
	for i, n := range nums {
		out[i] = dayName(n)
	}
	return out
}

// CountEvents counts events matching a SQL condition on events (alias e),
// across every day: for tests and maintenance, not for user input.
func (d *DB) CountEvents(ctx context.Context, where string, args ...any) (int64, error) {
	d.days.move.RLock()
	defer d.days.move.RUnlock()
	var total int64
	for _, s := range d.days.span(0, 0) {
		db, err := s.reader()
		if err != nil {
			return 0, err
		}
		lw, largs := d.days.legacyWhere(s)
		var n int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events e`+whereSQL(nonEmpty(where, lw)),
			append(slices.Clone(args), largs...)...).Scan(&n); err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
