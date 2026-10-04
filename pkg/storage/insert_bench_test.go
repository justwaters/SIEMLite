package storage

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestInsertStrategies compares ways of storing a batch of events in a day
// file. It only runs with SIEMLITE_BENCH=1 (SIEMLITE_BENCH_ONLY picks
// strategies by name, SIEMLITE_BENCH_N and SIEMLITE_BENCH_PREFILL set sizes),
// and prints events per second for each into an empty day and into one
// already holding many events. It is how day files' insert path (insertDay)
// was chosen: multi-row inserts, one text-index update per batch, large
// batches and less frequent checkpoints together store about 4x faster.
func TestInsertStrategies(t *testing.T) {
	if os.Getenv("SIEMLITE_BENCH") == "" {
		t.Skip("set SIEMLITE_BENCH=1 to compare insert strategies")
	}
	n, prefill := 200_000, 1_000_000
	if v := os.Getenv("SIEMLITE_BENCH_N"); v != "" {
		fmt.Sscan(v, &n)
	}
	if v := os.Getenv("SIEMLITE_BENCH_PREFILL"); v != "" {
		fmt.Sscan(v, &prefill)
	}
	recs := benchRecords(n + prefill)
	type strategy struct {
		name      string
		batch     int
		multiRow  int  // rows per INSERT statement (1 = one row each)
		bulkFTS   bool // index text once per batch instead of by trigger
		pageSize  int
		mmap      bool
		autoCkpt  int // wal_autocheckpoint pages (0 = default 1000)
		cacheMB   int
		dropIndex bool // no secondary indexes at all (an upper bound, not a candidate)
		automerge int  // FTS5 automerge (0 = default 4)
	}
	strategies := []strategy{
		{name: "before: 1 row/stmt, FTS trigger, batch 500", batch: 500, multiRow: 1},
		{name: "batch 5000", batch: 5000, multiRow: 1},
		{name: "multi-row 50/stmt", batch: 500, multiRow: 50},
		{name: "multi-row 200/stmt", batch: 500, multiRow: 200},
		{name: "bulk FTS per batch", batch: 500, multiRow: 1, bulkFTS: true},
		{name: "multi-row 200 + bulk FTS", batch: 500, multiRow: 200, bulkFTS: true},
		{name: "multi-row 200 + bulk FTS, batch 5000", batch: 5000, multiRow: 200, bulkFTS: true},
		{name: "page size 16k", batch: 500, multiRow: 1, pageSize: 16384},
		{name: "mmap 256 MB", batch: 500, multiRow: 1, mmap: true},
		{name: "autocheckpoint 10000 pages", batch: 500, multiRow: 1, autoCkpt: 10000},
		{name: "cache 256 MB", batch: 500, multiRow: 1, cacheMB: 256},
		{name: "(bound) no secondary indexes", batch: 500, multiRow: 1, dropIndex: true},
		{name: "FTS automerge 8", batch: 500, multiRow: 1, automerge: 8},
		{name: "FTS automerge 16", batch: 500, multiRow: 1, automerge: 16},
		{name: "batch 5000 + FTS automerge 8", batch: 5000, multiRow: 1, automerge: 8},
		{name: "now: multi 200, bulk FTS, 5000, ckpt 10k", batch: 5000, multiRow: 200, bulkFTS: true, autoCkpt: 10000},
		{name: "best + FTS automerge 8", batch: 5000, multiRow: 200, bulkFTS: true, autoCkpt: 10000, automerge: 8},
	}
	if only := os.Getenv("SIEMLITE_BENCH_ONLY"); only != "" {
		var keep []strategy
		for _, st := range strategies {
			if strings.Contains(st.name, only) {
				keep = append(keep, st)
			}
		}
		strategies = keep
	}
	ctx := context.Background()
	t.Logf("%-46s %14s %14s", "strategy", "empty day", "after 1M")
	for _, st := range strategies {
		var rates [2]float64
		for k, pre := range []int{0, prefill} {
			path := filepath.Join(t.TempDir(), "2026-10-04.db")
			q := dayDSN(path, false)
			if st.pageSize > 0 {
				q += fmt.Sprintf("&_pragma=page_size(%d)", st.pageSize)
				// page_size must come before WAL is switched on; rebuild the DSN.
				q = strings.Replace(dayDSN(path, false), "_pragma=busy_timeout", fmt.Sprintf("_pragma=page_size(%d)&_pragma=busy_timeout", st.pageSize), 1)
			}
			if st.mmap {
				q += "&_pragma=mmap_size(268435456)"
			}
			if st.autoCkpt > 0 {
				q += fmt.Sprintf("&_pragma=wal_autocheckpoint(%d)", st.autoCkpt)
			}
			if st.cacheMB > 0 {
				q += fmt.Sprintf("&_pragma=cache_size(-%d)", st.cacheMB*1024)
			}
			db, err := sql.Open("sqlite", q)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			for _, s := range daySchema {
				if st.dropIndex && strings.HasPrefix(s, "CREATE INDEX") {
					continue
				}
				if _, err := db.ExecContext(ctx, s); err != nil {
					t.Fatal(err)
				}
			}
			if !st.bulkFTS { // index row by row, as day files did before
				if _, err := db.ExecContext(ctx, `CREATE TRIGGER events_ai AFTER INSERT ON events BEGIN
					INSERT INTO events_fts(rowid, raw_data) VALUES (new.id, new.raw_data); END`); err != nil {
					t.Fatal(err)
				}
			}
			if st.automerge > 0 {
				if _, err := db.ExecContext(ctx, `INSERT INTO events_fts (events_fts, rank) VALUES ('automerge', ?)`, st.automerge); err != nil {
					t.Fatal(err)
				}
			}
			if pre > 0 { // fill the day first, the same way
				if err := benchInsert(ctx, db, recs[n:n+pre], 5000, 200, st.bulkFTS); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			for i := 0; i < n; i += st.batch {
				if err := benchInsert(ctx, db, recs[i:min(i+st.batch, n)], st.batch, st.multiRow, st.bulkFTS); err != nil {
					t.Fatal(err)
				}
			}
			rates[k] = float64(n) / time.Since(start).Seconds()
			var check int
			db.QueryRow(`SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'password'`).Scan(&check)
			if check == 0 {
				t.Fatalf("%s: search index is empty", st.name)
			}
			db.Close()
		}
		t.Logf("%-46s %12.0f/s %12.0f/s", st.name, rates[0], rates[1])
	}
}

// benchInsert stores recs in one transaction.
func benchInsert(ctx context.Context, db *sql.DB, recs []Record, batch, perStmt int, bulkFTS bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var firstID int64
	if bulkFTS {
		tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&firstID)
	}
	row := "(?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	stmts := map[int]*sql.Stmt{}
	stmtFor := func(rows int) (*sql.Stmt, error) {
		if s, ok := stmts[rows]; ok {
			return s, nil
		}
		s, err := tx.PrepareContext(ctx, `INSERT INTO events (`+insertCols+`) VALUES `+strings.TrimSuffix(strings.Repeat(row+",", rows), ","))
		stmts[rows] = s
		return s, err
	}
	for i := 0; i < len(recs); i += perStmt {
		chunk := recs[i:min(i+perStmt, len(recs))]
		s, err := stmtFor(len(chunk))
		if err != nil {
			return err
		}
		args := make([]any, 0, len(chunk)*19)
		for j := range chunk {
			r := &chunk[j]
			args = append(args, int64(i+j), r.Timestamp, r.CategoryUID, r.ClassUID, r.SeverityID,
				nullable(r.SrcIP), nullable(r.DstIP), nullable(r.UserName), r.RawData,
				nullable(r.Source), nullable(r.Host), nullable(r.SrcCountry), nullable(r.DstCountry),
				nullableInt(r.SrcASN), nullableInt(r.DstASN), r.Threat, nullable(string(r.Enrichment)),
				nullableInt64(r.SourceID), nullable(string(r.Fields)))
		}
		if _, err := s.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	if bulkFTS {
		if _, err := tx.ExecContext(ctx, `INSERT INTO events_fts (rowid, raw_data) SELECT id, raw_data FROM events WHERE id > ?`, firstID); err != nil {
			return err
		}
	}
	for _, s := range stmts {
		s.Close()
	}
	return tx.Commit()
}

// benchRecords makes events like the load test's: varied text, addresses,
// users and hosts, all in one day.
func benchRecords(n int) []Record {
	rng := rand.New(rand.NewPCG(1, 2))
	words := []string{"failed", "password", "accepted", "connection", "refused", "timeout", "denied", "login", "session",
		"opened", "closed", "error", "warning", "request", "served", "upload", "download", "admin", "kernel", "firewall"}
	day := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC).UnixMilli()
	out := make([]Record, n)
	for i := range out {
		var b strings.Builder
		for w := 0; w < 6+rng.IntN(6); w++ {
			b.WriteString(words[rng.IntN(len(words))])
			b.WriteByte(' ')
		}
		src := fmt.Sprintf("10.%d.%d.%d", rng.IntN(4), rng.IntN(256), rng.IntN(256))
		fmt.Fprintf(&b, "from %s user%d id=%d", src, rng.IntN(2000), i)
		out[i] = Record{Timestamp: day + int64(i)*86_400_000/int64(n), CategoryUID: 1 + rng.IntN(6), ClassUID: 3002,
			SeverityID: rng.IntN(7), SrcIP: src, DstIP: fmt.Sprintf("192.0.2.%d", rng.IntN(256)),
			UserName: fmt.Sprintf("user%d", rng.IntN(2000)), RawData: b.String(), Source: "sshd",
			Host: fmt.Sprintf("host%d", rng.IntN(50)), SourceID: int64(1 + rng.IntN(8)), Fields: []byte(`{"action":"x"}`)}
	}
	return out
}
