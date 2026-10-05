package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// buildAt creates a database exactly as schema version k left it, using the
// same statements that built it at the time, and fills it with the kind of
// data a real install at that version holds.
func buildAt(t *testing.T, path string, k int) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := append([]string{}, schemaStatements...)
	if k < 6 {
		stmts = append(stmts, `CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL, revoked_at INTEGER)`)
	}
	for v := 3; v < k; v++ {
		stmts = append(stmts, upgrades[v]...)
	}
	stmts = append(stmts,
		`INSERT INTO users (id, username, password_hash, role, created_at) VALUES (1, 'root', 'h1', 'admin', 1)`,
		fmt.Sprintf(`INSERT INTO users (id, username, password_hash, role, created_at) VALUES (2, 'ann', 'h2', '%s', 1)`,
			map[bool]string{true: "analyst", false: "standard"}[k < 6]),
		`INSERT INTO sessions VALUES ('tok', 2, 1, 9999999999999)`,
		`INSERT INTO indicators (type, value, source, added_at) VALUES ('ip', '203.0.113.7', 'feed', 1)`,
	)
	for i := 0; i < 50; i++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO events (timestamp, category_uid, class_uid, severity_id, src_ip, raw_data)
			VALUES (%d, 3, 3002, %d, '10.0.0.%d', 'chain v%d event %d failed password')`, 1000+i, i%7, i%9, k, i))
	}
	switch {
	case k < 6:
		stmts = append(stmts, `INSERT INTO api_keys (id, name, role, key_hash, created_at) VALUES (7, 'app', 'write', 'hash-app', 1)`)
	default:
		stmts = append(stmts,
			`INSERT INTO sources (id, name, kind, key_hash, created_at) VALUES (7, 'app', 'token', 'hash-app', 1)`,
			`INSERT INTO user_sources VALUES (2, 7)`,
			`UPDATE events SET source_id = 7 WHERE id % 2 = 0`)
	}
	if k >= 7 {
		stmts = append(stmts, `UPDATE users SET limited = 1 WHERE id = 2`)
	}
	if k >= 8 {
		stmts = append(stmts, `INSERT INTO settings VALUES ('backup_schedule', '{"every_hours":24,"keep":7}')`)
	}
	stmts = append(stmts, fmt.Sprintf(`PRAGMA user_version = %d`, k))
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("v%d: %v\n%s", k, err, s)
		}
	}
}

// schemaOf lists every table, index and trigger with its SQL.
func schemaOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var typ, name, s string
		rows.Scan(&typ, &name, &s)
		fmt.Fprintf(&sb, "%s %s: %s\n", typ, name, strings.Join(strings.Fields(s), " "))
	}
	return sb.String()
}

// TestUpgradeChainFromEveryVersion upgrades a populated database from every
// schema version SIEMLite has shipped and checks the result is the same as a
// new database, with every row, reference and search index intact.
func TestUpgradeChainFromEveryVersion(t *testing.T) {
	ctx := context.Background()
	fresh, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "fresh.db")})
	if err != nil {
		t.Fatal(err)
	}
	want := schemaOf(t, fresh.Read)
	fresh.Close()

	// Databases at v11 or later have already moved their events (see
	// TestUpgradeFromV11); the rest of this test follows the move.
	for k := 3; k < 11; k++ {
		t.Run(fmt.Sprintf("v%d", k), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			buildAt(t, path, k)
			for open := 0; open < 2; open++ { // the second open must change nothing
				db, err := Open(ctx, Options{Path: path})
				if err != nil {
					t.Fatalf("open %d: %v", open, err)
				}
				check := func(q string, want any) {
					t.Helper()
					var got any
					if err := db.Write.QueryRow(q).Scan(&got); err != nil {
						t.Fatalf("%s: %v", q, err)
					}
					if fmt.Sprint(got) != fmt.Sprint(want) {
						t.Errorf("%s = %v, want %v", q, got, want)
					}
				}
				if got := schemaOf(t, db.Read); got != want {
					t.Errorf("schema differs from a new database:\n got: %s\nwant: %s", got, want)
				}
				check(`PRAGMA user_version`, schemaVersion)
				check(`PRAGMA integrity_check`, "ok")
				check(`PRAGMA foreign_keys`, 1)
				check(`SELECT COUNT(*) FROM pragma_foreign_key_check`, 0)
				check(`SELECT role FROM users WHERE username = 'ann'`, "standard")
				check(`SELECT COUNT(*) FROM indicators`, 1)
				check(`SELECT group_concat(kind, ' ') FROM (SELECT kind FROM sources WHERE kind <> 'token' ORDER BY kind)`, "internal syslog upload")
				check(`SELECT COUNT(*) FROM alert_rules WHERE builtin = 1`, 4)
				check(`SELECT kind || ' ' || COALESCE(revoked_at, 'live') FROM sources WHERE id = 7`, "token live")
				if k >= 6 {
					check(`SELECT limited FROM users WHERE id = 2`, 1)
					check(`SELECT COUNT(*) FROM user_sources WHERE user_id = 2 AND source_id = 7`, 1)
				}
				if k >= 8 {
					check(`SELECT COUNT(*) FROM settings WHERE key = 'backup_schedule'`, 1)
				}
				{
					// The parser_none column (v12) starts off for every source and
					// keeps a value set after the upgrade across a restart.
					want := 0
					if open > 0 {
						want = 1
					}
					check(`SELECT parser_none FROM sources WHERE id = 7`, want)
					check(`SELECT COUNT(*) FROM sources WHERE parser_none <> 0 AND id <> 7`, 0)
					if _, err := db.Write.Exec(`UPDATE sources SET parser_none = 1, parser_id = NULL WHERE id = 7`); err != nil {
						t.Fatal(err)
					}
				}
				count := func(where string, want int64) {
					t.Helper()
					if n, err := db.CountEvents(ctx, where); err != nil || n != want {
						t.Errorf("events where %s = %d, %v; want %d", where, n, err, want)
					}
				}
				repo := NewRepository(db)
				search := func(match string) int {
					t.Helper()
					recs, err := repo.Search(ctx, Filter{Match: match, Limit: 1000})
					if err != nil {
						t.Fatal(err)
					}
					return len(recs)
				}

				if open == 0 {
					// Before the move, the events are searched where they are.
					if !db.MovingEvents() || search(`"failed password" AND chain`) != 50 {
						t.Errorf("before moving: moving %v, found %d", db.MovingEvents(), search(`"failed password" AND chain`))
					}
					check(`SELECT value FROM settings WHERE key = 'event_seq'`, 50)
					if err := db.MoveLegacyEvents(ctx, nil); err != nil {
						t.Fatal(err)
					}
				}
				if db.MovingEvents() {
					t.Error("events left to move after moving them")
				}
				check(`SELECT COUNT(*) FROM events`, 0) // the main database's old table is empty
				check(`SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'chain'`, 0)
				count(`e.raw_data LIKE 'chain%'`, 50)
				count(`e.message = e.raw_data AND e.message LIKE 'chain%'`, 50) // a moved event's message is its line
				count(`e.seq = e.legacy_id`, 50)                                // moved events keep their id as their arrival number
				if n := search(`"failed password" AND chain`); n != 50 {
					t.Errorf("search after moving found %d, want 50", n)
				}
				if k >= 6 {
					count(`e.source_id = 7`, int64(25+open))
				}
				for _, day := range db.Days() {
					if err := CheckDayFile(ctx, filepath.Join(EventsDir(path), day+".db")); err != nil {
						t.Error(err)
					}
				}
				// The upgraded database works: new events are numbered after
				// the moved ones and are searchable.
				if err := repo.InsertBatch(ctx, []Record{{Timestamp: 5000, CategoryUID: 6, ClassUID: 6003, SeverityID: 1,
					RawData: fmt.Sprintf("after upgrade %d", open), SourceID: 7}}); err != nil {
					t.Fatal(err)
				}
				check(`SELECT value FROM settings WHERE key = 'event_seq'`, 51+open)
				if n := search("upgrade"); n != open+1 {
					t.Errorf("new events found = %d, want %d", n, open+1)
				}
				db.Close()
			}
		})
	}
}

// TestUpgradeFromV11 adds parser_none to a v11 database: every source starts
// with it off, a source's parser is kept, and the value set afterwards
// survives another open.
func TestUpgradeFromV11(t *testing.T) {
	ctx := context.Background()
	fresh, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "fresh.db")})
	if err != nil {
		t.Fatal(err)
	}
	want := schemaOf(t, fresh.Read)
	fresh.Close()

	path := filepath.Join(t.TempDir(), "old.db")
	buildAt(t, path, 11)
	raw, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO parsers (id, name, definition, created_at, updated_at) VALUES (3, 'nginx', '{}', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE sources SET parser_id = 3 WHERE id = 7`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	for open := 0; open < 2; open++ { // the second open must change nothing
		db, err := Open(ctx, Options{Path: path})
		if err != nil {
			t.Fatalf("open %d: %v", open, err)
		}
		if got := schemaOf(t, db.Read); got != want {
			t.Errorf("schema differs from a new database:\n got: %s\nwant: %s", got, want)
		}
		var version, none, parserID int
		db.Write.QueryRow(`PRAGMA user_version`).Scan(&version)
		db.Write.QueryRow(`SELECT parser_none, COALESCE(parser_id, 0) FROM sources WHERE id = 7`).Scan(&none, &parserID)
		if version != schemaVersion || none != open || parserID != 3-open*3 {
			t.Errorf("open %d: version %d, parser_none %d, parser_id %d", open, version, none, parserID)
		}
		var others int
		db.Write.QueryRow(`SELECT COUNT(*) FROM sources WHERE parser_none <> 0 AND id <> 7`).Scan(&others)
		if others != 0 {
			t.Errorf("other sources have parser_none set: %d", others)
		}
		if open == 0 {
			if _, err := db.Write.Exec(`UPDATE sources SET parser_none = 1, parser_id = NULL WHERE id = 7`); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
	}
}
