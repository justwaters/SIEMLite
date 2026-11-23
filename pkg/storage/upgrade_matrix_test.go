package storage

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// downgrades[k] undoes upgrades[k]: it turns a database at user_version k+1
// into the shape it had at user_version k. Applying downgrades[schemaVersion-1] down to
// downgrades[v] to a freshly migrated database gives one that looks like a
// database last opened by a SIEMLite that knew schema v.
//
// Versions 0, 1 and 2 cannot be told apart from 3: migrate treats any
// user_version below 3 as the base schema (schemaStatements are written
// idempotently and match version 3), and the repository holds no older DDL.
// So v = 0, 1, 2 and 3 all start from the same base schema, which is the
// oldest shape this code can reproduce.
var downgrades = map[int][]string{
	23: {
		`CREATE TABLE alert_rules_old (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL UNIQUE COLLATE NOCASE,
			description    TEXT NOT NULL DEFAULT '',
			enabled        INTEGER NOT NULL DEFAULT 1,
			severity       INTEGER NOT NULL,
			query          TEXT NOT NULL DEFAULT '',
			min_severity   INTEGER,
			threat_only    INTEGER NOT NULL DEFAULT 0,
			source_id      INTEGER REFERENCES sources(id) ON DELETE SET NULL,
			group_by       TEXT NOT NULL DEFAULT '' CHECK (group_by IN ('', 'src_ip', 'dst_ip', 'user', 'host')),
			threshold      INTEGER NOT NULL CHECK (threshold >= 1),
			window_minutes INTEGER NOT NULL CHECK (window_minutes >= 1),
			builtin        INTEGER NOT NULL DEFAULT 0,
			created_at     INTEGER NOT NULL,
			updated_at     INTEGER NOT NULL,
			kind           TEXT NOT NULL DEFAULT 'match' CHECK (kind IN ('match', 'volume_over', 'volume_under'))
		)`,
		`INSERT INTO alert_rules_old SELECT * FROM alert_rules WHERE group_by <> 'source'`,
		`DROP TABLE alert_rules`,
		`ALTER TABLE alert_rules_old RENAME TO alert_rules`,
	},
	22: {`DROP TABLE report_runs`, `DROP TABLE report_schedules`},
	21: {`ALTER TABLE alerts DROP COLUMN closed_seq`},
	20: {`DROP TABLE friendly_entries`, `DROP TABLE friendly_lists`},
	19: {`DROP TABLE rule_proposals`},
	18: {`ALTER TABLE alerts DROP COLUMN note`},
	17: {
		`UPDATE alert_rules SET query = '"mass ingestion"' WHERE builtin = 1 AND name = 'Mass ingestion of late logs'`,
		`UPDATE alert_rules SET query = '"sign-in failed"' WHERE builtin = 1 AND name = 'Failed sign-ins to SIEMLite'`,
	},
	16: {`DROP TABLE agent_tokens`},
	15: {`ALTER TABLE alert_rules DROP COLUMN kind`},
	14: {`DELETE FROM alert_rules WHERE name = 'Mass ingestion of late logs'`},
	13: {`ALTER TABLE users DROP COLUMN display_name`},
	12: {
		`DROP INDEX idx_users_external`,
		`ALTER TABLE users DROP COLUMN auth_provider`,
		`ALTER TABLE users DROP COLUMN external_id`,
		`ALTER TABLE users DROP COLUMN disabled`,
	},
	11: {`ALTER TABLE sources DROP COLUMN parser_none`},
	10: {`DELETE FROM settings WHERE key IN ('event_seq', 'legacy_moved_through')`},
	9: {
		`DROP INDEX idx_events_src_ip`, `DROP INDEX idx_events_dst_ip`,
		`DROP INDEX idx_events_user`, `DROP INDEX idx_events_host`,
	},
	8: {`DROP TABLE alerts`, `DROP TABLE alert_rules`, `DELETE FROM sources WHERE kind = 'internal'`},
	7: {`DROP TABLE settings`},
	6: {`ALTER TABLE users DROP COLUMN limited`},
	5: {
		`DROP TABLE user_sources`,
		`DROP INDEX idx_events_source`,
		`ALTER TABLE events DROP COLUMN source_id`,
		`ALTER TABLE events DROP COLUMN fields`,
		`DROP TABLE sources`,
		`DROP TABLE parsers`,
		`CREATE TABLE users_old (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')), created_at INTEGER NOT NULL)`,
		`INSERT INTO users_old (id, username, password_hash, role, created_at)
			SELECT id, username, password_hash, CASE role WHEN 'standard' THEN 'analyst' ELSE role END, created_at FROM users`,
		`DROP TABLE users`,
		`ALTER TABLE users_old RENAME TO users`,
		`CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL, revoked_at INTEGER)`,
	},
	4: {`DROP INDEX idx_events_sample`, `ALTER TABLE events DROP COLUMN sample`},
	3: {
		`DROP INDEX idx_events_threat`,
		`ALTER TABLE events DROP COLUMN source`, `ALTER TABLE events DROP COLUMN host`,
		`ALTER TABLE events DROP COLUMN src_country`, `ALTER TABLE events DROP COLUMN dst_country`,
		`ALTER TABLE events DROP COLUMN src_asn`, `ALTER TABLE events DROP COLUMN dst_asn`,
		`ALTER TABLE events DROP COLUMN threat`, `ALTER TABLE events DROP COLUMN enrichment`,
	},
}

// A database last written at every schema version from 0 to schemaVersion-1
// opens, migrates to the current version, keeps its rows, and a second open
// changes nothing.
func TestUpgradeFromEveryVersion(t *testing.T) {
	if len(downgrades) != schemaVersion-3 { // versions 3 to schemaVersion-1: a new upgrade needs its downgrade here
		t.Fatalf("downgrades covers %d versions but schemaVersion is %d: add the downgrade for the new upgrade", len(downgrades), schemaVersion)
	}
	for v := 0; v < schemaVersion; v++ {
		t.Run(fmt.Sprintf("from_v%d", v), func(t *testing.T) { upgradeFrom(t, v) })
	}
}

func upgradeFrom(t *testing.T, v int) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "siemlite.db")
	const ts = 1_793_000_000_000 // late October 2026

	// 1. A current database holding one of everything.
	db, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewRepository(db)
	if _, err := repo.CreateUser(ctx, "root", "x", "admin", ts); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateUser(ctx, "alice", "x", "standard", ts); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateTokenSource(ctx, "web-app", "hash-web", nil, false, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRule(ctx, Rule{Name: "custom rule", Enabled: true, Severity: 3, Query: "needle",
		GroupBy: "src_ip", Threshold: 3, WindowMinutes: 10}, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddIndicators(ctx, []Indicator{{Type: "ip", Value: "203.0.113.9", Source: "test", Description: "bad"}}, ts); err != nil {
		t.Fatal(err)
	}
	if v >= 11 { // events live in day files from schema 11 on, apart from the main database
		if err := repo.InsertBatch(ctx, []Record{{Timestamp: ts, CategoryUID: 4, ClassUID: 4001, SeverityID: 3,
			SrcIP: "203.0.113.9", RawData: "needle in a day file"}}); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	// 2. Rewind the main database to schema v. Foreign keys stay off while
	// tables are dropped and rebuilt, as migrate does.
	raw, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := raw.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(stmt string) {
		t.Helper()
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec(`PRAGMA foreign_keys = OFF`)
	for k := schemaVersion - 1; k >= max(v, 3); k-- {
		for _, stmt := range downgrades[k] {
			exec(stmt)
		}
	}
	if v < 6 { // before sources existed, tokens were API keys
		exec(`INSERT INTO api_keys (id, name, role, key_hash, created_at) VALUES (7, 'web-app', 'write', 'hash-web', 1)`)
	}
	if v < 11 { // before day files, events were in the main database
		exec(fmt.Sprintf(`INSERT INTO events (timestamp, category_uid, class_uid, severity_id, src_ip, raw_data)
			VALUES (%d, 4, 4001, 3, '203.0.113.9', 'needle in the main database')`, ts))
	}
	exec(fmt.Sprintf(`PRAGMA user_version = %d`, v))
	conn.Close()
	raw.Close()

	// 3. Migrate, and check what survived.
	snapshot := func() (version int, objects []string, counts map[string]int) {
		t.Helper()
		db, err := Open(ctx, Options{Path: path})
		if err != nil {
			t.Fatalf("open at schema %d: %v", v, err)
		}
		defer db.Close()
		repo := NewRepository(db)
		if err := db.Write.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Write.Query(`SELECT type || ' ' || name FROM sqlite_master ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			rows.Scan(&s)
			objects = append(objects, s)
		}
		rows.Close()
		counts = map[string]int{}
		for _, tbl := range []string{"users", "sources", "alert_rules", "indicators", "settings", "friendly_lists", "agent_tokens"} {
			var n int
			if err := db.Write.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", tbl, err)
			}
			counts[tbl] = n
		}
		found, err := repo.Search(ctx, Filter{Match: "needle", Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		counts["events found"] = len(found)

		if users, _ := repo.ListUsers(ctx); len(users) != 2 || users[0].Username != "root" || users[1].Username != "alice" || users[1].Role != "standard" {
			t.Errorf("users = %+v", users)
		}
		if tok, err := repo.FindActiveToken(ctx, "hash-web"); err != nil || tok.Name != "web-app" {
			t.Errorf("token source = %+v, %v", tok, err)
		}
		if inds, err := repo.AllIndicators(ctx); err != nil || len(inds) != 1 || inds[0].Value != "203.0.113.9" {
			t.Errorf("indicators = %+v, %v", inds, err)
		}
		rules, err := repo.ListRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		has := func(name string) bool {
			return slices.ContainsFunc(rules, func(r Rule) bool { return r.Name == name })
		}
		if !has("SSH brute force") {
			t.Error("built-in rules missing")
		}
		if v >= 9 && !has("custom rule") { // before 9 there were no rules to keep
			t.Error("custom alert rule lost")
		}
		for _, r := range rules {
			if r.Kind == "" {
				t.Errorf("rule %q has no kind", r.Name)
			}
		}
		return version, objects, counts
	}
	ver1, objs1, counts1 := snapshot()
	if ver1 != schemaVersion {
		t.Fatalf("user_version = %d, want %d", ver1, schemaVersion)
	}
	if counts1["events found"] != 1 {
		t.Errorf("events found = %d, want 1", counts1["events found"])
	}
	for _, o := range []string{"table friendly_lists", "table agent_tokens", "table rule_proposals", "table events_fts", "index idx_events_threat"} {
		if !slices.Contains(objs1, o) {
			t.Errorf("after migrating, missing %s", o)
		}
	}

	// 4. A second open is a no-op.
	ver2, objs2, counts2 := snapshot()
	if ver2 != schemaVersion || !slices.Equal(objs1, objs2) || !reflect.DeepEqual(counts1, counts2) {
		t.Errorf("second open changed the database:\n objects %v\n vs      %v\n counts %v vs %v", objs1, objs2, counts1, counts2)
	}
}
