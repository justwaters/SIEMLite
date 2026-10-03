package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// A database created by v0.2 (schema 3) gains the enrichment columns and
// keeps its events.
func TestUpgradeFromV3(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
			category_uid INTEGER NOT NULL, class_uid INTEGER NOT NULL, severity_id INTEGER NOT NULL,
			src_ip TEXT, dst_ip TEXT, user_name TEXT, raw_data TEXT NOT NULL)`,
		`INSERT INTO events (timestamp, category_uid, class_uid, severity_id, raw_data) VALUES (1, 6, 6003, 1, 'old event')`,
		`PRAGMA user_version = 3`,
	} {
		if _, err := old.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	for range 2 { // the second open must be a no-op
		db, err := Open(ctx, Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		repo := NewRepository(db)
		if err := repo.InsertBatch(ctx, []Record{{Timestamp: 2, CategoryUID: 4, ClassUID: 4001, SeverityID: 4,
			RawData: "new", SrcCountry: "NL", Threat: true, Enrichment: []byte(`{"threat_intel":[]}`)}}); err != nil {
			t.Fatal(err)
		}
		recs, err := repo.Search(ctx, Filter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if recs[len(recs)-1].RawData != "old event" {
			t.Errorf("old event lost: %+v", recs)
		}
		threats, err := repo.Search(ctx, Filter{Limit: 10, ThreatOnly: true, Country: "NL"})
		if err != nil || len(threats) == 0 || string(threats[0].Enrichment) != `{"threat_intel":[]}` {
			t.Errorf("threat search = %+v, %v", threats, err)
		}
		db.Close()
	}
}

// A v0.4 database (schema 5) keeps its API keys as token sources, its
// analysts become standard users, and the built-in sources appear.
func TestUpgradeToV6(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v5.db")
	old, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
			category_uid INTEGER NOT NULL, class_uid INTEGER NOT NULL, severity_id INTEGER NOT NULL,
			src_ip TEXT, dst_ip TEXT, user_name TEXT, raw_data TEXT NOT NULL, source TEXT, host TEXT,
			src_country TEXT, dst_country TEXT, src_asn INTEGER, dst_asn INTEGER,
			threat INTEGER NOT NULL DEFAULT 0, enrichment TEXT, sample INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL, revoked_at INTEGER)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')), created_at INTEGER NOT NULL)`,
		`CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
		`INSERT INTO api_keys (id, name, role, key_hash, created_at) VALUES (7, 'myapp', 'write', 'hash-myapp', 1)`,
		`INSERT INTO api_keys (id, name, role, key_hash, created_at) VALUES (8, 'old-reader', 'read', 'hash-read', 1)`,
		`INSERT INTO users (username, password_hash, role, created_at) VALUES ('root', 'x', 'admin', 1), ('alice', 'x', 'analyst', 1)`,
		`INSERT INTO events (timestamp, category_uid, class_uid, severity_id, raw_data, sample) VALUES (1, 6, 6003, 1, 'demo', 1)`,
		`PRAGMA user_version = 5`,
	} {
		if _, err := old.Exec(stmt); err != nil {
			t.Fatal(stmt, err)
		}
	}
	old.Close()

	db, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)

	tok, err := repo.FindActiveToken(ctx, "hash-myapp")
	if err != nil || tok.ID != 7 || tok.Name != "myapp" {
		t.Fatalf("token source = %+v, %v", tok, err)
	}
	if _, err := repo.FindActiveToken(ctx, "hash-read"); err == nil {
		t.Error("v0.1 read key should stay revoked")
	}
	users, _ := repo.ListUsers(ctx)
	if len(users) != 2 || users[0].Role != "admin" || users[1].Role != "standard" {
		t.Errorf("users = %+v", users)
	}
	for _, kind := range []string{SourceSyslog, SourceUpload, SourceSample} {
		if _, err := repo.BuiltinSource(ctx, kind); err != nil {
			t.Errorf("built-in %s source: %v", kind, err)
		}
	}
	sample, _ := repo.BuiltinSource(ctx, SourceSample)
	recs, _ := repo.Search(ctx, Filter{Limit: 5})
	if len(recs) != 1 || recs[0].SourceID != sample.ID || recs[0].SourceName != "Sample data" {
		t.Errorf("sample event source = %+v", recs)
	}
	// A restricted view with no allowed sources sees nothing; with the
	// sample source it sees the event.
	if recs, _ := repo.Search(ctx, Filter{Limit: 5, Restrict: true}); len(recs) != 0 {
		t.Errorf("empty restriction returned %d events", len(recs))
	}
	if recs, _ := repo.Search(ctx, Filter{Limit: 5, Restrict: true, AllowedSources: []int64{sample.ID}}); len(recs) != 1 {
		t.Errorf("restricted to sample returned %d events", len(recs))
	}
	if err := repo.UpdateUserAccess(ctx, users[0].ID, "standard", nil); err != ErrLastAdmin {
		t.Errorf("demoting the last admin: %v", err)
	}
}
