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
