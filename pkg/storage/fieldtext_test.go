package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestFieldsText(t *testing.T) {
	for in, want := range map[string]string{
		``:                                   "",
		`not json`:                           "",
		`{}`:                                 "",
		`{"meta.failed":"[]"}`:               "[]",
		`{"a":"x y","b":3,"c":true}`:         "x y 3",
		`{"b":"two","a":"one"}`:              "one two",
		`{"list":["p","q"],"o":{"k":"v"}}`:   "p q v",
		`{"n":1782,"f":1.5,"z":null,"e":""}`: "1.5 1782",
	} {
		if got := fieldsText(json.RawMessage(in)); got != want {
			t.Errorf("fieldsText(%q) = %q, want %q", in, got, want)
		}
	}
}

// Searching for a word finds events that have it in a value, not events that
// have a field named after it, whether the event was stored now or in a day
// file made before fields were indexed this way.
func TestSearchIgnoresFieldNames(t *testing.T) {
	ctx := context.Background()
	db, repo := openTemp(t)
	now := time.Now().UnixMilli()
	fields := json.RawMessage(`{"meta.failed":"[]","meta.users":"[\"Jonathan Martinez\"]","action":"digest"}`)
	if err := repo.InsertBatch(ctx, []Record{
		{Timestamp: now, CategoryUID: 3, ClassUID: 3002, SeverityID: 1, Message: "Emailed digest to 1 user(s)", RawData: "x", Fields: fields},
		{Timestamp: now - 1000, CategoryUID: 3, ClassUID: 3002, SeverityID: 3, Message: "Login failed for bob", RawData: "y"},
	}); err != nil {
		t.Fatal(err)
	}
	count := func(r *Repository, match string) int {
		t.Helper()
		got, err := r.Search(ctx, Filter{Match: match, Limit: 50})
		if err != nil {
			t.Fatalf("search %q: %v", match, err)
		}
		return len(got)
	}
	check := func(r *Repository, when string) {
		t.Helper()
		if n := count(r, "failed"); n != 1 {
			t.Errorf("%s: failed matched %d events, want 1 (only the one that says it)", when, n)
		}
		if n := count(r, "jonathan"); n != 1 {
			t.Errorf("%s: a value in a field wasn't found (%d)", when, n)
		}
		if n := count(r, "digest"); n != 1 {
			t.Errorf("%s: digest matched %d, want 1", when, n)
		}
	}
	check(repo, "a new event")

	// Put the day file back as version 3 made it: the index covers `fields` itself.
	path := db.Path()
	days := db.Days()
	db.Close()
	for _, d := range days {
		day, err := sql.Open("sqlite", dayDSN(filepath.Join(EventsDir(path), d+".db"), false))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`DROP TRIGGER events_ad`, `DROP TABLE events_fts`,
			`CREATE VIRTUAL TABLE events_fts USING fts5(message, source, host, user_name, src_ip, dst_ip, fields, content='events', content_rowid='id')`,
			`CREATE TRIGGER events_ad AFTER DELETE ON events BEGIN
				INSERT INTO events_fts(events_fts, rowid, message, source, host, user_name, src_ip, dst_ip, fields) VALUES ('delete', old.id, old.message, old.source, old.host, old.user_name, old.src_ip, old.dst_ip, old.fields); END`,
			`INSERT INTO events_fts(events_fts) VALUES ('rebuild')`,
			`ALTER TABLE events DROP COLUMN fields_text`, `PRAGMA user_version = 3`,
		} {
			if _, err := day.Exec(stmt); err != nil {
				t.Fatalf("%.50s: %v", stmt, err)
			}
		}
		var n int
		if err := day.QueryRow(`SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'failed'`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("the version 3 index should match the field's name too: %d %v", n, err)
		}
		day.Close()
	}
	// Opening it upgrades the day file, and the name stops matching.
	db2, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	check(NewRepository(db2), "after upgrading a version 3 day file")
}

// The text the index holds for a day written now is the text the upgrade makes
// for an older day: the same values in the same order.
func TestFieldsTextMatchesTheUpgrade(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, doc := range []string{
		`{"action":"digest","id":1782,"meta.failed":"[]","meta.users":"[\"Jonathan Martinez\",\"Ann B\"]"}`,
		`{"b":"two","a":"one","c":"three"}`,
		`{"z":1.5,"y":"last","x":"first"}`,
		`{"only":"one"}`,
	} {
		// Events store their fields as Go writes a map: keys in order.
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		stored, _ := json.Marshal(m)
		var viaSQL sql.NullString
		if err := db.QueryRow(`SELECT group_concat(value, ' ') FROM json_tree(?) WHERE type IN ('text', 'integer', 'real')`, string(stored)).Scan(&viaSQL); err != nil {
			t.Fatal(err)
		}
		if got := fieldsText(stored); got != viaSQL.String {
			t.Errorf("fieldsText(%s) = %q, the upgrade makes %q", stored, got, viaSQL.String)
		}
	}
}

// A field name that isn't one a parser could have made is not a way into the
// query: it matches nothing, and nothing is harmed.
func TestOddFieldNamesMatchNothing(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	now := time.Now().UnixMilli()
	if err := repo.InsertBatch(ctx, []Record{{Timestamp: now, CategoryUID: 3, ClassUID: 3002, SeverityID: 1, Message: "hello", RawData: "x",
		Fields: json.RawMessage(`{"action":"digest"}`)}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`a"); DROP TABLE events; --`, `x" OR 1=1 --`, `$.action`, `a b`, ``, `1abc`, "a\nb"} {
		got, err := repo.Search(ctx, Filter{Conds: []Cond{{Field: name, Values: []string{"digest", `' OR '1'='1`}}}, Limit: 10})
		if err != nil || len(got) != 0 {
			t.Errorf("field %q: %d events, %v; want none and no error", name, len(got), err)
		}
	}
	if got, err := repo.Search(ctx, Filter{Conds: []Cond{{Field: "action", Values: []string{"digest"}}}, Limit: 10}); err != nil || len(got) != 1 {
		t.Errorf("a real field after all that: %d events, %v", len(got), err)
	}
}
