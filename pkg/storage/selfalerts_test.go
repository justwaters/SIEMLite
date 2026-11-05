package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// SIEMLite's own audit events about alerts are never counted by a rule, whatever
// its search says, while the same words from an outside log still are.
func TestRulesSkipSIEMLitesOwnAlertEvents(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	internal, err := repo.BuiltinSource(ctx, SourceInternal)
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateTokenSource(ctx, "app", "k", nil, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	rec := func(i int, src int64, msg, action string) Record {
		r := Record{Timestamp: now - int64(i)*1000, CategoryUID: 6, ClassUID: 6003, SeverityID: 1, Message: msg, RawData: msg, SourceID: src}
		if action != "" {
			r.Fields = json.RawMessage(`{"action":"` + action + `"}`)
		}
		return r
	}
	if err := repo.InsertBatch(ctx, []Record{
		rec(0, internal.ID, "Mass ingestion of late logs: 481 events", "ingest.late"),
		rec(1, internal.ID, "JD Waters acknowledged the alert Mass ingestion of late logs", "alert.acknowledged"),
		rec(2, internal.ID, "JD Waters closed the alert Mass ingestion of late logs", "alert.closed"),
		rec(3, internal.ID, "JD Waters reopened the alert Mass ingestion of late logs", "alert.open"),
		rec(4, internal.ID, "SIEMLite will add alerts of its own: a future action", "alert.escalated"),
		rec(5, internal.ID, "JD Waters updated the alert rule Mass ingestion of late logs", "rule.save"),
		rec(6, other, "an outside app says mass ingestion of late logs", "alert.created"), // not SIEMLite's: it counts
		rec(7, internal.ID, "an audit event with no fields about mass ingestion", ""),     // no action: it counts
	}); err != nil {
		t.Fatal(err)
	}
	seq, _ := repo.MaxEventSeq(ctx)
	matches := func(ru Rule) int64 {
		t.Helper()
		groups, err := repo.NewMatches(ctx, ru, 0, seq)
		if err != nil {
			t.Fatal(err)
		}
		var n int64
		for _, g := range groups {
			n += g.New
		}
		return n
	}
	// A phrase that is in the alert's name: none of the alert.* events count. The real ingest.late event, the rule.save audit
	// event (the rule is not an alert), the outside log and the audit event with no action do.
	if n := matches(Rule{Name: "phrase", Query: `"mass ingestion"`, Threshold: 1, WindowMinutes: 5}); n != 4 {
		t.Errorf("a phrase rule counted %d events, want 4", n)
	}
	if n := matches(Rule{Name: "words", Query: `late AND logs`, Threshold: 1, WindowMinutes: 5}); n != 3 {
		t.Errorf("a words rule counted %d, want 3", n)
	}
	// A field term matches by what the event is.
	byAction := Rule{Name: "by action", Conds: []Cond{{Field: "action", Values: []string{"ingest.late"}}}, Threshold: 1, WindowMinutes: 5}
	if n := matches(byAction); n != 1 {
		t.Errorf("action=ingest.late counted %d, want 1", n)
	}
	// Even a rule that asks for alert.closed by name sees none of them.
	if n := matches(Rule{Name: "ask", Conds: []Cond{{Field: "action", Values: []string{"alert.closed", "alert.open"}}}, Threshold: 1, WindowMinutes: 5}); n != 0 {
		t.Errorf("a rule asking for alert.* counted %d, want 0", n)
	}
	// ... but the outside app's event, whose action also starts with alert., does.
	if n := matches(Rule{Name: "outside", Conds: []Cond{{Field: "action", Values: []string{"alert.created"}}}, Threshold: 1, WindowMinutes: 5}); n != 1 {
		t.Errorf("an outside log's alert.created counted %d, want 1", n)
	}
	// Counting for an alert's span uses the same rule, so the audit events don't come back that way.
	got, err := repo.CountRuleEvents(ctx, byAction, "", now-60_000, now)
	if err != nil || got != 1 {
		t.Errorf("CountRuleEvents = %d, %v; want 1", got, err)
	}
	got, err = repo.CountRuleEvents(ctx, Rule{Name: "p", Query: `"mass ingestion"`}, "", now-3500, now-1500)
	if err != nil || got != 0 {
		t.Errorf("CountRuleEvents over only alert.acknowledged and alert.closed = %d, %v; want 0", got, err)
	}
}

// The two built-in rules that read SIEMLite's audit log are re-worded to match the
// action, on installs that have them as shipped; an admin's own wording is kept.
func TestUpgradeToV18RewordsTheBuiltInRules(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v17.db")
	db, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	query := func(name string) string {
		var q string
		if err := db.Read.QueryRow(`SELECT query FROM alert_rules WHERE name = ?`, name).Scan(&q); err != nil {
			t.Fatal(name, err)
		}
		return q
	}
	// A new database starts on the new wording.
	if got := query("Mass ingestion of late logs"); got != "action=ingest.late" {
		t.Errorf("rule 5 on a new database = %q", got)
	}
	if got := query("Failed sign-ins to SIEMLite"); got != "action=signin.failed" {
		t.Errorf("rule 4 on a new database = %q", got)
	}
	// An install from before: both as shipped, plus a custom rule worded the old way.
	for _, stmt := range []string{
		`UPDATE alert_rules SET query = '"mass ingestion"' WHERE name = 'Mass ingestion of late logs'`,
		`UPDATE alert_rules SET query = '"sign-in failed"' WHERE name = 'Failed sign-ins to SIEMLite'`,
		`INSERT INTO alert_rules (name, severity, query, threshold, window_minutes, builtin, created_at, updated_at) VALUES ('My own', 3, '"mass ingestion"', 1, 5, 0, 1, 1)`,
		`PRAGMA user_version = 17`,
	} {
		if _, err := db.Write.Exec(stmt); err != nil {
			t.Fatal(stmt, err)
		}
	}
	db.Close()
	if db, err = Open(ctx, Options{Path: path}); err != nil {
		t.Fatal(err)
	}
	if got := query("Mass ingestion of late logs"); got != "action=ingest.late" {
		t.Errorf("rule 5 after the upgrade = %q", got)
	}
	if got := query("Failed sign-ins to SIEMLite"); got != "action=signin.failed" {
		t.Errorf("rule 4 after the upgrade = %q", got)
	}
	if got := query("My own"); got != `"mass ingestion"` {
		t.Errorf("a custom rule was changed: %q", got)
	}
	// An admin who edited a built-in rule keeps their wording.
	if _, err := db.Write.Exec(`UPDATE alert_rules SET query = '"sign-in failed" AND admin' WHERE name = 'Failed sign-ins to SIEMLite'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Write.Exec(`PRAGMA user_version = 17`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err = Open(ctx, Options{Path: path}); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := query("Failed sign-ins to SIEMLite"); got != `"sign-in failed" AND admin` {
		t.Errorf("an edited built-in rule was changed: %q", got)
	}
}
