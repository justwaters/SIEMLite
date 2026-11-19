package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

const day = 24 * time.Hour

// populate fills e with events on five different days, plus users, alert
// rules, a manual alert, threat indicators and a friendly list.
func populate(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	var recs []storage.Record
	for d := range 5 {
		for i := range 20 {
			at := base.Add(time.Duration(d)*day + time.Duration(i)*time.Minute)
			recs = append(recs, storage.Record{
				Timestamp: at.UnixMilli(), CategoryUID: 4, ClassUID: 4001, SeverityID: 1 + i%5,
				SrcIP: fmt.Sprintf("198.51.100.%d", d+1), DstIP: "10.0.0.5", UserName: "alice",
				Message: fmt.Sprintf("backupneedle day%d number%d", d, i), RawData: fmt.Sprintf("raw line day%d number%d", d, i),
				Host: "fw-1", Source: "sshd", Threat: d == 2 && i == 3,
			})
		}
	}
	if err := e.repo.InsertBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.CreateUser(ctx, "root", "hash-root", "admin", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.CreateUser(ctx, "bob", "hash-bob", "standard", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.SaveRule(ctx, storage.Rule{Name: "backup rule", Enabled: true, Severity: 4, Query: "backupneedle",
		GroupBy: "src_ip", Threshold: 5, WindowMinutes: 30}, 3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.repo.RaiseManualAlert(ctx, storage.Alert{RuleName: "Manual finding", Severity: 4, GroupBy: "src_ip",
		GroupValue: "198.51.100.1", Note: "looked odd"}, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.AddIndicators(ctx, []storage.Indicator{
		{Type: "ip", Value: "198.51.100.3", Source: "feed", Description: "scanner"},
		{Type: "domain", Value: "evil.example", Source: "feed"},
	}, 5); err != nil {
		t.Fatal(err)
	}
	id, err := e.repo.CreateFriendlyList(ctx, "office", "our ranges", 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.AddFriendlyEntries(ctx, id, []string{"192.0.2.0/24", "192.0.2.77"}, "hq", 7); err != nil {
		t.Fatal(err)
	}
}

// checkPopulated asserts everything populate stored is present and searchable.
func checkPopulated(t *testing.T, e *env) {
	t.Helper()
	ctx := context.Background()
	if days := e.db.Days(); len(days) != 5 {
		t.Errorf("day files = %v, want 5", days)
	}
	all, err := e.repo.Search(ctx, storage.Filter{Limit: 1000})
	if err != nil || len(all) != 100 {
		t.Fatalf("events = %d, %v; want 100", len(all), err)
	}
	if n, err := e.db.CountEvents(ctx, "1=1"); err != nil || n != 100 {
		t.Errorf("count = %d, %v", n, err)
	}
	// Full-text, a field, a severity, a threat and a time-range search.
	if r, _ := e.repo.Search(ctx, storage.Filter{Match: "backupneedle", Limit: 1000}); len(r) != 100 {
		t.Errorf("full-text search found %d", len(r))
	}
	if r, _ := e.repo.Search(ctx, storage.Filter{Match: `"day3 number7"`, Limit: 10}); len(r) != 1 || r[0].RawData != "raw line day3 number7" {
		t.Errorf("phrase search = %+v", r)
	}
	if r, _ := e.repo.Search(ctx, storage.Filter{Conds: []storage.Cond{{Field: "src_ip", Values: []string{"198.51.100.2"}}}, Limit: 1000}); len(r) != 20 {
		t.Errorf("src_ip search found %d, want 20", len(r))
	}
	if r, _ := e.repo.Search(ctx, storage.Filter{Conds: []storage.Cond{{Field: "severity", Values: []string{"5"}}}, Limit: 1000}); len(r) != 20 {
		t.Errorf("severity search found %d, want 20", len(r))
	}
	if r, _ := e.repo.Search(ctx, storage.Filter{ThreatOnly: true, Limit: 10}); len(r) != 1 || r[0].Message != "backupneedle day2 number3" {
		t.Errorf("threat search = %+v", r)
	}
	from := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).UnixMilli()
	if r, _ := e.repo.Search(ctx, storage.Filter{StartMs: from, EndMs: from + 2*int64(day/time.Millisecond) - 1, Limit: 1000}); len(r) != 40 {
		t.Errorf("two-day range found %d, want 40", len(r))
	}

	users, err := e.repo.ListUsers(ctx)
	if err != nil || len(users) != 2 || users[0].Username != "root" || users[1].Username != "bob" || users[1].Role != "standard" {
		t.Errorf("users = %+v, %v", users, err)
	}
	rules, err := e.repo.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rules {
		if r.Name == "backup rule" && r.Threshold == 5 && r.GroupBy == "src_ip" {
			found = true
		}
	}
	if !found {
		t.Errorf("alert rule missing from %d rules", len(rules))
	}
	if alerts, _, err := e.repo.ListAlerts(ctx, "", 50); err != nil || len(alerts) != 1 || alerts[0].RuleName != "Manual finding" || alerts[0].Note != "looked odd" {
		t.Errorf("alerts = %+v, %v", alerts, err)
	}
	if inds, err := e.repo.AllIndicators(ctx); err != nil || len(inds) != 2 {
		t.Errorf("indicators = %+v, %v", inds, err)
	}
	lists, err := e.repo.FriendlyLists(ctx)
	if err != nil || len(lists) != 1 || lists[0].Name != "office" || len(lists[0].Entries) != 2 {
		t.Errorf("friendly lists = %+v, %v", lists, err)
	}
	if vals, _ := e.repo.FriendlyValues(ctx); len(vals) != 2 {
		t.Errorf("friendly values = %v", vals)
	}
	var v int
	if err := e.db.Write.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v < 21 {
		t.Errorf("user_version = %d, %v", v, err)
	}
}

// restoreInto copies the backup into a brand new data folder's backups,
// stages the restore there, applies it as the next start would, and opens it.
func restoreInto(t *testing.T, from *env, b Backup) *env {
	t.Helper()
	ctx := context.Background()
	fresh := newEnv(t)
	fresh.db.Close() // an empty installation, not yet in use
	fresh.open()
	f, err := from.m.Open(b.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	up, err := fresh.m.Upload(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.m.StageRestore(ctx, up.Name); err != nil {
		t.Fatal(err)
	}
	fresh.db.Close()
	applied, err := ApplyPendingRestore(fresh.path, nil)
	if err != nil || applied == nil {
		t.Fatalf("apply = %+v, %v", applied, err)
	}
	fresh.open()
	return fresh
}

// A backup of a database with events over several days, alerts, rules, users,
// indicators and friendly lists restores into a fresh data folder with
// everything present and searchable.
func TestRestoreIntoFreshDataFolder(t *testing.T) {
	src := newEnv(t)
	populate(t, src)
	checkPopulated(t, src) // the source itself is as the checks expect
	b, err := src.m.Create(context.Background(), Manual)
	if err != nil {
		t.Fatal(err)
	}
	src.db.Close()

	dst := restoreInto(t, src, b)
	defer dst.db.Close()
	if dst.dir == src.dir {
		t.Fatal("restored into the source folder")
	}
	checkPopulated(t, dst)
}

// oldSnapshotter takes the real snapshot and then turns its main database
// into one last written at schema 15: it drops what later upgrades added
// and lowers user_version, so restoring it has to migrate forward.
type oldSnapshotter struct{ *storage.DB }

func (o oldSnapshotter) SnapshotTo(ctx context.Context, dir string) error {
	if err := o.DB.SnapshotTo(ctx, dir); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, storage.MainFile))
	if err != nil {
		return err
	}
	defer db.Close()
	for _, stmt := range []string{
		`DROP TABLE friendly_entries`, `DROP TABLE friendly_lists`, // v21
		`ALTER TABLE alerts DROP COLUMN closed_seq`, // v22
		`DROP TABLE rule_proposals`,                 // v20
		`ALTER TABLE alerts DROP COLUMN note`,       // v19
		`DROP TABLE agent_tokens`,                   // v17
		`ALTER TABLE alert_rules DROP COLUMN kind`,  // v16
		`PRAGMA user_version = 15`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// A backup made by an older SIEMLite (older schema) restores and the normal
// start-up migration brings it forward without losing anything.
func TestRestoreOlderSchemaMigratesForward(t *testing.T) {
	ctx := context.Background()
	src := newEnv(t)
	populate(t, src)
	// Friendly lists and the alert note only exist from schema 20/19 on, so
	// the old backup cannot hold them: check them separately below.
	old, err := New(filepath.Join(src.dir, "oldbackups"), oldSnapshotter{src.db}, src.repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.Create(ctx, Manual)
	if err != nil {
		t.Fatal(err)
	}
	src.db.Close()

	// The backup file really holds an old database.
	check := filepath.Join(t.TempDir(), "unpacked")
	if err := unpack(ctx, filepath.Join(old.Dir(), b.Name), check); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(check, storage.MainFile))
	if err != nil {
		t.Fatal(err)
	}
	var v int
	raw.QueryRow(`PRAGMA user_version`).Scan(&v)
	raw.Close()
	if v != 15 {
		t.Fatalf("backup's schema = %d, want 15", v)
	}

	fresh := newEnv(t)
	fresh.db.Close()
	fresh.open()
	f, err := os.Open(filepath.Join(old.Dir(), b.Name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	up, err := fresh.m.Upload(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.m.StageRestore(ctx, up.Name); err != nil {
		t.Fatal(err)
	}
	fresh.db.Close()
	if applied, err := ApplyPendingRestore(fresh.path, nil); err != nil || applied == nil {
		t.Fatalf("apply = %+v, %v", applied, err)
	}
	fresh.open() // migrates
	defer fresh.db.Close()

	if err := fresh.db.Write.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v < 22 {
		t.Fatalf("user_version after open = %d, %v", v, err)
	}
	if all, err := fresh.repo.Search(ctx, storage.Filter{Match: "backupneedle", Limit: 1000}); err != nil || len(all) != 100 {
		t.Errorf("events after migrating = %d, %v", len(all), err)
	}
	if days := fresh.db.Days(); len(days) != 5 {
		t.Errorf("day files = %v", days)
	}
	if users, _ := fresh.repo.ListUsers(ctx); len(users) != 2 {
		t.Errorf("users = %+v", users)
	}
	rules, _ := fresh.repo.ListRules(ctx)
	var kept bool
	for _, r := range rules {
		if r.Name == "backup rule" && r.Kind == storage.RuleMatch {
			kept = true
		}
	}
	if !kept {
		t.Errorf("alert rule lost or without a kind: %+v", rules)
	}
	if alerts, _, err := fresh.repo.ListAlerts(ctx, "", 50); err != nil || len(alerts) != 1 || alerts[0].RuleName != "Manual finding" {
		t.Errorf("alerts = %+v, %v", alerts, err)
	}
	if inds, _ := fresh.repo.AllIndicators(ctx); len(inds) != 2 {
		t.Errorf("indicators = %+v", inds)
	}
	// The tables added since the backup's schema exist and work.
	if _, err := fresh.repo.CreateFriendlyList(ctx, "new list", "", 1); err != nil {
		t.Errorf("friendly lists after migrating: %v", err)
	}
}

// A truncated or damaged backup is refused, at upload and at restore, and the
// live database and its day files are untouched.
func TestCorruptBackupRejectedLiveDataUntouched(t *testing.T) {
	ctx := context.Background()
	live := newEnv(t)
	populate(t, live)
	good, err := live.m.Create(ctx, Manual)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(live.m.Dir(), good.Name))
	if err != nil {
		t.Fatal(err)
	}
	damaged := map[string][]byte{
		"truncated in half":    data[:len(data)/2],
		"truncated to a few":   data[:20],
		"empty":                {},
		"bytes flipped inside": append(append(append([]byte{}, data[:len(data)/2]...), make([]byte, 64)...), data[len(data)/2+64:]...),
		"not a backup":         []byte("this is not a backup at all"),
	}
	n := 0
	for what, bad := range damaged {
		n++
		name := fmt.Sprintf("siemlite-20261002-00000%d-manual.tar.gz", n)
		if err := os.WriteFile(filepath.Join(live.m.Dir(), name), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := live.m.StageRestore(ctx, name); err == nil {
			t.Errorf("%s: restore was accepted", what)
		}
		if _, err := os.Stat(PendingPath(live.path)); err == nil {
			t.Errorf("%s: a restore was staged", what)
		}
		list, _ := live.m.List()
		for _, b := range list {
			if b.Kind == BeforeRestore {
				t.Errorf("%s: a before-restore backup was made for a restore that cannot happen", what)
			}
		}
		f, _ := os.Open(filepath.Join(live.m.Dir(), name))
		if _, err := live.m.Upload(ctx, f); err == nil {
			t.Errorf("%s: upload was accepted", what)
		}
		f.Close()
	}
	// Nothing was applied, so the live database and day files are as they were
	// and still answer.
	if applied, err := ApplyPendingRestore(live.path, nil); err != nil || applied != nil {
		t.Errorf("apply = %+v, %v; nothing should be pending", applied, err)
	}
	live.db.Close()
	if left, _ := filepath.Glob(live.path + ".*"); len(left) > 0 {
		t.Errorf("leftovers next to the live database: %v", left)
	}
	live.open()
	defer live.db.Close()
	checkPopulated(t, live)
}
