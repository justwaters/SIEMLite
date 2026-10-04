package alerts

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/loggen"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

func setup(t *testing.T) (*storage.Repository, *ingest.Worker, *Engine) {
	t.Helper()
	db, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "a.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	w := ingest.New(repo, ingest.Config{FlushInterval: 10 * time.Millisecond})
	t.Cleanup(w.Close)
	return repo, w, New(repo, nil)
}

func alertsByRule(t *testing.T, repo *storage.Repository) map[string][]storage.Alert {
	t.Helper()
	list, _, err := repo.ListAlerts(context.Background(), "", 500)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]storage.Alert{}
	for _, a := range list {
		out[a.RuleName] = append(out[a.RuleName], a)
	}
	return out
}

// The log generator's attacks trip the built-in rules, read through its
// parser as SIEMLite reads them.
func TestGeneratorAttacksRaiseAlerts(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	p, err := parser.Compile(parser.LogGenerator)
	if err != nil {
		t.Fatal(err)
	}
	g := loggen.New(7)
	start := time.Now().Add(-30 * time.Minute)
	for i := 0; i < 5000; i++ {
		at := start.Add(time.Duration(i) * 300 * time.Millisecond)
		res, err := p.Parse(string(g.Next(at)), parser.Defaults{Now: at})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Submit(ctx, res.Event); err != nil {
			t.Fatal(err)
		}
	}
	w.Drain(ctx)
	res, err := eng.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := alertsByRule(t, repo)
	brute := got["SSH brute force"]
	if len(brute) == 0 || brute[0].Count < 10 || brute[0].Status != "open" {
		t.Errorf("brute force alerts = %+v", brute)
	}
	if len(got["Critical event"]) == 0 {
		t.Errorf("no critical event alert (result %+v, alerts %v)", res, got)
	}
	for _, a := range brute {
		if !strings.HasPrefix(a.GroupValue, "192.0.2.") && !strings.HasPrefix(a.GroupValue, "198.51.100.") && !strings.HasPrefix(a.GroupValue, "203.0.113.") {
			t.Errorf("brute force from %s, which isn't one of the generator's attackers", a.GroupValue)
		}
	}
	// Nothing new: nothing changes.
	if res2, _ := eng.Check(ctx); res2.Opened+res2.Updated != 0 {
		t.Errorf("second check changed alerts: %+v", res2)
	}
}

func event(at time.Time, msg, src string) *ocsf.Event {
	return &ocsf.Event{Time: at.UnixMilli(), CategoryUID: 3, ClassUID: 3002, ActivityID: 1, SeverityID: 3,
		Message: msg, RawData: msg, SrcEndpoint: &ocsf.Endpoint{IP: src}}
}

func TestThresholdWindowAndDedupe(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	// Each burst continues from where the last left off, as real logs do.
	clock := time.Now().Add(-3 * time.Hour)
	send := func(n int, gap time.Duration, src string) {
		for i := 0; i < n; i++ {
			clock = clock.Add(gap)
			ev := event(clock, "Failed password for root from "+src, src)
			if err := w.Submit(ctx, ev); err != nil {
				t.Fatal(err)
			}
		}
		w.Drain(ctx)
	}
	// 9 failures in 5 minutes: below the threshold of 10.
	send(9, 20*time.Second, "192.0.2.1")
	// 12 failures 6 minutes apart: never 10 within 5 minutes.
	send(12, 6*time.Minute, "192.0.2.2")
	clock = clock.Add(-70 * time.Minute) // back to just after the .1 burst
	eng.Check(ctx)
	if got := alertsByRule(t, repo)["SSH brute force"]; len(got) != 0 {
		t.Fatalf("alerts below threshold: %+v", got)
	}
	// One more for .1 reaches 10 within the window.
	send(1, 10*time.Second, "192.0.2.1")
	eng.Check(ctx)
	got := alertsByRule(t, repo)["SSH brute force"]
	if len(got) != 1 || got[0].GroupValue != "192.0.2.1" || got[0].Count != 10 {
		t.Fatalf("after reaching threshold: %+v", got)
	}
	// Further failures update the same alert instead of opening another.
	send(3, time.Second, "192.0.2.1")
	eng.Check(ctx)
	got = alertsByRule(t, repo)["SSH brute force"]
	if len(got) != 1 || got[0].Count != 13 {
		t.Fatalf("after more failures: %+v", got)
	}
	// Once closed, a new burst opens a new alert.
	if _, err := repo.SetAlertStatus(ctx, got[0].ID, storage.AlertClosed, "test", 1); err != nil {
		t.Fatal(err)
	}
	send(10, time.Second, "192.0.2.1")
	eng.Check(ctx)
	if got := alertsByRule(t, repo)["SSH brute force"]; len(got) != 2 {
		t.Errorf("after closing and a new burst: %+v", got)
	}
}

func TestBrokenRuleDoesNotStopOthers(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "bad", Enabled: true, Severity: 3, Query: `"unterminated`, Threshold: 1, WindowMinutes: 5}, 1); err != nil {
		t.Fatal(err)
	}
	ev := event(time.Now(), "critical disk failure", "10.0.0.1")
	ev.SeverityID = 5
	w.Submit(ctx, ev)
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alertsByRule(t, repo)["Critical event"]; len(got) != 1 {
		t.Errorf("critical alerts = %+v", got)
	}
}

// flaky fails one rule's lookups while failing is set.
type flaky struct {
	*storage.Repository
	rule    string
	failing bool
}

func (f *flaky) NewMatches(ctx context.Context, ru storage.Rule, afterSeq, maxSeq int64) ([]storage.RuleGroup, error) {
	if f.failing && ru.Name == f.rule {
		return nil, errors.New("database is locked")
	}
	return f.Repository.NewMatches(ctx, ru, afterSeq, maxSeq)
}

// A rule that fails once looks at the same events again on the next check,
// instead of skipping them, and the other rules carry on meanwhile.
func TestFailedRuleRetriesItsEvents(t *testing.T) {
	repo, w, _ := setup(t)
	ctx := context.Background()
	store := &flaky{Repository: repo, rule: "SSH brute force", failing: true}
	eng := New(store, nil)
	now := time.Now()
	for i := 0; i < 12; i++ {
		ev := &ocsf.Event{Time: now.Add(time.Duration(i) * time.Second).UnixMilli(), CategoryUID: 3, ClassUID: 3002, ActivityID: 1, SeverityID: 5,
			Message: "Failed password for root from 198.51.100.9", SrcEndpoint: &ocsf.Endpoint{IP: "198.51.100.9"}}
		if err := w.Submit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	got := alertsByRule(t, repo)
	if len(got["SSH brute force"]) != 0 || len(got["Critical event"]) == 0 {
		t.Fatalf("while failing: brute force %d, critical %d", len(got["SSH brute force"]), len(got["Critical event"]))
	}
	store.failing = false
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	got = alertsByRule(t, repo)
	if b := got["SSH brute force"]; len(b) != 1 || b[0].Count != 12 {
		t.Errorf("after recovering: brute force alerts %+v", b)
	}
	if c := got["Critical event"]; len(c) != 1 || c[0].Count != 12 {
		t.Errorf("critical event counted again: %+v", c)
	}
}

func failedPasswords(t *testing.T, repo *storage.Repository, ip string, times ...time.Time) {
	t.Helper()
	var recs []storage.Record
	for _, at := range times {
		recs = append(recs, storage.Record{Timestamp: at.UnixMilli(), CategoryUID: 3, ClassUID: 3002, SeverityID: 3,
			SrcIP: ip, RawData: "sshd: Failed password for root from " + ip})
	}
	if err := repo.InsertBatch(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

// A brute force that spans midnight is split across two day files; the
// window counts both.
func TestWindowAcrossMidnight(t *testing.T) {
	repo, _, eng := setup(t)
	ctx := context.Background()
	midnight := time.Now().UTC().Truncate(24 * time.Hour)
	var times []time.Time
	for i := 0; i < 12; i++ {
		times = append(times, midnight.Add(time.Duration(i-6)*10*time.Second)) // 23:59:00 to 00:00:50
	}
	failedPasswords(t, repo, "198.51.100.1", times...)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if b := alertsByRule(t, repo)["SSH brute force"]; len(b) != 1 || b[0].Count != 12 {
		t.Errorf("brute force across midnight = %+v", b)
	}
}

// Events that arrive late are filed in an older day; the engine still sees
// them as new.
func TestLateEventsInOldDay(t *testing.T) {
	repo, _, eng := setup(t)
	ctx := context.Background()
	failedPasswords(t, repo, "198.51.100.2", time.Now())
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3 * 24 * time.Hour)
	var times []time.Time
	for i := 0; i < 10; i++ {
		times = append(times, old.Add(time.Duration(i)*time.Second))
	}
	failedPasswords(t, repo, "198.51.100.3", times...)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if b := alertsByRule(t, repo)["SSH brute force"]; len(b) != 1 || b[0].GroupValue != "198.51.100.3" || b[0].Count != 10 {
		t.Errorf("late brute force = %+v", b)
	}
}
