package alerts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/sample"
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

// The sample data's incident trips the built-in rules.
func TestSampleDataRaisesAlerts(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	if _, err := sample.NewManager(repo, w).Enable(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := eng.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := alertsByRule(t, repo)
	brute := got["SSH brute force"]
	if len(brute) != 1 || brute[0].GroupValue != "203.0.113.7" || brute[0].Count < 10 || !brute[0].Sample || brute[0].Status != "open" {
		t.Errorf("brute force alerts = %+v", brute)
	}
	if len(got["Threat intel match"]) == 0 || len(got["Critical event"]) != 1 {
		t.Errorf("threat %d, critical %d (result %+v)", len(got["Threat intel match"]), len(got["Critical event"]), res)
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
