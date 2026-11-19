package alerts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/intel"
	"siemlite/pkg/storage"
)

// A log line from a Tor exit node raises a High "Threat intel match" alert, unless the address is friendly.
func TestTorExitNodeRaisesAHighAlert(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "a.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	if _, err := repo.AddIndicators(ctx, []storage.Indicator{
		{Type: "ip", Value: "171.25.193.25", Source: "Tor exit nodes", Description: "Tor exit node"},
		{Type: "ip", Value: "80.67.167.81", Source: "Tor exit nodes", Description: "Tor exit node"},
	}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateFriendlyList(ctx, "Our exit", "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddFriendlyEntries(ctx, 1, []string{"80.67.167.81"}, "", 1); err != nil {
		t.Fatal(err)
	}
	svc := intel.NewService(repo, intel.Config{})
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	w := ingest.New(repo, ingest.Config{FlushInterval: 10 * time.Millisecond, Enricher: svc.Matcher})
	t.Cleanup(w.Close)
	eng := New(repo, nil)
	var told []Opened
	eng.SetNotifier(func(_ context.Context, o Opened) { told = append(told, o) })
	now := time.Now()
	for _, ip := range []string{"171.25.193.25", "80.67.167.81", "192.0.2.50"} {
		if err := w.Submit(ctx, event(now, "GET /login from "+ip, ip)); err != nil {
			t.Fatal(err)
		}
	}
	w.Drain(ctx)
	eng.Check(ctx)
	got := alertsByRule(t, repo)["Threat intel match"]
	if len(got) != 1 || got[0].GroupValue != "171.25.193.25" || got[0].Severity != 4 {
		t.Fatalf("alerts = %+v; want one High alert for the unlisted-friendly Tor exit only", got)
	}
	if len(told) != 1 || told[0].Group != "171.25.193.25" || told[0].Rule.Severity != 4 || told[0].Rule.Name != "Threat intel match" {
		t.Errorf("the notifier was told %+v; want the one new alert", told)
	}
	// A second check with nothing new opens nothing, so nothing more is announced.
	eng.Check(ctx)
	if len(told) != 1 {
		t.Errorf("announced again: %d", len(told))
	}
}
