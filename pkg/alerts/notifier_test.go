package alerts

import (
	"context"
	"testing"
	"time"
)

// The notifier hears about each alert that opens, once, and not about one that only gains events.
func TestNotifierHearsOnlyOfOpenedAlerts(t *testing.T) {
	_, w, eng := setup(t)
	ctx := context.Background()
	var told []Opened
	eng.SetNotifier(func(_ context.Context, o Opened) { told = append(told, o) })

	clock := time.Now().Add(-time.Hour)
	send := func(n int) {
		for i := 0; i < n; i++ {
			clock = clock.Add(time.Second)
			if err := w.Submit(ctx, event(clock, "Failed password for root from 192.0.2.9", "192.0.2.9")); err != nil {
				t.Fatal(err)
			}
		}
		w.Drain(ctx)
	}
	send(9)
	eng.Check(ctx)
	if len(told) != 0 {
		t.Fatalf("announced below the threshold: %+v", told)
	}
	send(1)
	eng.Check(ctx)
	if len(told) != 1 || told[0].Rule.Name != "SSH brute force" || told[0].Group != "192.0.2.9" || told[0].Count != 10 {
		t.Fatalf("told = %+v; want the one new alert", told)
	}
	send(3)
	eng.Check(ctx)
	if len(told) != 1 {
		t.Errorf("an alert that only gained events was announced again: %+v", told)
	}
}
