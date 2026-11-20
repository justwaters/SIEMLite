package storage

import (
	"context"
	"testing"
)

// Counting open alerts at or above a severity: closed ones and lower ones are left out.
func TestCountOpenAlertsAtLeast(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	var critical int64
	for i, sev := range []int{2, 3, 4, 5} {
		ru := Rule{Name: "r" + string(rune('a'+i)), Severity: sev, Enabled: true, Threshold: 1, WindowMinutes: 1}
		id, err := repo.SaveRule(ctx, ru, 1000)
		if err != nil {
			t.Fatal(err)
		}
		ru.ID = id
		if _, err := repo.RaiseAlert(ctx, ru, "", 1, 1, 1, 1, 1000); err != nil {
			t.Fatal(err)
		}
		if sev == 5 {
			critical = id
		}
	}
	for min, want := range map[int]int64{1: 4, 3: 3, 4: 2, 5: 1, 6: 0} {
		if got, err := repo.CountOpenAlertsAtLeast(ctx, min); err != nil || got != want {
			t.Errorf("at least %d: %d, %v; want %d", min, got, err, want)
		}
	}
	alerts, err := repo.AlertsOfRule(ctx, critical)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts of the critical rule: %v %v", alerts, err)
	}
	if _, err := repo.SetAlertStatus(ctx, alerts[0].ID, AlertClosed, "jd", 2000); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.CountOpenAlertsAtLeast(ctx, 4); got != 1 {
		t.Errorf("after closing the critical one: %d, want 1", got)
	}
}
