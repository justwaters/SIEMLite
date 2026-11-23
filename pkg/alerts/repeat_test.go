package alerts

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

func repeatRule(t *testing.T, repo *storage.Repository, name, kind, query string, threshold, window int) storage.Rule {
	t.Helper()
	ru := storage.Rule{Name: name, Kind: kind, Enabled: true, Severity: 3, Query: query, GroupBy: "src_ip", Threshold: threshold, WindowMinutes: window}
	id, err := repo.SaveRule(context.Background(), ru, 1)
	if err != nil {
		t.Fatal(err)
	}
	ru.ID = id
	return ru
}

func ev(user string, sev int, msg string, at time.Time) storage.Record {
	return storage.Record{Timestamp: at.UnixMilli(), CategoryUID: 3, ClassUID: 3002, SeverityID: sev, UserName: user,
		Message: msg, RawData: msg}
}

// burst is n events of the user, 5 seconds apart from start.
func burst(user string, sev int, msg string, n int, start time.Time) []storage.Record {
	var out []storage.Record
	for i := 0; i < n; i++ {
		out = append(out, ev(user, sev, msg, start.Add(time.Duration(i)*5*time.Second)))
	}
	return out
}

func repeatSetup(t *testing.T) (*storage.Repository, *Engine, *[]Opened) {
	t.Helper()
	repo, _, eng := setup(t)
	var told []Opened
	eng.SetNotifier(func(_ context.Context, o Opened) { told = append(told, o) })
	return repo, eng, &told
}

func mine(t *testing.T, repo *storage.Repository, name string) []storage.Alert {
	t.Helper()
	return alertsByRule(t, repo)[name]
}

func TestRepeatSeverityFiresAtThreshold(t *testing.T) {
	repo, eng, told := repeatSetup(t)
	repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "", 5, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	insert(t, repo, burst("alice", 4, "disk event", 4, t0)...)
	check(t, eng)
	if got := mine(t, repo, "Same level"); len(got) != 0 {
		t.Fatalf("4 of 5: %+v", got)
	}
	insert(t, repo, ev("alice", 4, "disk event", t0.Add(time.Minute)))
	if res := check(t, eng); res.Opened == 0 {
		t.Fatalf("result = %+v", res)
	}
	got := mine(t, repo, "Same level")
	if len(got) != 1 || got[0].GroupValue != "alice" || got[0].GroupBy != "user" || got[0].Count != 5 {
		t.Fatalf("alerts = %+v", got)
	}
	var o Opened
	for _, x := range *told {
		if x.Rule.Name == "Same level" {
			o = x
		}
	}
	if o.Group != "alice" || o.Count != 5 || !strings.Contains(o.Detail, "5 events") || !strings.Contains(o.Detail, "severity High") {
		t.Errorf("told = %+v", o)
	}
}

func TestRepeatSeverityMixedLevelsDoNotAdd(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "", 5, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	var recs []storage.Record
	recs = append(recs, burst("alice", 4, "x", 3, t0)...)
	recs = append(recs, burst("alice", 2, "x", 4, t0.Add(time.Minute))...)
	insert(t, repo, recs...)
	check(t, eng)
	if got := mine(t, repo, "Same level"); len(got) != 0 {
		t.Fatalf("3 High + 4 Low: %+v", got)
	}
}

func TestRepeatKeyword(t *testing.T) {
	repo, eng, told := repeatSetup(t)
	repeatRule(t, repo, "Same word", storage.RuleRepeatKeyword, "denied, failed, blocked", 5, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	var recs []storage.Record
	recs = append(recs, burst("alice", 3, "access denied for file", 2, t0)...)
	recs = append(recs, burst("alice", 3, "login failed here", 3, t0.Add(time.Minute))...)
	insert(t, repo, recs...)
	check(t, eng)
	if got := mine(t, repo, "Same word"); len(got) != 0 {
		t.Fatalf("2 denied + 3 failed: %+v", got)
	}
	insert(t, repo, burst("alice", 3, "login failed again", 2, t0.Add(2*time.Minute))...)
	check(t, eng)
	got := mine(t, repo, "Same word")
	if len(got) != 1 || got[0].GroupValue != "alice" || got[0].Count != 5 {
		t.Fatalf("5 failed: %+v", got)
	}
	for _, x := range *told {
		if x.Rule.Name == "Same word" && !strings.Contains(x.Detail, `"failed"`) {
			t.Errorf("detail = %q", x.Detail)
		}
	}
}

func TestRepeatKeywordPhrase(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	repeatRule(t, repo, "Phrase", storage.RuleRepeatKeyword, "bad password", 3, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	var recs []storage.Record
	recs = append(recs, burst("alice", 3, "bad password given", 2, t0)...)
	recs = append(recs, burst("alice", 3, "bad token, password ok", 5, t0)...) // not the phrase
	insert(t, repo, recs...)
	check(t, eng)
	if got := mine(t, repo, "Phrase"); len(got) != 0 {
		t.Fatalf("phrase matched loosely: %+v", got)
	}
	insert(t, repo, ev("alice", 3, "bad password again", t0.Add(time.Minute)))
	check(t, eng)
	if got := mine(t, repo, "Phrase"); len(got) != 1 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestRepeatBoth(t *testing.T) {
	repo, eng, told := repeatSetup(t)
	repeatRule(t, repo, "Word and level", storage.RuleRepeatBoth, "failed, denied", 4, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	var recs []storage.Record
	// 6 failed in total, but split over two levels; 3 denied High: no pair has 4.
	recs = append(recs, burst("alice", 4, "failed", 3, t0)...)
	recs = append(recs, burst("alice", 2, "failed", 3, t0.Add(time.Minute))...)
	recs = append(recs, burst("alice", 4, "denied", 3, t0.Add(2*time.Minute))...)
	insert(t, repo, recs...)
	check(t, eng)
	if got := mine(t, repo, "Word and level"); len(got) != 0 {
		t.Fatalf("no pair at 4: %+v", got)
	}
	insert(t, repo, ev("alice", 4, "failed", t0.Add(3*time.Minute)))
	check(t, eng)
	got := mine(t, repo, "Word and level")
	if len(got) != 1 || got[0].Count != 4 {
		t.Fatalf("failed+High reached 4: %+v", got)
	}
	for _, x := range *told {
		if x.Rule.Name == "Word and level" && (!strings.Contains(x.Detail, `"failed"`) || !strings.Contains(x.Detail, "High")) {
			t.Errorf("detail = %q", x.Detail)
		}
	}
}

func TestRepeatWindowEmptyUserAndUsers(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "", 5, 10)
	t0 := time.Now().Add(-3 * time.Hour)
	var recs []storage.Record
	// Four in the window and a fifth far outside it.
	recs = append(recs, burst("old", 4, "x", 4, t0.Add(time.Hour))...)
	recs = append(recs, ev("old", 4, "x", t0))
	// No user: never counted, and never grouped as "".
	recs = append(recs, burst("", 4, "x", 12, t0)...)
	// Two users, one at the threshold, one a short.
	recs = append(recs, burst("bob", 5, "x", 5, t0)...)
	recs = append(recs, burst("carol", 5, "x", 4, t0)...)
	insert(t, repo, recs...)
	check(t, eng)
	got := mine(t, repo, "Same level")
	if len(got) != 1 || got[0].GroupValue != "bob" {
		t.Fatalf("alerts = %+v", got)
	}
	// Carol's fifth arrives: she gets her own alert; bob's stays one.
	insert(t, repo, ev("carol", 5, "x", t0.Add(time.Minute)))
	check(t, eng)
	got = mine(t, repo, "Same level")
	if len(got) != 2 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestRepeatNoDuplicateAlertOnRerun(t *testing.T) {
	repo, eng, told := repeatSetup(t)
	repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "", 3, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	insert(t, repo, burst("alice", 4, "x", 3, t0)...)
	check(t, eng)
	if res := check(t, eng); res.Opened+res.Updated != 0 {
		t.Errorf("second check = %+v", res)
	}
	// More of the same: the one alert is updated, not announced again.
	insert(t, repo, burst("alice", 4, "x", 2, t0.Add(time.Minute))...)
	check(t, eng)
	got := mine(t, repo, "Same level")
	if len(got) != 1 || got[0].Count != 5 {
		t.Fatalf("alerts = %+v", got)
	}
	n := 0
	for _, x := range *told {
		if x.Rule.Name == "Same level" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("announced %d times", n)
	}
}

func TestRepeatLateEvents(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	repeatRule(t, repo, "Same word", storage.RuleRepeatKeyword, "failed", 5, 10)
	now := time.Now()
	insert(t, repo, burst("alice", 3, "failed", 2, now.Add(-8*time.Minute))...)
	check(t, eng)
	// Three older ones arrive afterwards (a backfill); together they are five in ten minutes.
	insert(t, repo, burst("alice", 3, "failed", 3, now.Add(-30*time.Hour))...)
	insert(t, repo, burst("alice", 3, "failed", 3, now.Add(-5*time.Minute))...)
	check(t, eng)
	if got := mine(t, repo, "Same word"); len(got) != 1 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestRepeatDisabledAndEdited(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	ctx := context.Background()
	ru := repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "", 3, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	ru.Enabled = false
	if _, err := repo.SaveRule(ctx, ru, 2); err != nil {
		t.Fatal(err)
	}
	insert(t, repo, burst("alice", 4, "x", 3, t0)...)
	check(t, eng)
	ru.Enabled = true // switching it back on doesn't raise what happened meanwhile
	if _, err := repo.SaveRule(ctx, ru, 3); err != nil {
		t.Fatal(err)
	}
	check(t, eng)
	if got := mine(t, repo, "Same level"); len(got) != 0 {
		t.Fatalf("alerts for events while off: %+v", got)
	}
	// Edited to a keyword rule, it counts the new events by keyword.
	ru.Kind, ru.Query = storage.RuleRepeatKeyword, "boom"
	if _, err := repo.SaveRule(ctx, ru, 4); err != nil {
		t.Fatal(err)
	}
	insert(t, repo, burst("alice", 4, "boom", 3, t0.Add(5*time.Minute))...)
	check(t, eng)
	if got := mine(t, repo, "Same level"); len(got) != 1 {
		t.Fatalf("alerts = %+v", got)
	}
	// A repeat rule is always about users, whatever the caller asked for.
	rules, _ := repo.ListRules(ctx)
	for _, r := range rules {
		if r.ID == ru.ID && r.GroupBy != "user" {
			t.Errorf("group by = %q", r.GroupBy)
		}
	}
}

func TestRepeatSeverityKeepsItsFilters(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	repeatRule(t, repo, "Same level", storage.RuleRepeatSeverity, "login", 3, 10)
	t0 := time.Now().Add(-20 * time.Minute)
	insert(t, repo, burst("alice", 4, "other thing", 5, t0)...)
	insert(t, repo, burst("bob", 4, "login thing", 3, t0)...)
	check(t, eng)
	got := mine(t, repo, "Same level")
	if len(got) != 1 || got[0].GroupValue != "bob" {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestRepeatManyRules(t *testing.T) {
	repo, eng, _ := repeatSetup(t)
	for i := 0; i < 3; i++ {
		repeatRule(t, repo, fmt.Sprintf("R%d", i), storage.RuleRepeatKeyword, "k"+fmt.Sprint(i), 2, 10)
	}
	t0 := time.Now().Add(-20 * time.Minute)
	insert(t, repo, burst("alice", 3, "k1", 2, t0)...)
	check(t, eng)
	if len(mine(t, repo, "R1")) != 1 || len(mine(t, repo, "R0")) != 0 || len(mine(t, repo, "R2")) != 0 {
		t.Errorf("alerts = %+v", alertsByRule(t, repo))
	}
}
