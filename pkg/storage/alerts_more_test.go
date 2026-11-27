package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newRule(t *testing.T, repo *Repository, ru Rule) Rule {
	t.Helper()
	id, err := repo.SaveRule(context.Background(), ru, 10)
	if err != nil {
		t.Fatal(err)
	}
	ru.ID = id
	return ru
}

func TestRuleSaveGetDelete(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	sev, src := 3, int64(1)
	ru := Rule{Name: "ssh brute", Description: "d", Enabled: true, Severity: 4, Query: "ssh", MinSeverity: &sev, ThreatOnly: true,
		SourceID: &src, GroupBy: "src_ip", Threshold: 5, WindowMinutes: 10}
	id, err := repo.SaveRule(ctx, ru, 100)
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	got, err := repo.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != RuleMatch || got.Builtin || got.CreatedAt != 100 || got.UpdatedAt != 100 || got.Query != "ssh" || !got.ThreatOnly ||
		got.MinSeverity == nil || *got.MinSeverity != 3 || got.SourceID == nil || *got.SourceID != 1 || got.GroupBy != "src_ip" {
		t.Errorf("rule: %+v", got)
	}

	// Duplicate name, on create and on rename.
	if _, err := repo.SaveRule(ctx, Rule{Name: "ssh brute", Threshold: 1, WindowMinutes: 1}, 1); !errors.Is(err, ErrRuleExists) {
		t.Errorf("duplicate create: %v", err)
	}
	other := newRule(t, repo, Rule{Name: "other", Threshold: 1, WindowMinutes: 1})
	other.Name = "ssh brute"
	if _, err := repo.SaveRule(ctx, other, 2); !errors.Is(err, ErrRuleExists) {
		t.Errorf("duplicate rename: %v", err)
	}

	// Update keeps created_at, bumps updated_at; unknown id is not found.
	got.Name, got.Threshold, got.MinSeverity = "renamed", 9, nil
	if uid, err := repo.SaveRule(ctx, *got, 500); err != nil || uid != id {
		t.Fatalf("update: %d %v", uid, err)
	}
	g2, _ := repo.GetRule(ctx, id)
	if g2.Name != "renamed" || g2.Threshold != 9 || g2.MinSeverity != nil || g2.CreatedAt != 100 || g2.UpdatedAt != 500 {
		t.Errorf("after update: %+v", g2)
	}
	if _, err := repo.SaveRule(ctx, Rule{ID: 424242, Name: "ghost", Threshold: 1, WindowMinutes: 1}, 1); !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("update unknown: %v", err)
	}

	// A volume rule drops search, grouping and filters whatever the caller passed.
	vsrc := int64(2)
	vr := newRule(t, repo, Rule{Name: "quiet", Kind: RuleVolumeUnder, Query: "x", MinSeverity: &sev, ThreatOnly: true, GroupBy: "user",
		SourceID: &vsrc, Threshold: 1, WindowMinutes: 5})
	g3, _ := repo.GetRule(ctx, vr.ID)
	if !g3.IsVolume() || g3.Query != "" || g3.MinSeverity != nil || g3.ThreatOnly || g3.GroupBy != "" || g3.SourceID == nil || *g3.SourceID != 2 {
		t.Errorf("volume rule not normalized: %+v", g3)
	}

	// Delete keeps the alerts the rule raised.
	if _, err := repo.RaiseAlert(ctx, *g2, "1.1.1.1", 3, 3, 1, 2, 1000); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteRule(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetRule(ctx, id); !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	if err := repo.DeleteRule(ctx, id); !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("delete twice: %v", err)
	}
	if _, err := repo.GetRule(ctx, 987654); !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("get unknown: %v", err)
	}
	var n int
	repo.db.Read.QueryRow(`SELECT COUNT(*) FROM alerts WHERE rule_name = 'renamed'`).Scan(&n)
	if n != 1 {
		t.Errorf("alerts of a deleted rule: %d, want 1 kept", n)
	}
}

func TestRaiseAlertGroupsAndStatus(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	ru := newRule(t, repo, Rule{Name: "r", Severity: 2, GroupBy: "src_ip", Threshold: 1, WindowMinutes: 1})

	opened, err := repo.RaiseAlert(ctx, ru, "9.9.9.9", 4, 4, 100, 200, 1000)
	if err != nil || !opened {
		t.Fatalf("first raise: %v %v", opened, err)
	}
	// Same group again: no new alert; the count adds the new events, the span widens, severity follows the rule.
	ru.Severity = 5
	opened, err = repo.RaiseAlert(ctx, ru, "9.9.9.9", 3, 99, 50, 150, 2000)
	if err != nil || opened {
		t.Fatalf("second raise: %v %v", opened, err)
	}
	if opened, _ := repo.RaiseAlert(ctx, ru, "8.8.8.8", 1, 1, 1, 1, 2000); !opened {
		t.Error("a different group opens its own alert")
	}
	alerts, err := repo.AlertsOfRule(ctx, ru.ID)
	if err != nil || len(alerts) != 2 {
		t.Fatalf("alerts: %+v %v", alerts, err)
	}
	a := alerts[0]
	if a.GroupValue != "9.9.9.9" || a.Count != 7 || a.FirstSeen != 50 || a.LastSeen != 200 || a.Severity != 5 || a.Status != AlertOpen ||
		a.RuleName != "r" || a.RuleID == nil || *a.RuleID != ru.ID || a.GroupBy != "src_ip" || a.CreatedAt != 1000 || a.UpdatedAt != 2000 {
		t.Errorf("alert: %+v", a)
	}

	// SetAlertCount corrects the count; unknown id errors.
	if err := repo.SetAlertCount(ctx, a.ID, 42, 3000); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetAlertCount(ctx, 99999, 1, 1); !errors.Is(err, ErrAlertNotFound) {
		t.Errorf("set count unknown: %v", err)
	}
	alerts, _ = repo.AlertsOfRule(ctx, ru.ID)
	if alerts[0].Count != 42 || alerts[0].UpdatedAt != 3000 {
		t.Errorf("after SetAlertCount: %+v", alerts[0])
	}

	if n, _ := repo.CountOpenAlerts(ctx); n != 2 {
		t.Errorf("open = %d, want 2", n)
	}
	ack, err := repo.SetAlertStatus(ctx, a.ID, AlertAcknowledged, "jd", "", 4000)
	if err != nil || ack.Status != AlertAcknowledged || ack.UpdatedBy != "jd" || ack.UpdatedAt != 4000 {
		t.Fatalf("ack: %+v %v", ack, err)
	}
	if n, _ := repo.CountOpenAlerts(ctx); n != 1 {
		t.Errorf("open after ack = %d, want 1", n)
	}
	// An acknowledged alert still absorbs new events.
	if opened, _ := repo.RaiseAlert(ctx, ru, "9.9.9.9", 1, 1, 1, 1, 4500); opened {
		t.Error("acknowledged alert should be updated, not duplicated")
	}
	closed, err := repo.SetAlertStatus(ctx, a.ID, AlertClosed, "jd", "closed in the test", 5000)
	if err != nil || closed.Status != AlertClosed {
		t.Fatalf("close: %+v %v", closed, err)
	}
	var cs int64
	repo.db.Read.QueryRow(`SELECT closed_seq FROM alerts WHERE id = ?`, a.ID).Scan(&cs)
	top, _ := repo.TopEventSeq(ctx)
	if cs != top {
		t.Errorf("closed_seq=%d, want top seq %d", cs, top)
	}
	// After closing, the group opens a fresh alert.
	if opened, _ := repo.RaiseAlert(ctx, ru, "9.9.9.9", 1, 1, 1, 1, 6000); !opened {
		t.Error("a closed alert must not absorb new events")
	}
	if closed.CloseNote != "closed in the test" || closed.UpdatedBy != "jd" {
		t.Errorf("close note not kept: %+v", closed)
	}
	if list, _, _ := repo.ListAlerts(ctx, AlertClosed, 10); len(list) != 1 || list[0].CloseNote != "closed in the test" {
		t.Errorf("listed close note: %+v", list)
	}
	if _, err := repo.SetAlertStatus(ctx, 99999, AlertClosed, "x", "closed in the test", 1); !errors.Is(err, ErrAlertNotFound) {
		t.Errorf("status unknown: %v", err)
	}
	// Reopening works and leaves closed_seq alone.
	re, err := repo.SetAlertStatus(ctx, a.ID, AlertOpen, "jd", "", 7000)
	if err != nil || re.Status != AlertOpen {
		t.Fatalf("reopen: %+v %v", re, err)
	}
	if re.CloseNote != "" {
		t.Errorf("a reopened alert still shows a close note: %q", re.CloseNote)
	}
	var cs2 int64
	repo.db.Read.QueryRow(`SELECT closed_seq FROM alerts WHERE id = ?`, a.ID).Scan(&cs2)
	if cs2 != cs {
		t.Errorf("reopen changed closed_seq %d -> %d", cs, cs2)
	}
	if got, _ := repo.AlertsOfRule(ctx, 123456); len(got) != 0 || got == nil {
		t.Errorf("alerts of an unknown rule: %+v", got)
	}
}

func TestRaiseVolumeAlert(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	src := int64(1)
	over := newRule(t, repo, Rule{Name: "loud", Kind: RuleVolumeOver, SourceID: &src, Severity: 3, Threshold: 10, WindowMinutes: 5})
	under := newRule(t, repo, Rule{Name: "quiet", Kind: RuleVolumeUnder, SourceID: &src, Severity: 2, Threshold: 10, WindowMinutes: 5})

	for _, ru := range []Rule{over, under} {
		opened, err := repo.RaiseVolumeAlert(ctx, ru, 50, 100, 200, 1000)
		if err != nil || !opened {
			t.Fatalf("%s first: %v %v", ru.Name, opened, err)
		}
		// 30 is lower than 50, 80 is higher: "over" keeps the peak, "under" the lowest.
		for _, c := range []int64{30, 80} {
			if opened, err := repo.RaiseVolumeAlert(ctx, ru, c, 150, 300, 2000); err != nil || opened {
				t.Fatalf("%s repeat: %v %v", ru.Name, opened, err)
			}
		}
		al, _ := repo.AlertsOfRule(ctx, ru.ID)
		if len(al) != 1 {
			t.Fatalf("%s: %d alerts", ru.Name, len(al))
		}
		want := int64(80)
		if ru.Kind == RuleVolumeUnder {
			want = 30
		}
		if al[0].Count != want || al[0].LastSeen != 300 || al[0].FirstSeen != 100 || al[0].GroupValue != "" {
			t.Errorf("%s alert: %+v, want count %d", ru.Name, al[0], want)
		}
	}
	// After closing, a new one opens.
	al, _ := repo.AlertsOfRule(ctx, over.ID)
	repo.SetAlertStatus(ctx, al[0].ID, AlertClosed, "x", "closed in the test", 3000)
	if opened, _ := repo.RaiseVolumeAlert(ctx, over, 11, 1, 2, 4000); !opened {
		t.Error("closed volume alert should not be reused")
	}
}

func TestRaiseManualAlert(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	in := Alert{RuleName: "Odd login", Severity: 3, GroupBy: "user", GroupValue: "bob", Count: 2, Note: "first", UpdatedBy: "agent"}
	a, created, err := repo.RaiseManualAlert(ctx, in, 1000)
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	if a.RuleID != nil || a.Status != AlertOpen || a.Count != 2 || a.FirstSeen != 1000 || a.LastSeen != 1000 || a.Note != "first" || a.UpdatedBy != "agent" {
		t.Errorf("created: %+v", a)
	}
	in.Count, in.Severity, in.Note = 3, 5, "second"
	b, created, err := repo.RaiseManualAlert(ctx, in, 2000)
	if err != nil || created || b.ID != a.ID {
		t.Fatalf("repeat: %+v %v %v", b, created, err)
	}
	if b.Count != 5 || b.Severity != 5 || b.Note != "second" || b.LastSeen != 2000 || b.FirstSeen != 1000 {
		t.Errorf("updated: %+v", b)
	}
	// Different group value or title opens another one; closed ones are not reused.
	if _, c, _ := repo.RaiseManualAlert(ctx, Alert{RuleName: "Odd login", GroupBy: "user", GroupValue: "eve", Count: 1}, 3000); !c {
		t.Error("different group should create")
	}
	repo.SetAlertStatus(ctx, a.ID, AlertClosed, "x", "closed in the test", 3500)
	if c2, c, _ := repo.RaiseManualAlert(ctx, in, 4000); !c || c2.ID == a.ID {
		t.Error("a closed manual alert should not be reused")
	}
}

func TestAlertsInRangeAndCounts(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	ru := newRule(t, repo, Rule{Name: "r", Severity: 1, Threshold: 1, WindowMinutes: 1})
	mk := func(sev int, count int64, at int64, name string) Alert {
		t.Helper()
		a, _, err := repo.RaiseManualAlert(ctx, Alert{RuleName: name, Severity: sev, Count: count}, at)
		if err != nil {
			t.Fatal(err)
		}
		return *a
	}
	low := mk(1, 100, 1000, "low")
	hiSmall := mk(4, 1, 2000, "hi-small")
	hiBig := mk(4, 9, 3000, "hi-big")
	outside := mk(5, 1, 5000, "outside") // at toMs: excluded (half-open)
	_ = outside
	before := mk(5, 1, 999, "before")
	_ = before
	repo.SetAlertStatus(ctx, low.ID, AlertClosed, "x", "closed in the test", 3100)
	_ = ru

	list, total, bySev, byStat, err := repo.AlertsInRange(ctx, 1000, 5000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(list) != 3 {
		t.Fatalf("total=%d list=%d, want 3", total, len(list))
	}
	if list[0].ID != hiBig.ID || list[1].ID != hiSmall.ID || list[2].ID != low.ID {
		t.Errorf("order should be severity then count: %v %v %v", list[0].RuleName, list[1].RuleName, list[2].RuleName)
	}
	if bySev[4] != 2 || bySev[1] != 1 || len(bySev) != 2 || byStat[AlertOpen] != 2 || byStat[AlertClosed] != 1 {
		t.Errorf("bySev=%v byStat=%v", bySev, byStat)
	}
	// limit truncates the list, not the totals.
	list, total, _, _, _ = repo.AlertsInRange(ctx, 1000, 5000, 1)
	if len(list) != 1 || total != 3 || list[0].ID != hiBig.ID {
		t.Errorf("limit: %d %d", len(list), total)
	}
	list, total, bySev, byStat, err = repo.AlertsInRange(ctx, 10000, 20000, 5)
	if err != nil || list == nil || len(list) != 0 || total != 0 || len(bySev) != 0 || len(byStat) != 0 {
		t.Errorf("empty range: %v %d %v %v %v", list, total, bySev, byStat, err)
	}
}

func TestCountSourceEvents(t *testing.T) {
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
	rec := func(ago int64, src int64, action string) Record {
		r := Record{Timestamp: now - ago, CategoryUID: 6, ClassUID: 6003, SeverityID: 1, Message: "m", RawData: "m", SourceID: src}
		if action != "" {
			r.Fields = []byte(`{"action":"` + action + `"}`)
		}
		return r
	}
	if err := repo.InsertBatch(ctx, []Record{
		rec(1000, other, ""), rec(2000, other, ""), rec(3000, other, ""),
		rec(500, other, ""),        // inside
		rec(10*60*1000, other, ""), // older than the range
		rec(1000, internal.ID, "ingest.late"),
		rec(1000, internal.ID, "alert.closed"), // SIEMLite's own alert audit: not counted
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.CountSourceEvents(ctx, other, now-60_000, now); err != nil || n != 4 {
		t.Errorf("other source: %d %v, want 4", n, err)
	}
	if n, _ := repo.CountSourceEvents(ctx, other, now-1500, now); n != 2 {
		t.Errorf("narrow range: %d, want 2 (inclusive bounds)", n)
	}
	if n, _ := repo.CountSourceEvents(ctx, internal.ID, now-60_000, now); n != 1 {
		t.Errorf("internal source: %d, want 1 (alert.* audit excluded)", n)
	}
	if n, err := repo.CountSourceEvents(ctx, 987, now-60_000, now); err != nil || n != 0 {
		t.Errorf("unknown source: %d %v", n, err)
	}
}

// Counting open alerts at or above a severity: closed ones and lower ones are left out.
func TestCountOpenAlertsAtLeast(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)
	for i, sev := range []int{2, 3, 4, 5} {
		ru := newRule(t, repo, Rule{Name: "r" + string(rune('a'+i)), Severity: sev, Threshold: 1, WindowMinutes: 1})
		if _, err := repo.RaiseAlert(ctx, ru, "", 1, 1, 1, 1, 1000); err != nil {
			t.Fatal(err)
		}
	}
	for min, want := range map[int]int64{1: 4, 3: 3, 4: 2, 5: 1, 6: 0} {
		if got, err := repo.CountOpenAlertsAtLeast(ctx, min); err != nil || got != want {
			t.Errorf("at least %d: %d, %v; want %d", min, got, err, want)
		}
	}
	all, _, _, _, err := repo.AlertsInRange(ctx, 0, 1<<40, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.Severity == 5 {
			if _, err := repo.SetAlertStatus(ctx, a.ID, AlertClosed, "jd", "closed in the test", 2000); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got, _ := repo.CountOpenAlertsAtLeast(ctx, 4); got != 1 {
		t.Errorf("after closing the critical one: %d, want 1", got)
	}
}
