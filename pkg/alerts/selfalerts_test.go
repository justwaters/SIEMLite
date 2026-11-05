package alerts

import (
	"context"
	"testing"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/storage"
)

// auditEvent writes an event the way SIEMLite's audit log does: from the INTERNAL source, with the action as a field.
func auditEvent(t *testing.T, w *ingest.Worker, repo *storage.Repository, at time.Time, action, msg string) {
	t.Helper()
	ctx := context.Background()
	internal, err := repo.BuiltinSource(ctx, storage.SourceInternal)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SubmitWith(ctx, event(at, msg, ""), ingest.SubmitOptions{SourceID: internal.ID, Fields: map[string]string{"action": action}}); err != nil {
		t.Fatal(err)
	}
}

func ruleByName(t *testing.T, repo *storage.Repository, name string) storage.Rule {
	t.Helper()
	rules, err := repo.ListRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no rule %q", name)
	return storage.Rule{}
}

// The built-in "Mass ingestion of late logs" rule reads the event's action, so an
// ingest.late event opens it and the audit events about managing the alert, which name
// it, never add to it or open another.
func TestMassIngestionRuleIgnoresTheAuditOfItsOwnAlert(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	if got := ruleByName(t, repo, "Mass ingestion of late logs").Query; got != "action=ingest.late" {
		t.Fatalf("the rule's search = %q", got)
	}
	now := time.Now()
	auditEvent(t, w, repo, now, "ingest.late", "Mass ingestion of late logs: 481 events more than 30 days old from DealTracker - Prod01, dated 2026-08-01 to 2026-09-20.")
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	alerts := alertsByRule(t, repo)["Mass ingestion of late logs"]
	if len(alerts) != 1 || alerts[0].Count != 1 || alerts[0].Status != "open" {
		t.Fatalf("after the real event: %+v", alerts)
	}
	// Managing the alert: acknowledge, close, reopen, as the API records them.
	for i, a := range []struct{ action, did string }{{"alert.acknowledged", "acknowledged"}, {"alert.closed", "closed"}, {"alert.open", "reopened"}} {
		auditEvent(t, w, repo, now.Add(time.Duration(i+1)*time.Second), a.action, "JD Waters "+a.did+" the alert Mass ingestion of late logs")
	}
	w.Drain(ctx)
	for i := 0; i < 2; i++ {
		if _, err := eng.Check(ctx); err != nil {
			t.Fatal(err)
		}
	}
	alerts = alertsByRule(t, repo)["Mass ingestion of late logs"]
	if len(alerts) != 1 || alerts[0].Count != 1 {
		t.Errorf("managing the alert changed it: %+v", alerts)
	}
	// A second real event still raises it.
	auditEvent(t, w, repo, now.Add(10*time.Second), "ingest.late", "Mass ingestion of late logs: 60 events more than 30 days old from another source.")
	w.Drain(ctx)
	eng.Check(ctx)
	if alerts = alertsByRule(t, repo)["Mass ingestion of late logs"]; len(alerts) != 1 || alerts[0].Count != 2 {
		t.Errorf("a second ingest.late event: %+v", alerts)
	}
}

// A rule an admin wrote, with a phrase from an alert's name, doesn't fire on that alert's
// lifecycle events either: the guard is in the engine, not in one rule.
func TestACustomRuleDoesNotFireOnAlertLifecycleEvents(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "Unusual zebra activity", Enabled: true, Severity: 3, Query: `"zebra sighting"`, Threshold: 1, WindowMinutes: 5}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "Zebra rule watcher", Enabled: true, Severity: 3, Query: `"unusual zebra"`, Threshold: 1, WindowMinutes: 5}, 1); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	w.Submit(ctx, event(now, "zebra sighting at the north gate", "10.0.0.1"))
	w.Drain(ctx)
	eng.Check(ctx)
	got := alertsByRule(t, repo)
	if len(got["Unusual zebra activity"]) != 1 || len(got["Zebra rule watcher"]) != 0 {
		t.Fatalf("after the real event: %v", got)
	}
	for i, a := range []struct{ action, did string }{{"alert.acknowledged", "acknowledged"}, {"alert.closed", "closed"}, {"alert.open", "reopened"}} {
		auditEvent(t, w, repo, now.Add(time.Duration(i+1)*time.Second), a.action, "JD Waters "+a.did+" the alert Unusual zebra activity")
	}
	w.Drain(ctx)
	eng.Check(ctx)
	eng.Check(ctx)
	got = alertsByRule(t, repo)
	if len(got["Zebra rule watcher"]) != 0 {
		t.Errorf("a rule fired on an alert's lifecycle events: %+v", got["Zebra rule watcher"])
	}
	if len(got["Unusual zebra activity"]) != 1 || got["Unusual zebra activity"][0].Count != 1 {
		t.Errorf("the alert was changed by managing it: %+v", got["Unusual zebra activity"])
	}
}

// A rule's search takes the same field terms as the search box.
func TestRuleSearchesTakeFieldTerms(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "By term", Enabled: true, Severity: 3, Query: `action=wanted src_ip=10.0.0.9,10.0.0.8`, Threshold: 1, WindowMinutes: 5}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "Broken term", Enabled: true, Severity: 3, Query: `severity=loud`, Threshold: 1, WindowMinutes: 5}, 1); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	internal, _ := repo.BuiltinSource(ctx, storage.SourceInternal)
	send := func(ip, action string) {
		ev := event(now, "something happened", ip)
		if err := w.SubmitWith(ctx, ev, ingest.SubmitOptions{SourceID: internal.ID, Fields: map[string]string{"action": action}}); err != nil {
			t.Fatal(err)
		}
	}
	send("10.0.0.9", "other")  // right address, wrong action
	send("10.0.0.1", "wanted") // right action, wrong address
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alertsByRule(t, repo)["By term"]; len(got) != 0 {
		t.Fatalf("a rule fired without matching every term: %+v", got)
	}
	send("10.0.0.8", "wanted")
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alertsByRule(t, repo)["By term"]; len(got) != 1 || got[0].GroupValue != "" && got[0].Count != 1 {
		t.Errorf("a rule that matches both terms: %+v", got)
	}
	// A rule whose search is broken fails on its own and holds nothing else back.
	if got := alertsByRule(t, repo)["Broken term"]; len(got) != 0 {
		t.Errorf("a broken rule raised an alert: %+v", got)
	}
}

// Alerts that SIEMLite's own audit events raised or inflated before this fix are corrected once: an alert with
// no event of its own is closed, an inflated count is lowered to the real one, a genuine alert is left as it is,
// and a restart does it no more.
func TestRepairCorrectsAlertsRaisedByOwnAuditEvents(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	rule5 := ruleByName(t, repo, "Mass ingestion of late logs")
	t0 := time.Now().Add(-48 * time.Hour)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	auditEvent(t, w, repo, at(0), "ingest.late", "Mass ingestion of late logs: 481 events from DealTracker - Prod01")
	auditEvent(t, w, repo, at(10), "alert.closed", "JD Waters closed the alert Mass ingestion of late logs")
	auditEvent(t, w, repo, at(20), "alert.acknowledged", "JD Waters acknowledged the alert Mass ingestion of late logs")
	auditEvent(t, w, repo, at(30), "alert.closed", "JD Waters closed the alert Mass ingestion of late logs")
	auditEvent(t, w, repo, at(100), "ingest.late", "Mass ingestion of late logs: 90 events from another source") // a genuine second burst
	auditEvent(t, w, repo, at(105), "alert.acknowledged", "JD Waters acknowledged the alert Mass ingestion of late logs")
	auditEvent(t, w, repo, at(200), "ingest.late", "Mass ingestion of late logs: 55 events from a third source") // and a third
	w.Drain(ctx)
	insert := func(status string, count int64, first, last time.Time) int64 {
		res, err := repo.DB().Write.Exec(`INSERT INTO alerts (rule_id, rule_name, severity, group_by, group_value, status, count, first_seen, last_seen, created_at, updated_at)
			VALUES (?, ?, 4, '', '', ?, ?, ?, ?, 1, 1)`, rule5.ID, rule5.Name, status, count, first.UnixMilli(), last.UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	one := insert("closed", 2, at(0), at(10))   // the real event, and one audit event that matched the old phrase
	two := insert("open", 3, at(0), at(30))     // raised by audit events: its span reaches back over the real event, which alert 1 covers
	three := insert("closed", 1, at(0), at(20)) // closed already, raised the same way
	four := insert("open", 2, at(40), at(105))  // genuine (the second burst), count inflated by an audit event
	five := insert("open", 1, at(200), at(200)) // genuine and right: left alone
	fixed, err := eng.RepairSelfTriggered(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]storage.Alert{}
	list, _, _ := repo.ListAlerts(ctx, "", 50)
	for _, a := range list {
		byID[a.ID] = a
	}
	if a := byID[one]; a.Count != 1 || a.Status != "closed" {
		t.Errorf("the alert with the real event: %+v (want count 1, status unchanged)", a)
	}
	if a := byID[two]; a.Count != 0 || a.Status != "closed" || a.UpdatedBy != "SIEMLite" {
		t.Errorf("the alert made only by audit events: %+v (want closed by SIEMLite, count 0)", a)
	}
	if a := byID[three]; a.Count != 0 || a.Status != "closed" || a.UpdatedBy == "SIEMLite" {
		t.Errorf("the alert that was already closed: %+v (want its count corrected and nothing else)", a)
	}
	if a := byID[four]; a.Count != 1 || a.Status != "open" {
		t.Errorf("a genuine alert with an inflated count: %+v (want count 1, still open)", a)
	}
	if a := byID[five]; a.Count != 1 || a.Status != "open" || a.UpdatedAt != 1 {
		t.Errorf("a genuine alert that was right: %+v (want it untouched)", a)
	}
	closed := 0
	for _, f := range fixed {
		if f.Closed {
			closed++
		}
	}
	if len(fixed) != 4 || closed != 1 {
		t.Errorf("repairs = %+v (want 4, one of them a close)", fixed)
	}
	// Once per database.
	if again, err := eng.RepairSelfTriggered(ctx); err != nil || len(again) != 0 {
		t.Errorf("a second run = %+v, %v", again, err)
	}
	// Other rules' alerts are left alone.
	other, _ := repo.SaveRule(ctx, storage.Rule{Name: "Other", Enabled: true, Severity: 3, Query: "x", Threshold: 1, WindowMinutes: 5}, 1)
	if _, err := repo.DB().Write.Exec(`INSERT INTO alerts (rule_id, rule_name, severity, status, count, first_seen, last_seen, created_at, updated_at) VALUES (?, 'Other', 3, 'open', 7, 1, 2, 1, 1)`, other); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB().Write.Exec(`DELETE FROM settings WHERE key = ?`, repairKey); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RepairSelfTriggered(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alertsByRule(t, repo)["Other"]; len(got) != 1 || got[0].Count != 7 || got[0].Status != "open" {
		t.Errorf("another rule's alert was touched: %+v", got)
	}
}

// A volume rule watching the INTERNAL source doesn't count the audit of managing alerts: closing the alert it
// raised would otherwise push the count over its threshold again.
func TestVolumeRuleOnInternalIgnoresAlertAudit(t *testing.T) {
	repo, w, eng := setup(t)
	ctx := context.Background()
	internal, err := repo.BuiltinSource(ctx, storage.SourceInternal)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	eng.now = func() time.Time { return now }
	eng.started = now.Add(-time.Hour)
	if _, err := repo.SaveRule(ctx, storage.Rule{Name: "Busy audit log", Kind: storage.RuleVolumeOver, Enabled: true, Severity: 3, SourceID: &internal.ID,
		Threshold: 3, WindowMinutes: 10}, now.Add(-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	auditEvent(t, w, repo, now, "signin", "ann signed in")
	for i, action := range []string{"alert.acknowledged", "alert.closed", "alert.open", "alert.closed"} {
		auditEvent(t, w, repo, now.Add(-time.Duration(i+1)*time.Second), action, "ann managed the alert Busy audit log")
	}
	w.Drain(ctx)
	if _, err := eng.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if got := alertsByRule(t, repo)["Busy audit log"]; len(got) != 0 {
		t.Fatalf("a volume rule counted the audit of managing alerts: %+v", got)
	}
	for i := 0; i < 3; i++ { // three real audit events more: now it is over
		auditEvent(t, w, repo, now.Add(-time.Duration(10+i)*time.Second), "signin", "bob signed in")
	}
	w.Drain(ctx)
	eng.Check(ctx)
	if got := alertsByRule(t, repo)["Busy audit log"]; len(got) != 1 || got[0].Count != 4 {
		t.Errorf("with real events over the threshold: %+v (want one alert counting 4)", got)
	}
}
