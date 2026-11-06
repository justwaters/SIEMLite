package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"siemlite/api"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/retention"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
)

func TestRetentionSetting(t *testing.T) {
	ctx := context.Background()
	e := newEnvWith(t, func(d *api.Deps) {
		d.Retention = retention.New(d.Repo, retention.Config{RetentionDays: retention.DefaultDays})
	})
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root, sam := e.client(), e.client()
	e.login(root, "root", password)
	e.login(sam, "sam", password)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/retention", nil, &v, nil); got != 200 || v["days"] != float64(730) || v["saved"] != false ||
		v["late_after_days"] != float64(30) || v["late_burst"] != float64(50) {
		t.Fatalf("get = %d %v", got, v)
	}
	if got := e.call(sam, "PUT", "/api/v1/system/retention", map[string]int{"days": 30}, nil, nil); got != 403 {
		t.Errorf("standard user = %d", got)
	}
	for _, bad := range []int{0, -5, 3651} {
		if got := e.call(root, "PUT", "/api/v1/system/retention", map[string]int{"days": bad}, nil, nil); got != 400 {
			t.Errorf("%d days = %d", bad, got)
		}
	}
	// An event 100 days old is kept for two years...
	old := time.Now().AddDate(0, 0, -100)
	if err := e.worker.Submit(ctx, &ocsf.Event{Time: old.UnixMilli(), CategoryUID: 6, ClassUID: 6003, SeverityID: 1, RawData: "an old event"}); err != nil {
		t.Fatal(err)
	}
	e.worker.Drain(ctx)
	count := func() int {
		var res struct{ Count int }
		e.call(root, "GET", "/api/v1/search?q=%22an+old+event%22", nil, &res, nil)
		return res.Count
	}
	if count() != 1 {
		t.Fatal("the old event wasn't stored")
	}
	// ...and deleted at once when the period is shortened below its age.
	if got := e.call(root, "PUT", "/api/v1/system/retention", map[string]int{"days": 30}, &v, nil); got != 200 || v["days"] != float64(30) || v["saved"] != true || v["cleaning"] != true {
		t.Fatalf("shorten = %d %v", got, v)
	}
	deadline := time.Now().Add(5 * time.Second)
	for count() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if count() != 0 {
		t.Error("the old event survived shortening the period")
	}
	// New events older than the period are refused now.
	if err := e.worker.Submit(ctx, &ocsf.Event{Time: time.Now().AddDate(0, 0, -40).UnixMilli(), CategoryUID: 6, ClassUID: 6003, SeverityID: 1, RawData: "x"}); err == nil {
		t.Error("a 40-day-old event was accepted with a 30-day period")
	}
	v = nil
	if got := e.call(root, "PUT", "/api/v1/system/retention", map[string]int{"days": 365}, &v, nil); got != 200 || v["cleaning"] == true {
		t.Errorf("lengthen = %d %v", got, v)
	}
}

// TestMassIngestionOfLateLogsRaisesAnAlert: 50 or more events more than 30
// days old from one source raise one High alert; the events keep their own
// severity and their own dates.
func TestMassIngestionOfLateLogsRaisesAnAlert(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	srcID, _, err := auth.CreateKey(ctx, e.repo, "Deal Tracker", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var log *audit.Logger
	w := ingest.New(e.repo, ingest.Config{FlushInterval: 10 * time.Millisecond, MaxAge: 730 * 24 * time.Hour,
		OnLateBatch: func(b ingest.LateBatch) { log.LateBatch(ctx, "Deal Tracker", b, 730) }})
	defer w.Close()
	log = audit.New(w, sources.New(e.repo), nil)
	start := time.Now().AddDate(0, -3, 0)
	for i := 0; i < 60; i++ {
		ev := &ocsf.Event{Time: start.Add(time.Duration(i) * time.Hour).UnixMilli(), CategoryUID: 6, ClassUID: 6003, SeverityID: ocsf.SeverityLow, RawData: "an old deal event"}
		if err := w.SubmitWith(ctx, ev, ingest.SubmitOptions{SourceID: srcID}); err != nil {
			t.Fatal(err)
		}
	}
	w.EndLateBursts()
	w.Drain(ctx)
	if _, err := e.alerts.Check(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Alerts []storage.Alert `json:"alerts"`
	}
	e.call(root, "GET", "/api/v1/alerts?status=open", nil, &list, nil)
	var found *storage.Alert
	for i, a := range list.Alerts {
		if a.RuleName == "Mass ingestion of late logs" {
			found = &list.Alerts[i]
		}
	}
	if found == nil || found.Severity != ocsf.SeverityHigh {
		t.Fatalf("alerts = %+v", list.Alerts)
	}
	var res struct {
		Count  int
		Events []storage.Record
	}
	e.call(root, "GET", "/api/v1/search?q=%22mass+ingestion%22", nil, &res, nil)
	if res.Count != 1 || !strings.Contains(res.Events[0].Message, "60 events more than 30 days old from Deal Tracker, dated "+start.UTC().Format("2006-01-02")) {
		t.Errorf("audit event = %+v", res.Events)
	}
	e.call(root, "GET", "/api/v1/search?q=%22old+deal+event%22&limit=100", nil, &res, nil)
	if res.Count != 60 {
		t.Fatalf("old events stored = %d", res.Count)
	}
	for _, ev := range res.Events {
		if ev.SeverityID != ocsf.SeverityLow || ev.Timestamp > time.Now().AddDate(0, 0, -30).UnixMilli() {
			t.Errorf("an old event changed: severity %d, time %s", ev.SeverityID, time.UnixMilli(ev.Timestamp))
			break
		}
	}
}

// The System page's "keep original lines" setting: admins only, 0 to 87600 hours, 24 until saved.
func TestRawKeepSetting(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root, sam := e.client(), e.client()
	e.login(root, "root", password)
	e.login(sam, "sam", password)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/raw-retention", nil, &v, nil); got != 200 || v["hours"] != float64(24) || v["default"] != float64(24) || v["saved"] != false {
		t.Fatalf("get = %d %v", got, v)
	}
	if got := e.call(sam, "PUT", "/api/v1/system/raw-retention", map[string]int{"hours": 48}, nil, nil); got != 403 {
		t.Errorf("standard user = %d", got)
	}
	for _, bad := range []map[string]int{{"hours": -1}, {"hours": storage.MaxRawKeepHours + 1}, {}} {
		if got := e.call(root, "PUT", "/api/v1/system/raw-retention", bad, nil, nil); got != 400 {
			t.Errorf("%v = %d", bad, got)
		}
	}
	if got := e.call(root, "PUT", "/api/v1/system/raw-retention", map[string]int{"hours": 168}, &v, nil); got != 200 || v["hours"] != float64(168) || v["saved"] != true || v["cleaning"] == true {
		t.Fatalf("lengthen = %d %v", got, v)
	}
	if got := e.call(root, "PUT", "/api/v1/system/raw-retention", map[string]int{"hours": 0}, &v, nil); got != 200 || v["hours"] != float64(0) {
		t.Fatalf("forever = %d %v", got, v)
	}
	// Going from "always" to a time shortens it: lines past it are removed now.
	if got := e.call(root, "PUT", "/api/v1/system/raw-retention", map[string]int{"hours": 24}, &v, nil); got != 200 || v["cleaning"] != true {
		t.Fatalf("from always to 24 = %d %v", got, v)
	}
}
