package api_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/report"
	"siemlite/pkg/storage"
)

// Reports: admins make a summary and a PDF, keep and download it, and manage schedules.
func TestReports(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) { d.Reports = report.New(d.Repo, nil, d.Audit, "v-test", nil) })
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)

	for _, path := range []string{"/api/v1/reports/summary?days=7", "/api/v1/reports/runs", "/api/v1/reports/schedules"} {
		if got := e.call(ann, "GET", path, nil, nil, nil); got != 403 {
			t.Errorf("a standard user read %s: %d", path, got)
		}
	}
	if got := e.call(root, "GET", "/api/v1/reports/summary", nil, nil, nil); got != 400 {
		t.Errorf("a summary with no period: %d", got)
	}
	if got := e.call(root, "GET", "/api/v1/reports/summary?days=9999", nil, nil, nil); got != 400 {
		t.Errorf("a summary of 9999 days: %d", got)
	}
	var sum report.Data
	if got := e.call(root, "GET", "/api/v1/reports/summary?days=7", nil, &sum, nil); got != 200 || sum.Version != "v-test" || sum.End <= sum.Start {
		t.Fatalf("summary = %d %+v", got, sum)
	}

	var run storage.ReportRun
	if got := e.call(root, "POST", "/api/v1/reports/runs", map[string]int{"days": 7}, &run, nil); got != 201 || run.ID == 0 || run.Size == 0 {
		t.Fatalf("make = %d %+v", got, run)
	}
	res, err := root.Get(e.srv.URL + fmt.Sprintf("/api/v1/reports/runs/%d/pdf", run.ID))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(string(body), "%PDF-") ||
		!strings.Contains(res.Header.Get("Content-Disposition"), "attachment") || !strings.Contains(res.Header.Get("Content-Disposition"), ".pdf") {
		t.Errorf("download = %d %v, %d bytes", res.StatusCode, res.Header, len(body))
	}
	var runs []storage.ReportRun
	if got := e.call(root, "GET", "/api/v1/reports/runs", nil, &runs, nil); got != 200 || len(runs) != 1 {
		t.Errorf("runs = %d %+v", got, runs)
	}

	// Schedules.
	bad := map[string]any{"name": "", "frequency": "weekly", "hour": 8, "covers_days": 7}
	if got := e.call(root, "POST", "/api/v1/reports/schedules", bad, nil, nil); got != 400 {
		t.Errorf("a nameless schedule: %d", got)
	}
	var sc storage.ReportSchedule
	good := map[string]any{"name": "Weekly", "frequency": "weekly", "weekday": 1, "hour": 8, "covers_days": 7, "recipients": "soc@example.com"}
	if got := e.call(root, "POST", "/api/v1/reports/schedules", good, &sc, nil); got != 201 || sc.ID == 0 || !sc.Enabled || sc.NextRun == 0 {
		t.Fatalf("create schedule = %d %+v", got, sc)
	}
	good["name"], good["enabled"] = "Weekly 2", false
	if got := e.call(root, "PUT", fmt.Sprintf("/api/v1/reports/schedules/%d", sc.ID), good, &sc, nil); got != 200 || sc.Name != "Weekly 2" || sc.Enabled {
		t.Errorf("update = %d %+v", got, sc)
	}
	var list struct {
		Schedules  []storage.ReportSchedule
		EmailReady bool `json:"email_ready"`
	}
	if got := e.call(root, "GET", "/api/v1/reports/schedules", nil, &list, nil); got != 200 || len(list.Schedules) != 1 || list.EmailReady {
		t.Errorf("list = %d %+v", got, list)
	}
	var ran storage.ReportRun
	if got := e.call(root, "POST", fmt.Sprintf("/api/v1/reports/schedules/%d/run", sc.ID), nil, &ran, nil); got != 201 || ran.Size == 0 || !strings.Contains(ran.Note, "email") {
		t.Errorf("run now = %d %+v", got, ran)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/reports/schedules/%d", sc.ID), nil, nil, nil); got != 204 {
		t.Errorf("delete schedule = %d", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/reports/schedules/%d", sc.ID), nil, nil, nil); got != 404 {
		t.Errorf("delete again = %d", got)
	}
	// The reports a deleted schedule made stay; a report can be deleted by itself.
	e.call(root, "GET", "/api/v1/reports/runs", nil, &runs, nil)
	if len(runs) != 2 {
		t.Fatalf("runs after deleting the schedule = %d", len(runs))
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/reports/runs/%d", runs[0].ID), nil, nil, nil); got != 204 {
		t.Errorf("delete report = %d", got)
	}
	if got := e.call(root, "GET", fmt.Sprintf("/api/v1/reports/runs/%d/pdf", runs[0].ID), nil, nil, nil); got != 404 {
		t.Errorf("download a deleted report = %d", got)
	}
}
