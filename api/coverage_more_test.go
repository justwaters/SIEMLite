package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/chatnotify"
	"siemlite/pkg/integrations"
	"siemlite/pkg/intel"
	"siemlite/pkg/report"
)

// offline is an HTTP transport that fails at once, so no test ever reaches a real feed or webhook.
type offline struct{}

func (offline) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("offline") }

// gated blocks every request until release is closed.
type gated struct{ release chan struct{} }

func (g gated) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case <-g.release:
	case <-r.Context().Done():
	}
	return nil, errors.New("offline")
}

// fullDeps gives the server threat intel, reports and both chat services, none of which can reach the network.
func fullDeps(t testing.TB, rt http.RoundTripper) func(*api.Deps) {
	return func(d *api.Deps) {
		d.Intel = intel.NewService(d.Repo, intel.Config{HTTPClient: &http.Client{Transport: rt}})
		d.Reports = report.New(d.Repo, nil, d.Audit, "v-test", nil)
		d.Slack = chatnotify.New(chatnotify.Slack, d.Repo, filepath.Join(t.TempDir(), "k"))
		d.Teams = chatnotify.New(chatnotify.Teams, d.Repo, filepath.Join(t.TempDir(), "k2"))
		d.Slack.Client = &http.Client{Transport: offline{}}
		d.Teams.Client = &http.Client{Transport: offline{}}
		d.Integrations = integrations.New(d.Slack, d.Teams)
	}
}

// raw sends a body exactly as given and returns the status and body text.
func (e *env) raw(c *http.Client, method, path, body string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestActivityShowsFeedDownloads(t *testing.T) {
	g := gated{release: make(chan struct{})}
	e := newEnvWith(t, fullDeps(t, g))
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	defer close(g.release)

	if got := e.call(root, "PUT", "/api/v1/intel/feeds", map[string][]string{"feeds": {"feodo"}}, nil, nil); got != 200 {
		t.Fatalf("choose feeds = %d", got)
	}
	var out struct{ Tasks []api.Task }
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out.Tasks = nil
		e.call(root, "GET", "/api/v1/activity", nil, &out, nil)
		if len(out.Tasks) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(out.Tasks) != 1 || out.Tasks[0].ID != "feeds" || out.Tasks[0].Total != 1 || !strings.Contains(out.Tasks[0].Detail, "1 of 1") {
		t.Errorf("tasks = %+v", out.Tasks)
	}
	// A refresh asked for while one runs is accepted and dropped.
	var st map[string]string
	if got := e.call(root, "POST", "/api/v1/intel/feeds/refresh", nil, &st, nil); got != 202 || st["status"] != "started" {
		t.Errorf("refresh = %d %v", got, st)
	}
}

func TestThreatFeedErrors(t *testing.T) {
	e := newEnvWith(t, fullDeps(t, offline{}))
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	const p = "/api/v1/intel/feeds"

	for name, body := range map[string]string{
		"not json": "{nope", "empty": "", "wrong type": `{"feeds":"feodo"}`, "numbers": `{"feeds":[1,2]}`,
		"null entry": `{"feeds":[null]}`, "oversize": `{"feeds":["` + strings.Repeat("a", 2<<10) + `"]}`,
	} {
		if got, b := e.raw(root, "PUT", p, body); got != 400 {
			t.Errorf("%s: %d %s", name, got, b)
		}
	}
	for _, body := range []string{`{"feeds":["bogus"]}`, `{"feeds":["feodo","nope"]}`, `{"feeds":["custom:x"]}`, `{"feeds":["` + strings.Repeat("a", 500) + `"]}`} {
		if got, b := e.raw(root, "PUT", p, body); got != 400 {
			t.Errorf("%s: %d %s", body[:20], got, b)
		}
	}
	// Choosing none, and null, are valid and clear the choice; duplicates are kept once.
	for _, body := range []string{`{"feeds":[]}`, `{"feeds":null}`, `{}`} {
		var v intel.FeedsView
		if got := e.call(root, "PUT", p, json.RawMessage(body), &v, nil); got != 200 || len(v.Feeds) == 0 {
			t.Errorf("%s: %d", body, got)
		}
		for _, f := range v.Feeds {
			if f.Selected {
				t.Errorf("%s left %s chosen", body, f.ID)
			}
		}
	}
	var v intel.FeedsView
	if got := e.call(root, "PUT", p, map[string][]string{"feeds": {"feodo", "feodo", "tor-exit"}}, &v, nil); got != 200 {
		t.Fatalf("save = %d", got)
	}
	n := 0
	for _, f := range v.Feeds {
		if f.Selected {
			n++
		}
	}
	if n != 2 {
		t.Errorf("chosen = %d, want 2", n)
	}
	// An unreachable feed shows its error on the page rather than failing the request.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.call(root, "GET", p, nil, &v, nil)
		bad := 0
		for _, f := range v.Feeds {
			if f.Selected && f.Error != "" {
				bad++
			}
		}
		if bad == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("failed downloads weren't reported: %+v", v.Feeds[:3])
}

func TestThreatFeedsNeedIntel(t *testing.T) {
	e := newEnv(t) // no Intel
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	for _, c := range [][2]string{{"GET", "/api/v1/intel/feeds"}, {"PUT", "/api/v1/intel/feeds"}, {"POST", "/api/v1/intel/feeds/refresh"},
		{"POST", "/api/v1/intel/friendly"}, {"PATCH", "/api/v1/intel/friendly/1"}, {"DELETE", "/api/v1/intel/friendly/1"},
		{"POST", "/api/v1/intel/friendly/1/entries"}, {"DELETE", "/api/v1/intel/friendly/1/entries"}} {
		if got, _ := e.raw(root, c[0], c[1], `{"name":"x","feeds":[]}`); got != 501 {
			t.Errorf("%s %s without intel = %d", c[0], c[1], got)
		}
	}
	// Activity needs nothing and reports nothing running.
	var out struct{ Tasks []api.Task }
	if got := e.call(root, "GET", "/api/v1/activity", nil, &out, nil); got != 200 || out.Tasks == nil || len(out.Tasks) != 0 {
		t.Errorf("activity = %d %+v", got, out)
	}
}

func TestFriendlyErrors(t *testing.T) {
	e := newEnvWith(t, fullDeps(t, offline{}))
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	const p = "/api/v1/intel/friendly"

	var a, b struct{ ID int64 }
	e.call(root, "POST", p, map[string]string{"name": "A"}, &a, nil)
	e.call(root, "POST", p, map[string]string{"name": "B", "description": "second"}, &b, nil)
	if a.ID == 0 || b.ID == 0 {
		t.Fatal("lists weren't made")
	}
	one := fmt.Sprintf("%s/%d", p, a.ID)
	two := fmt.Sprintf("%s/%d", p, b.ID)

	long := strings.Repeat("é", 61)
	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"create not json":       {"POST", p, "{", 400},
		"create long name":      {"POST", p, `{"name":"` + long + `"}`, 400},
		"create long desc":      {"POST", p, `{"name":"x","description":"` + strings.Repeat("d", 301) + `"}`, 400},
		"create oversize":       {"POST", p, `{"name":"` + strings.Repeat("a", 2<<10) + `"}`, 400},
		"create wrong type":     {"POST", p, `{"name":5}`, 400},
		"create dup (case)":     {"POST", p, `{"name":"A"}`, 409},
		"update not json":       {"PATCH", one, "x", 400},
		"update empty name":     {"PATCH", one, `{"name":"  "}`, 400},
		"update long name":      {"PATCH", one, `{"name":"` + long + `"}`, 400},
		"update unknown id":     {"PATCH", p + "/99999", `{"name":"Z"}`, 404},
		"update taken name":     {"PATCH", one, `{"name":"B"}`, 409},
		"update bad id":         {"PATCH", p + "/abc", `{"name":"Z"}`, 400},
		"update zero id":        {"PATCH", p + "/0", `{"name":"Z"}`, 400},
		"update negative id":    {"PATCH", p + "/-4", `{"name":"Z"}`, 400},
		"update huge id":        {"PATCH", p + "/99999999999999999999", `{"name":"Z"}`, 400},
		"delete bad id":         {"DELETE", p + "/x", "", 400},
		"delete unknown":        {"DELETE", p + "/99999", "", 404},
		"entries not json":      {"POST", one + "/entries", "[", 400},
		"entries empty":         {"POST", one + "/entries", `{"values":" ,\n "}`, 400},
		"entries missing":       {"POST", one + "/entries", `{}`, 400},
		"entries wrong type":    {"POST", one + "/entries", `{"values":["1.2.3.4"]}`, 400},
		"entries long note":     {"POST", one + "/entries", `{"values":"1.2.3.4","note":"` + strings.Repeat("n", 201) + `"}`, 400},
		"entries bad value":     {"POST", one + "/entries", `{"values":"1.2.3.4 999.1.1.1"}`, 400},
		"entries unknown list":  {"POST", p + "/99999/entries", `{"values":"1.2.3.4"}`, 404},
		"entries bad id":        {"POST", p + "/0/entries", `{"values":"1.2.3.4"}`, 400},
		"entries oversize body": {"POST", one + "/entries", `{"values":"` + strings.Repeat("1.2.3.4\n", 40<<10) + `"}`, 400},
		"remove no value":       {"DELETE", one + "/entries", "", 404},
		"remove unknown value":  {"DELETE", one + "/entries?value=1.1.1.1", "", 404},
		"remove bad id":         {"DELETE", p + "/q/entries?value=1.1.1.1", "", 400},
	} {
		if got, body := e.raw(root, tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s: %d, want %d (%.100s)", name, got, tc.want, body)
		}
	}
	// A rename that changes only the case of its own name is allowed, and the description is kept trimmed.
	if got, b := e.raw(root, "PATCH", one, `{"name":"  a  ","description":"  hq "}`); got != 204 {
		t.Errorf("rename own = %d %s", got, b)
	}
	var lists []struct {
		ID          int64
		Name        string
		Description string
	}
	e.call(root, "GET", p, nil, &lists, nil)
	for _, l := range lists {
		if l.ID == a.ID && (l.Name != "a" || l.Description != "hq") {
			t.Errorf("stored %+v", l)
		}
		if l.ID == b.ID && l.Name != "B" {
			t.Errorf("another list changed: %+v", l)
		}
	}
	// Too many entries are refused whole.
	var vals []string
	for i := 0; i < intel.MaxFriendlyAdd+1; i++ {
		vals = append(vals, fmt.Sprintf("10.%d.%d.1", i/250, i%250))
	}
	if got, b := e.raw(root, "POST", two+"/entries", mustJSON(map[string]string{"values": strings.Join(vals, " ")})); got != 400 || !strings.Contains(b, "at a time") {
		t.Errorf("a huge add: %d %.100s", got, b)
	}
	// Seven bad words are reported five at a time.
	if got, b := e.raw(root, "POST", two+"/entries", `{"values":"a b c d e f g"}`); got != 400 || !strings.Contains(b, "…") {
		t.Errorf("many bad: %d %s", got, b)
	}
	// More than five good ones are added and the audit message trails off.
	if got, b := e.raw(root, "POST", two+"/entries", `{"values":"10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6"}`); got != 200 || !strings.Contains(b, `"added":6`) {
		t.Errorf("six: %d %s", got, b)
	}
	// Lists are capped.
	for i := 0; ; i++ {
		got, _ := e.raw(root, "POST", p, fmt.Sprintf(`{"name":"L%d"}`, i))
		if got == 400 {
			break
		}
		if got != 201 || i > intel.MaxFriendlyLists+2 {
			t.Fatalf("filling the lists: %d at %d", got, i)
		}
	}
}

func manyAddrs() string {
	var a []string
	for i := 0; i < 80; i++ {
		a = append(a, fmt.Sprintf("u%d@example.com", i))
	}
	return strings.Join(a, ",")
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestReportErrors(t *testing.T) {
	e := newEnvWith(t, fullDeps(t, offline{}))
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	const runs, sch = "/api/v1/reports/runs", "/api/v1/reports/schedules"
	now := time.Now().UnixMilli()

	for name, tc := range map[string]struct {
		method, path, body string
		want               int
	}{
		"make not json":       {"POST", runs, "{", 400},
		"make empty":          {"POST", runs, `{}`, 400},
		"make null":           {"POST", runs, `null`, 400},
		"make zero days":      {"POST", runs, `{"days":0}`, 400},
		"make negative days":  {"POST", runs, `{"days":-3}`, 400},
		"make huge days":      {"POST", runs, `{"days":999999}`, 400},
		"make overflow days":  {"POST", runs, `{"days":99999999999999999999}`, 400},
		"make fraction days":  {"POST", runs, `{"days":1.5}`, 400},
		"make string days":    {"POST", runs, `{"days":"7"}`, 400},
		"make reversed range": {"POST", runs, fmt.Sprintf(`{"from":%d,"to":%d}`, now, now-1000), 400},
		"make only from":      {"POST", runs, fmt.Sprintf(`{"from":%d}`, now), 400},
		"make oversize":       {"POST", runs, `{"days":1,"x":"` + strings.Repeat("a", 2<<10) + `"}`, 400},
		"summary bad days":    {"GET", "/api/v1/reports/summary?days=abc", "", 400},
		"summary neg days":    {"GET", "/api/v1/reports/summary?days=-1", "", 400},
		"summary reversed":    {"GET", fmt.Sprintf("/api/v1/reports/summary?from=%d&to=%d", now, now-5), "", 400},
		"download bad id":     {"GET", runs + "/x/pdf", "", 400},
		"download zero id":    {"GET", runs + "/0/pdf", "", 400},
		"download unknown":    {"GET", runs + "/424242/pdf", "", 404},
		"delete bad id":       {"DELETE", runs + "/-1", "", 400},
		"delete unknown":      {"DELETE", runs + "/424242", "", 404},
		"sched create bad":    {"POST", sch, "nope", 400},
		"sched oversize":      {"POST", sch, `{"name":"` + strings.Repeat("a", 9<<10) + `"}`, 400},
		"sched wrong type":    {"POST", sch, `{"name":1}`, 400},
		"sched bad hour":      {"POST", sch, `{"name":"x","frequency":"daily","hour":24,"covers_days":1}`, 400},
		"sched negative hour": {"POST", sch, `{"name":"x","frequency":"daily","hour":-1,"covers_days":1}`, 400},
		"sched bad freq":      {"POST", sch, `{"name":"x","frequency":"hourly","hour":1,"covers_days":1}`, 400},
		"sched bad weekday":   {"POST", sch, `{"name":"x","frequency":"weekly","weekday":7,"hour":1,"covers_days":7}`, 400},
		"sched bad dom":       {"POST", sch, `{"name":"x","frequency":"monthly","day_of_month":29,"hour":1,"covers_days":30}`, 400},
		"sched bad cover":     {"POST", sch, `{"name":"x","frequency":"daily","hour":1,"covers_days":5}`, 400},
		"sched long name":     {"POST", sch, `{"name":"` + strings.Repeat("a", 81) + `","frequency":"daily","hour":1,"covers_days":1}`, 400},
		"sched bad email":     {"POST", sch, `{"name":"x","frequency":"daily","hour":1,"covers_days":1,"recipients":"not-an-address"}`, 400},
		"sched many emails":   {"POST", sch, `{"name":"x","frequency":"daily","hour":1,"covers_days":1,"recipients":"` + manyAddrs() + `"}`, 400},
		"sched update bad id": {"PUT", sch + "/x", `{}`, 400},
		"sched update 404":    {"PUT", sch + "/9999", `{"name":"x","frequency":"daily","hour":1,"covers_days":1}`, 404},
		"sched update bad":    {"PUT", sch + "/9999", `{`, 400},
		"sched delete bad":    {"DELETE", sch + "/0", "", 400},
		"sched delete 404":    {"DELETE", sch + "/9999", "", 404},
		"sched run bad id":    {"POST", sch + "/abc/run", "", 400},
		"sched run 404":       {"POST", sch + "/9999/run", "", 404},
	} {
		if got, b := e.raw(root, tc.method, tc.path, tc.body); got != tc.want {
			t.Errorf("%s: %d, want %d (%.100s)", name, got, tc.want, b)
		}
	}
	// Reports by date range and by days both work; nothing stray was kept by the failures above.
	var run struct{ ID int64 }
	if got := e.call(root, "POST", runs, map[string]int64{"from": now - 3600_000, "to": now}, &run, nil); got != 201 || run.ID == 0 {
		t.Errorf("range report = %d %+v", got, run)
	}
	var list []struct{ ID int64 }
	if e.call(root, "GET", runs, nil, &list, nil); len(list) != 1 {
		t.Errorf("reports kept = %d, want 1", len(list))
	}
	// Schedule limits: a duplicate-free set of 20, then refused; ids in a body can't pick another row.
	body := map[string]any{"name": "s", "frequency": "daily", "hour": 3, "covers_days": 1, "id": 777, "enabled": false, "next_run": 5}
	var made struct {
		ID      int64
		Enabled bool
		NextRun int64 `json:"next_run"`
	}
	if got := e.call(root, "POST", sch, body, &made, nil); got != 201 || made.ID == 777 || !made.Enabled || made.NextRun <= now {
		t.Errorf("create ignoring client fields: %d %+v", got, made)
	}
	for i := 1; i < 20; i++ {
		if got := e.call(root, "POST", sch, body, nil, nil); got != 201 {
			t.Fatalf("schedule %d = %d", i, got)
		}
	}
	if got, b := e.raw(root, "POST", sch, mustJSON(body)); got != 400 || !strings.Contains(b, "20 schedules") {
		t.Errorf("21st schedule: %d %s", got, b)
	}
	// Run now: the report is made, emailing is skipped without an Email integration, the schedule is untouched.
	var ran struct {
		ID   int64
		Note string
	}
	if got := e.call(root, "POST", fmt.Sprintf("%s/%d/run", sch, made.ID), nil, &ran, nil); got != 201 || ran.ID == 0 {
		t.Errorf("run = %d %+v", got, ran)
	}
	var after struct {
		Schedules []struct {
			ID      int64
			NextRun int64 `json:"next_run"`
		}
	}
	e.call(root, "GET", sch, nil, &after, nil)
	for _, s := range after.Schedules {
		if s.ID == made.ID && s.NextRun != made.NextRun {
			t.Errorf("run-now moved the next run: %d -> %d", made.NextRun, s.NextRun)
		}
	}
}

func TestReportsNeedService(t *testing.T) {
	e := newEnv(t) // no Reports
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	for _, c := range [][2]string{{"GET", "/api/v1/reports/summary?days=1"}, {"POST", "/api/v1/reports/runs"}, {"GET", "/api/v1/reports/runs"},
		{"GET", "/api/v1/reports/runs/1/pdf"}, {"DELETE", "/api/v1/reports/runs/1"}, {"GET", "/api/v1/reports/schedules"},
		{"POST", "/api/v1/reports/schedules"}, {"PUT", "/api/v1/reports/schedules/1"}, {"DELETE", "/api/v1/reports/schedules/1"},
		{"POST", "/api/v1/reports/schedules/1/run"}} {
		if got, _ := e.raw(root, c[0], c[1], `{}`); got != 501 {
			t.Errorf("%s %s without reports = %d", c[0], c[1], got)
		}
	}
}

func TestChatIntegrationErrors(t *testing.T) {
	e := newEnvWith(t, fullDeps(t, offline{}))
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	for _, svc := range []string{"slack", "teams"} {
		p := "/api/v1/integrations/" + svc
		for name, tc := range map[string]struct {
			method, path, body string
			want               int
		}{
			"save not json":      {"PUT", p, "{", 400},
			"save wrong type":    {"PUT", p, `{"webhook":5}`, 400},
			"save http":          {"PUT", p, `{"webhook":"http://example.com/x","min_severity":1}`, 400},
			"save wrong host":    {"PUT", p, `{"webhook":"https://example.com/x","min_severity":1}`, 400},
			"save not a url":     {"PUT", p, `{"webhook":"%%%","min_severity":1}`, 400},
			"save oversize":      {"PUT", p, `{"webhook":"https://` + strings.Repeat("a", 9<<10) + `"}`, 400},
			"test not json":      {"POST", p + "/test", "x", 400},
			"test empty":         {"POST", p + "/test", `{"webhook":""}`, 400},
			"test wrong host":    {"POST", p + "/test", `{"webhook":"https://example.com/x"}`, 400},
			"test oversize body": {"POST", p + "/test", `{"webhook":"` + strings.Repeat("a", 9<<10) + `"}`, 400},
		} {
			if got, b := e.raw(root, tc.method, tc.path, tc.body); got != tc.want {
				t.Errorf("%s %s: %d, want %d (%.100s)", svc, name, got, tc.want, b)
			}
		}
		// Nothing bad was saved.
		var v chatnotify.View
		if got := e.call(root, "GET", p, nil, &v, nil); got != 200 || v.Configured {
			t.Errorf("%s after bad saves: %d %+v", svc, got, v)
		}
		// With no address saved, a severity alone is refused.
		if got := e.call(root, "PUT", p, map[string]int{"min_severity": 3}, nil, nil); got != 400 {
			t.Errorf("%s severity with no address: %d", svc, got)
		}
		hook := `https://hooks.slack.com/services/T/B/X`
		if svc == "teams" {
			hook = `https://prod-00.westus.logic.azure.com/workflows/x`
		}
		if got := e.call(root, "PUT", p, map[string]any{"webhook": hook, "min_severity": 3}, &v, nil); got != 200 || !v.Configured || v.MinSeverity != 3 {
			t.Fatalf("%s save = %d %+v", svc, got, v)
		}
		// Leaving the address out keeps it; odd severities never break the stored value.
		for _, sev := range []int{-1, 6, 1 << 40} {
			got := e.call(root, "PUT", p, map[string]int{"min_severity": sev}, &v, nil)
			if got >= 500 || (got == 200 && (!v.Configured || v.MinSeverity < 0 || v.MinSeverity > 5)) {
				t.Errorf("%s severity %d: %d %+v", svc, sev, got, v)
			}
		}
		// "" removes the address.
		if got := e.call(root, "PUT", p, map[string]any{"webhook": "", "min_severity": 3}, &v, nil); got != 200 || v.Configured {
			t.Errorf("%s removing the address: %d %+v", svc, got, v)
		}
	}
	// A real-looking address on the right host that can't be reached is a gateway failure, not a crash.
	if got, b := e.raw(root, "POST", "/api/v1/integrations/slack/test", `{"webhook":"https://hooks.slack.com/services/T/B/X"}`); got != 502 {
		t.Errorf("unreachable webhook = %d %s", got, b)
	}
}

// Every admin-only endpoint turns away a visitor who isn't signed in (401), a standard user (403) and an API key (403),
// and doesn't do the work for them.
func TestNewEndpointsAccessMatrix(t *testing.T) {
	e := newEnvWith(t, fullDeps(t, offline{}))
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	ann, anon := e.client(), e.client()
	e.login(ann, "ann", password)
	_, key, _ := auth.CreateKey(context.Background(), e.repo, "app", nil, false)

	type ep struct{ method, path, body string }
	eps := []ep{
		{"GET", "/api/v1/intel/feeds", ""}, {"PUT", "/api/v1/intel/feeds", `{"feeds":["feodo"]}`}, {"POST", "/api/v1/intel/feeds/refresh", ""},
		{"GET", "/api/v1/intel/friendly", ""}, {"POST", "/api/v1/intel/friendly", `{"name":"x"}`}, {"PATCH", "/api/v1/intel/friendly/1", `{"name":"x"}`},
		{"DELETE", "/api/v1/intel/friendly/1", ""}, {"POST", "/api/v1/intel/friendly/1/entries", `{"values":"1.2.3.4"}`}, {"DELETE", "/api/v1/intel/friendly/1/entries?value=1.2.3.4", ""},
		{"GET", "/api/v1/reports/summary?days=1", ""}, {"POST", "/api/v1/reports/runs", `{"days":1}`}, {"GET", "/api/v1/reports/runs", ""},
		{"GET", "/api/v1/reports/runs/1/pdf", ""}, {"DELETE", "/api/v1/reports/runs/1", ""}, {"GET", "/api/v1/reports/schedules", ""},
		{"POST", "/api/v1/reports/schedules", `{"name":"x","frequency":"daily","hour":1,"covers_days":1}`},
		{"PUT", "/api/v1/reports/schedules/1", `{"name":"x","frequency":"daily","hour":1,"covers_days":1}`}, {"DELETE", "/api/v1/reports/schedules/1", ""},
		{"POST", "/api/v1/reports/schedules/1/run", ""}, {"GET", "/api/v1/activity", ""},
	}
	for _, svc := range []string{"slack", "teams"} {
		p := "/api/v1/integrations/" + svc
		eps = append(eps, ep{"GET", p, ""}, ep{"PUT", p, `{"min_severity":1}`}, ep{"POST", p + "/test", `{"webhook":"https://hooks.slack.com/services/x"}`})
	}
	for _, x := range eps {
		if got, _ := e.raw(anon, x.method, x.path, x.body); got != 401 {
			t.Errorf("anonymous %s %s = %d, want 401", x.method, x.path, got)
		}
		if got, _ := e.raw(ann, x.method, x.path, x.body); got != 403 {
			t.Errorf("standard user %s %s = %d, want 403", x.method, x.path, got)
		}
		req, _ := http.NewRequest(x.method, e.srv.URL+x.path, strings.NewReader(x.body))
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := anon.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 && resp.StatusCode != 403 {
			t.Errorf("api key %s %s = %d, want 401/403", x.method, x.path, resp.StatusCode)
		}
	}
	// Nothing happened as a result.
	if lists, _ := e.repo.FriendlyLists(context.Background()); len(lists) != 0 {
		t.Errorf("a refused request made a list: %+v", lists)
	}
	var runs []struct{}
	root := e.client()
	e.login(root, "root", password)
	e.call(root, "GET", "/api/v1/reports/runs", nil, &runs, nil)
	if len(runs) != 0 {
		t.Errorf("a refused request made a report")
	}
	_ = httptest.NewRecorder
}
