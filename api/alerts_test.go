package api_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"siemlite/pkg/auth"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

// TestFailedSignInsRaiseAnAlert follows a password-guessing attempt from the
// audit log in INTERNAL through the built-in rule to an alert an analyst works.
func TestFailedSignInsRaiseAnAlert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	for i := 0; i < 5; i++ {
		expect(t, "wrong password", e.login(e.client(), "root", fmt.Sprintf("guess %d", i)), 401)
	}
	root := e.client()
	expect(t, "root login", e.login(root, "root", password), 200)
	if err := e.worker.Drain(ctx); err != nil {
		t.Fatal(err)
	}

	// Each attempt is an INTERNAL event with the action and caller's address.
	var res search.Result
	e.call(root, "GET", "/api/v1/search?q="+url.QueryEscape(`"sign-in failed"`), nil, &res, nil)
	if res.Count != 5 {
		t.Fatalf("audit events for failed sign-ins = %d, want 5", res.Count)
	}
	for _, ev := range res.Events {
		if ev.SourceName != "INTERNAL" || !strings.Contains(string(ev.Fields), `"action":"signin.failed"`) ||
			ev.SrcIP != "127.0.0.1" {
			t.Errorf("audit event = source %q, src %q, fields %s", ev.SourceName, ev.SrcIP, ev.Fields)
		}
	}

	if _, err := e.alerts.Check(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Alerts []storage.Alert `json:"alerts"`
		Counts map[string]int  `json:"counts"`
	}
	sam := e.client()
	e.login(sam, "sam", password)
	e.call(sam, "GET", "/api/v1/alerts?status=open", nil, &list, nil)
	if len(list.Alerts) != 1 || list.Alerts[0].RuleName != "Failed sign-ins to SIEMLite" ||
		list.Alerts[0].GroupValue != "127.0.0.1" || list.Alerts[0].Count != 5 {
		t.Fatalf("open alerts = %+v", list.Alerts)
	}
	id := list.Alerts[0].ID

	// A standard user may work alerts; bad statuses and ids are refused.
	path := fmt.Sprintf("/api/v1/alerts/%d", id)
	if got := e.call(sam, "PATCH", path, map[string]any{"status": "snoozed"}, nil, nil); got != 400 {
		t.Errorf("bad status = %d", got)
	}
	if got := e.call(sam, "PATCH", "/api/v1/alerts/999", map[string]any{"status": "closed"}, nil, nil); got != 404 {
		t.Errorf("missing alert = %d", got)
	}
	if got := e.call(sam, "GET", "/api/v1/alerts?status=bogus", nil, nil, nil); got != 400 {
		t.Errorf("bad status filter = %d", got)
	}
	var a storage.Alert
	if got := e.call(sam, "PATCH", path, map[string]any{"status": "acknowledged"}, &a, nil); got != 200 ||
		a.Status != "acknowledged" || a.UpdatedBy != "sam" {
		t.Fatalf("acknowledge = %d %+v", got, a)
	}

	// More failures while acknowledged add to the same alert.
	for i := 0; i < 2; i++ {
		e.login(e.client(), "root", "another guess")
	}
	e.worker.Drain(ctx)
	if _, err := e.alerts.Check(ctx); err != nil {
		t.Fatal(err)
	}
	e.call(sam, "GET", "/api/v1/alerts?status=all", nil, &list, nil)
	if len(list.Alerts) != 1 || list.Alerts[0].Count != 7 || list.Alerts[0].Status != "acknowledged" {
		t.Errorf("after more failures = %+v", list.Alerts)
	}
	if list.Counts["acknowledged"] != 1 || list.Counts["open"] != 0 {
		t.Errorf("counts = %v", list.Counts)
	}

	// Closing is audited too, under the analyst's name.
	e.call(sam, "PATCH", path, map[string]any{"status": "closed"}, nil, nil)
	e.worker.Drain(ctx)
	e.call(root, "GET", "/api/v1/search?q="+url.QueryEscape(`"closed the alert"`), nil, &res, nil)
	if res.Count != 1 || !strings.Contains(string(res.Events[0].Fields), `"action":"alert.closed"`) {
		t.Errorf("close audit = %d %+v", res.Count, res.Events)
	}
}

func TestRuleValidation(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	ok := map[string]any{"name": "Port scan", "enabled": true, "severity": 3, "query": "connection refused",
		"group_by": "src_ip", "threshold": 50, "window_minutes": 10}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"no name", with("name", nil)},
		{"long name", with("name", strings.Repeat("x", 81))},
		{"severity 0", with("severity", 0)},
		{"severity 7", with("severity", 7)},
		{"threshold 0", with("threshold", 0)},
		{"huge threshold", with("threshold", 1_000_001)},
		{"window 0", with("window_minutes", 0)},
		{"window over a week", with("window_minutes", 7*24*60+1)},
		{"bad group", with("group_by", "src_port")},
		{"bad min severity", with("min_severity", 9)},
		{"missing source", with("source_id", 999)},
		{"broken query", with("query", `"unterminated`)},
		{"long description", with("description", strings.Repeat("x", 301))},
	} {
		if got := e.call(root, "POST", "/api/v1/rules", tc.body, nil, nil); got != 400 {
			t.Errorf("%s = %d, want 400", tc.name, got)
		}
	}

	var r storage.Rule
	if got := e.call(root, "POST", "/api/v1/rules", ok, &r, nil); got != 201 || r.ID == 0 {
		t.Fatalf("create = %d %+v", got, r)
	}
	if got := e.call(root, "POST", "/api/v1/rules", with("name", "PORT SCAN"), nil, nil); got != 409 {
		t.Errorf("duplicate name (any case) = %d, want 409", got)
	}
	if got := e.call(root, "PUT", fmt.Sprintf("/api/v1/rules/%d", r.ID), with("threshold", 20), &r, nil); got != 200 || r.Threshold != 20 {
		t.Errorf("update = %d %+v", got, r)
	}
	var rules []storage.Rule
	e.call(root, "GET", "/api/v1/rules", nil, &rules, nil)
	var builtin int64
	for _, ru := range rules {
		if ru.Builtin {
			builtin = ru.ID
		}
	}
	if len(rules) != 5 || builtin == 0 {
		t.Fatalf("rules = %d (built-in %d)", len(rules), builtin)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/rules/%d", builtin), nil, nil, nil); got != 400 {
		t.Errorf("delete built-in = %d, want 400", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/rules/%d", r.ID), nil, nil, nil); got != 200 {
		t.Errorf("delete = %d", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/rules/%d", r.ID), nil, nil, nil); got != 404 {
		t.Errorf("delete again = %d, want 404", got)
	}
}

// A failed sign-in names the account only if it exists (people type
// passwords into the username field), and a locked-out address can't fill the
// database by trying again and again.
func TestFailedSignInAuditIsSafe(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("root", auth.RoleAdmin)
	expect(t, "typo'd password as username", e.login(e.client(), "Tr0ub4dor&3-secret", "x"), 401)
	for i := 0; i < 60; i++ { // the address is locked out after 10; blocked attempts are recorded too
		e.login(e.client(), fmt.Sprintf("guess%d", i), "x")
	}
	e.worker.Drain(ctx)
	count := func(match string) int {
		t.Helper()
		recs, err := e.repo.Search(ctx, storage.Filter{Match: match, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	if n := count("Tr0ub4dor*"); n != 0 {
		t.Errorf("the text typed as a username was recorded %d times", n)
	}
	// Every failure until the lockout, then the lockout once, however many
	// more tries there are.
	if n := count(`"unknown username"`); n != 11 {
		t.Errorf("failed and blocked sign-ins recorded = %d, want 10 failures and 1 block", n)
	}
}
