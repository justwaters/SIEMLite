package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

// call sends a JSON request and decodes the JSON response into out (if set).
func (e *env) call(c *http.Client, method, path string, body any, out any, hdr map[string]string) int {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestAdminPagesNeedAdmin(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	_, key, _ := auth.CreateKey(context.Background(), e.repo, "app", nil, false)
	sam := e.client()
	e.login(sam, "sam", password)
	bearer := map[string]string{"Authorization": "Bearer " + key}

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/users"}, {"POST", "/api/v1/users"}, {"DELETE", "/api/v1/users/1"},
		{"POST", "/api/v1/sources"}, {"PATCH", "/api/v1/sources/1"}, {"DELETE", "/api/v1/sources/1"},
		{"GET", "/api/v1/parsers"}, {"POST", "/api/v1/parsers"}, {"POST", "/api/v1/parsers/test"},
		{"GET", "/api/v1/system"}, {"GET", "/api/v1/backups"}, {"POST", "/api/v1/backups"},
		{"PUT", "/api/v1/backups/settings"}, {"POST", "/api/v1/backups/upload"},
		{"GET", "/api/v1/backups/x"}, {"DELETE", "/api/v1/backups/x"}, {"POST", "/api/v1/backups/x/restore"},
	} {
		if got := e.call(sam, tc.method, tc.path, map[string]any{}, nil, nil); got != 403 {
			t.Errorf("standard user %s %s = %d, want 403", tc.method, tc.path, got)
		}
		if got := e.call(e.client(), tc.method, tc.path, map[string]any{}, nil, bearer); got != 403 {
			t.Errorf("access token %s %s = %d, want 403", tc.method, tc.path, got)
		}
	}
	// Standard users can read the dashboard and the list of sources.
	expect(t, "standard stats", e.do(sam, "GET", "/api/v1/stats", "", nil), 200)
	expect(t, "standard sources", e.do(sam, "GET", "/api/v1/sources", "", nil), 200)
}

func TestSourcesParsersAndRestrictions(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	// A parser for an nginx access log, from the built-in template.
	var saved struct {
		ID int64 `json:"id"`
	}
	tmpl := parser.Templates[0]
	tmpl.Name = "nginx"
	if got := e.call(root, "POST", "/api/v1/parsers", tmpl, &saved, nil); got != 201 {
		t.Fatalf("create parser = %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/parsers", tmpl, nil, nil); got != 409 {
		t.Errorf("duplicate parser name = %d, want 409", got)
	}
	bad := parser.Definition{Name: "bad", Format: "pattern", Pattern: "no placeholders"}
	if got := e.call(root, "POST", "/api/v1/parsers", bad, nil, nil); got != 400 {
		t.Errorf("invalid parser = %d, want 400", got)
	}

	// Two sources: one using the parser, one automatic.
	var web, other struct {
		Source storage.Source `json:"source"`
		Token  string         `json:"token"`
	}
	if got := e.call(root, "POST", "/api/v1/sources", map[string]any{"name": "web", "parser_id": saved.ID}, &web, nil); got != 201 || web.Token == "" {
		t.Fatalf("create source = %d %+v", got, web)
	}
	e.call(root, "POST", "/api/v1/sources", map[string]any{"name": "other"}, &other, nil)
	if web.Source.ParserName != "nginx" || web.Source.LastUsedAt != nil {
		t.Errorf("new source = %+v", web.Source)
	}

	line := `203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.5"`
	expect(t, "web logs", e.do(e.client(), "POST", "/api/v1/logs", line+"\nnot an access log\n",
		map[string]string{"Authorization": "Bearer " + web.Token}), 202)
	expect(t, "other logs", e.do(e.client(), "POST", "/api/v1/logs", "Failed password for root from 198.51.100.9",
		map[string]string{"Authorization": "Bearer " + other.Token}), 202)
	e.worker.Drain(context.Background())

	var res struct {
		Events []storage.Record `json:"events"`
	}
	e.call(root, "GET", fmt.Sprintf("/api/v1/search?source_id=%d", web.Source.ID), nil, &res, nil)
	if len(res.Events) != 2 {
		t.Fatalf("web source events = %d", len(res.Events))
	}
	parsed, unparsed := res.Events[1], res.Events[0] // newest first; the access log line is older
	if parsed.RawData != line {
		parsed, unparsed = unparsed, parsed
	}
	if parsed.SrcIP != "203.0.113.7" || parsed.SeverityID != 3 || parsed.SourceName != "web" ||
		!strings.Contains(string(parsed.Fields), `"status":"401"`) {
		t.Errorf("parsed event = %+v fields=%s", parsed, parsed.Fields)
	}
	if !strings.Contains(string(unparsed.Fields), "parse_error") {
		t.Errorf("unmatched line should be kept with a parse_error field: %s", unparsed.Fields)
	}

	// Last used is recorded.
	var list []storage.Source
	e.call(root, "GET", "/api/v1/sources", nil, &list, nil)
	used := map[string]bool{}
	for _, s := range list {
		used[s.Name] = s.LastUsedAt != nil
	}
	if !used["web"] || !used["other"] || used["Syslog"] {
		t.Errorf("last used = %v", used)
	}

	// A standard user limited to "other" sees only its event.
	var u storage.User
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{
		"username": "sam", "password": password, "role": "standard", "sources": []int64{other.Source.ID},
	}, &u, nil); got != 201 || len(u.Sources) != 1 {
		t.Fatalf("create user = %d %+v", got, u)
	}
	sam := e.client()
	e.login(sam, "sam", password)
	e.call(sam, "GET", "/api/v1/search", nil, &res, nil)
	if len(res.Events) != 1 || res.Events[0].SourceName != "other" {
		t.Errorf("restricted search = %+v", res.Events)
	}
	var stats struct {
		Overview storage.Overview `json:"overview"`
	}
	e.call(sam, "GET", "/api/v1/stats", nil, &stats, nil)
	if stats.Overview.Total != 1 {
		t.Errorf("restricted stats total = %d", stats.Overview.Total)
	}
	var visible []map[string]any
	e.call(sam, "GET", "/api/v1/sources", nil, &visible, nil)
	if len(visible) != 1 || visible[0]["name"] != "other" {
		t.Errorf("restricted sources = %v", visible)
	}

	if !u.Limited {
		t.Errorf("user created with sources should be limited: %+v", u)
	}

	// Regression: a partial update must never widen access. Changing only
	// the role, or sending an empty list without "limited", keeps the limit.
	if got := e.call(root, "PATCH", fmt.Sprintf("/api/v1/users/%d", u.ID), map[string]any{"role": "standard"}, nil, nil); got != 200 {
		t.Errorf("role-only update = %d", got)
	}
	e.call(sam, "GET", "/api/v1/search", nil, &res, nil)
	if len(res.Events) != 1 {
		t.Errorf("role-only update widened access: %d events visible", len(res.Events))
	}
	if got := e.call(root, "PATCH", fmt.Sprintf("/api/v1/users/%d", u.ID), map[string]any{"sources": []int64{}}, nil, nil); got != 400 {
		t.Errorf("limiting to no sources = %d, want 400", got)
	}
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{"username": "x", "password": password, "role": "standard", "limited": true}, nil, nil); got != 400 {
		t.Errorf("creating a user limited to no sources = %d, want 400", got)
	}
	// If a limited user's source rows disappear (e.g. a source is removed),
	// they see nothing rather than everything.
	if _, err := e.repo.DB().Write.Exec(`DELETE FROM user_sources WHERE user_id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	e.call(sam, "GET", "/api/v1/search", nil, &res, nil)
	if len(res.Events) != 0 {
		t.Errorf("lost source rows widened access: %d events visible", len(res.Events))
	}
	e.call(sam, "GET", "/api/v1/stats", nil, &stats, nil)
	if stats.Overview.Total != 0 {
		t.Errorf("lost source rows widened stats: %d", stats.Overview.Total)
	}

	// Removing the limit explicitly shows everything again.
	e.call(root, "PATCH", fmt.Sprintf("/api/v1/users/%d", u.ID), map[string]any{"limited": false}, nil, nil)
	e.call(sam, "GET", "/api/v1/search", nil, &res, nil)
	logs := 0
	for _, ev := range res.Events {
		if ev.SourceName != "INTERNAL" { // the audit log is visible too
			logs++
		}
	}
	if logs != 3 {
		t.Errorf("unrestricted search = %d log events", logs)
	}

	// Revoking a token stops it sending; deleting the parser returns the
	// source to automatic parsing.
	expect(t, "revoke", e.do(root, "DELETE", fmt.Sprintf("/api/v1/sources/%d", other.Source.ID), "", nil), 200)
	expect(t, "revoked token", e.do(e.client(), "POST", "/api/v1/logs", "x", map[string]string{"Authorization": "Bearer " + other.Token}), 401)
	syslog, _ := e.repo.BuiltinSource(context.Background(), storage.SourceSyslog)
	expect(t, "revoke built-in", e.do(root, "DELETE", fmt.Sprintf("/api/v1/sources/%d", syslog.ID), "", nil), 400)
	expect(t, "delete parser", e.do(root, "DELETE", fmt.Sprintf("/api/v1/parsers/%d", saved.ID), "", nil), 200)
	src, _ := e.repo.GetSource(context.Background(), web.Source.ID)
	if src.ParserID != nil {
		t.Errorf("source still has a parser after it was deleted")
	}
}

func TestUserManagement(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	var me storage.User
	var users []storage.User
	e.call(root, "GET", "/api/v1/users", nil, &users, nil)
	me = users[0]

	if got := e.call(root, "PATCH", fmt.Sprintf("/api/v1/users/%d", me.ID), map[string]any{"role": "standard"}, nil, nil); got != 409 {
		t.Errorf("demoting the last admin = %d, want 409", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/users/%d", me.ID), nil, nil, nil); got != 400 {
		t.Errorf("deleting yourself = %d, want 400", got)
	}
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{"username": "x", "password": "short", "role": "standard"}, nil, nil); got != 400 {
		t.Errorf("short password = %d, want 400", got)
	}
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{"username": "x", "password": password, "role": "standard", "sources": []int64{999}}, nil, nil); got != 400 {
		t.Errorf("unknown source = %d, want 400", got)
	}
	var u storage.User
	e.call(root, "POST", "/api/v1/users", map[string]any{"username": "alex", "password": password, "role": "admin"}, &u, nil)
	if got := e.call(root, "POST", fmt.Sprintf("/api/v1/users/%d/password", u.ID), map[string]any{"password": "a whole new password"}, nil, nil); got != 200 {
		t.Errorf("set password = %d", got)
	}
	expect(t, "new password works", e.login(e.client(), "alex", "a whole new password"), 200)
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/users/%d", u.ID), nil, nil, nil); got != 200 {
		t.Errorf("delete user = %d", got)
	}

	var test struct {
		Results []struct {
			Matched bool              `json:"matched"`
			Event   map[string]any    `json:"event"`
			Extra   map[string]string `json:"extra"`
		} `json:"results"`
	}
	e.call(root, "POST", "/api/v1/parsers/test", map[string]any{"definition": parser.Templates[2], "lines": parser.Templates[2].Samples}, &test, nil)
	if len(test.Results) != 2 || !test.Results[0].Matched || test.Results[0].Event["src_ip"] != "203.0.113.34" {
		t.Errorf("parser test = %+v", test.Results)
	}
	if got := e.call(root, "POST", "/api/v1/parsers/suggest", map[string]any{"lines": []string{"x"}}, nil, nil); got != 404 {
		t.Errorf("suggest without AI = %d, want 404", got)
	}
}

// A source set to None stores each line as it arrives; switching it back to
// Automatic (or choosing a parser) detects again.
func TestSourceParserNone(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	var created struct {
		Source storage.Source `json:"source"`
		Token  string         `json:"token"`
	}
	e.call(root, "POST", "/api/v1/sources", map[string]any{"name": "plain"}, &created, nil)
	id, bearer := created.Source.ID, map[string]string{"Authorization": "Bearer " + created.Token}
	path := fmt.Sprintf("/api/v1/sources/%d", id)
	if created.Source.ParserNone {
		t.Fatal("a new source should parse automatically")
	}

	// Both at once is refused, on create and on update.
	expect(t, "create with both", e.do(root, "POST", "/api/v1/sources", `{"name":"x","parser_id":1,"parser_none":true}`, nil), 400)
	expect(t, "update with both", e.do(root, "PATCH", path, `{"parser_id":1,"parser_none":true}`, nil), 400)
	expect(t, "bad value", e.do(root, "PATCH", path, `{"parser_none":"yes"}`, nil), 400)

	var src storage.Source
	if got := e.call(root, "PATCH", path, map[string]any{"parser_none": true}, &src, nil); got != 200 || !src.ParserNone || src.ParserID != nil {
		t.Fatalf("set None = %d %+v", got, src)
	}
	// The INTERNAL source never has a parser, None included.
	internal, _ := e.repo.BuiltinSource(context.Background(), storage.SourceInternal)
	expect(t, "internal none", e.do(root, "PATCH", fmt.Sprintf("/api/v1/sources/%d", internal.ID), `{"parser_none":true}`, nil), 400)
	// A source created as None.
	var made struct {
		Source storage.Source `json:"source"`
	}
	if e.call(root, "POST", "/api/v1/sources", map[string]any{"name": "born plain", "parser_none": true}, &made, nil); !made.Source.ParserNone {
		t.Errorf("source created with parser_none = %+v", made.Source)
	}

	syslogLine := "<38>Oct  3 11:58:01 web1 sshd[311]: Failed password for root from 203.0.113.7 port 22 ssh2"
	jsonLine := `{"level":"error","msg":"login failed user=bob from 198.51.100.9","user":"bob"}`
	send := func(lines ...string) {
		t.Helper()
		expect(t, "send", e.do(e.client(), "POST", "/api/v1/logs", strings.Join(lines, "\n"), bearer), 202)
		e.worker.Drain(context.Background())
	}
	events := func() map[string]storage.Record {
		t.Helper()
		var res struct {
			Events []storage.Record `json:"events"`
		}
		e.call(root, "GET", fmt.Sprintf("/api/v1/search?source_id=%d", id), nil, &res, nil)
		out := map[string]storage.Record{}
		for _, ev := range res.Events {
			out[ev.RawData] = ev
		}
		return out
	}

	before := time.Now().Add(-time.Second).UnixMilli()
	send(syslogLine, jsonLine)
	after := time.Now().Add(time.Second).UnixMilli()
	got := events()
	for _, line := range []string{syslogLine, jsonLine} {
		ev, ok := got[line]
		if !ok {
			t.Fatalf("no event for %q", line)
		}
		if ev.Message != line || ev.SrcIP != "" || ev.UserName != "" || ev.Host != "" || ev.Source != "" || len(ev.Fields) > 0 {
			t.Errorf("None kept more than the line: %+v", ev)
		}
		if ev.SeverityID != 1 || ev.CategoryUID != 6 {
			t.Errorf("severity = %d, category = %d", ev.SeverityID, ev.CategoryUID)
		}
		if ev.Timestamp < before || ev.Timestamp > after {
			t.Errorf("timestamp %d isn't the arrival time (%d to %d)", ev.Timestamp, before, after)
		}
	}

	// Back to Automatic: the same lines are detected again.
	if got := e.call(root, "PATCH", path, map[string]any{"parser_id": nil}, &src, nil); got != 200 || src.ParserNone {
		t.Fatalf("set Automatic = %d %+v", got, src)
	}
	send(syslogLine)
	var parsed storage.Record
	for _, ev := range events() {
		if ev.RawData == syslogLine && ev.SrcIP != "" {
			parsed = ev
		}
	}
	if parsed.SrcIP != "203.0.113.7" || parsed.Host != "web1" || parsed.Message != "Failed password for root from 203.0.113.7 port 22 ssh2" {
		t.Errorf("automatic parsing after None = %+v", parsed)
	}

	// And parser_none false on its own turns it off without touching the parser.
	e.call(root, "PATCH", path, map[string]any{"parser_none": true}, &src, nil)
	if e.call(root, "PATCH", path, map[string]any{"parser_none": false}, &src, nil); src.ParserNone {
		t.Errorf("parser_none false left it on: %+v", src)
	}
}
