package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

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
	_, key, _ := auth.CreateKey(context.Background(), e.repo, "app", nil)
	sam := e.client()
	e.login(sam, "sam", password)
	bearer := map[string]string{"Authorization": "Bearer " + key}

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/users"}, {"POST", "/api/v1/users"}, {"DELETE", "/api/v1/users/1"},
		{"POST", "/api/v1/sources"}, {"PATCH", "/api/v1/sources/1"}, {"DELETE", "/api/v1/sources/1"},
		{"GET", "/api/v1/parsers"}, {"POST", "/api/v1/parsers"}, {"POST", "/api/v1/parsers/test"},
		{"POST", "/api/v1/sample"},
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

	// Removing the limit shows everything again.
	e.call(root, "PATCH", fmt.Sprintf("/api/v1/users/%d", u.ID), map[string]any{"role": "standard", "sources": []int64{}}, nil, nil)
	e.call(sam, "GET", "/api/v1/search", nil, &res, nil)
	if len(res.Events) != 3 {
		t.Errorf("unrestricted search = %d events", len(res.Events))
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
