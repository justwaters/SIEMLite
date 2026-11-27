package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// rpc posts one JSON-RPC request to /mcp with a bearer token (none if empty).
func (e *env) rpc(token, method string, params any, hdr map[string]string) (int, map[string]any) {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", e.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// tool calls a tool and returns its text and whether it was an error.
func (e *env) tool(token, name string, args any) (string, bool) {
	e.t.Helper()
	status, m := e.rpc(token, "tools/call", map[string]any{"name": name, "arguments": args}, nil)
	if status != 200 {
		e.t.Fatalf("%s: status %d %v", name, status, m)
	}
	res, _ := m["result"].(map[string]any)
	if res == nil {
		e.t.Fatalf("%s: no result: %v", name, m)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		e.t.Fatalf("%s: no content: %v", name, m)
	}
	return content[0].(map[string]any)["text"].(string), res["isError"] == true
}

func (e *env) toolNames(token string) []string {
	e.t.Helper()
	status, m := e.rpc(token, "tools/list", map[string]any{}, nil)
	if status != 200 {
		e.t.Fatalf("tools/list = %d %v", status, m)
	}
	var out []string
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return out
}

func (e *env) mcpToken(root *http.Client, name, level string) string {
	e.t.Helper()
	var made struct {
		Token string `json:"token"`
	}
	if got := e.call(root, "POST", "/api/v1/integrations/mcp/tokens", map[string]string{"name": name, "level": level}, &made, nil); got != 201 || !strings.HasPrefix(made.Token, "slmcp_") {
		e.t.Fatalf("create %s token = %d %+v", level, got, made)
	}
	return made.Token
}

func TestMCPTokensAndLevels(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)

	// Only admins manage tokens, and the card starts as not set up.
	if got := e.call(ann, "GET", "/api/v1/integrations/mcp", nil, nil, nil); got != 403 {
		t.Errorf("a standard user read the MCP settings = %d", got)
	}
	if got := e.call(ann, "POST", "/api/v1/integrations/mcp/tokens", map[string]string{"name": "x", "level": "admin"}, nil, nil); got != 403 {
		t.Errorf("a standard user made a token = %d", got)
	}
	var list struct {
		Integrations []struct{ ID, State, Summary string }
	}
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	state := func(id string) (string, string) {
		for _, it := range list.Integrations {
			if it.ID == id {
				return it.State, it.Summary
			}
		}
		return "", ""
	}
	if st, _ := state("mcp"); st != "needs_setup" {
		t.Errorf("the MCP card before any token = %q", st)
	}

	// Bad requests for a token.
	for name, body := range map[string]map[string]string{
		"no name": {"name": " ", "level": "read"}, "bad level": {"name": "x", "level": "root"}, "no level": {"name": "x"},
	} {
		if got := e.call(root, "POST", "/api/v1/integrations/mcp/tokens", body, nil, nil); got != 400 {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	read := e.mcpToken(root, "reader", "read")
	analyst := e.mcpToken(root, "triage", "analyst")
	admin := e.mcpToken(root, "ci-bot", "admin")
	if got := e.call(root, "POST", "/api/v1/integrations/mcp/tokens", map[string]string{"name": "READER", "level": "read"}, nil, nil); got != 400 {
		t.Errorf("a duplicate name (any case) = %d, want 400", got)
	}
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	if st, sum := state("mcp"); st != "on" || sum != "3 tokens (1 read-only, 1 analyst, 1 admin)" {
		t.Errorf("the MCP card = %q %q", st, sum)
	}
	// The list never shows a token again.
	var info struct {
		Enabled bool
		Tokens  []map[string]any
	}
	e.call(root, "GET", "/api/v1/integrations/mcp", nil, &info, nil)
	raw, _ := json.Marshal(info)
	if !info.Enabled || len(info.Tokens) != 3 || strings.Contains(string(raw), "slmcp_") || strings.Contains(string(raw), "key_hash") {
		t.Errorf("settings = %s", raw)
	}

	// Connecting: no token, a bad one, a session cookie and another site are all refused.
	if status, _ := e.rpc("", "initialize", map[string]any{}, nil); status != 401 {
		t.Errorf("no token = %d", status)
	}
	if status, _ := e.rpc("slmcp_nope", "initialize", map[string]any{}, nil); status != 401 {
		t.Errorf("a bad token = %d", status)
	}
	if status, _ := e.rpc(read, "initialize", map[string]any{}, map[string]string{"Origin": "https://evil.example"}); status != 403 {
		t.Errorf("another site = %d", status)
	}
	if status, _ := e.rpc(read, "initialize", map[string]any{"protocolVersion": "2025-06-18"}, nil); status != 200 {
		t.Errorf("a good token = %d", status)
	}
	// A source's ingest token isn't an agent token, and an agent token isn't an API token.
	_, srcToken, err := auth.CreateKey(context.Background(), e.repo, "collector", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := e.rpc(srcToken, "initialize", map[string]any{}, nil); status != 401 {
		t.Errorf("an ingest token on /mcp = %d", status)
	}
	if got := e.call(e.srv.Client(), "GET", "/api/v1/search", nil, nil, map[string]string{"Authorization": "Bearer " + admin}); got != 401 {
		t.Errorf("an agent token on the REST API = %d", got)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/mcp", nil)
	if resp, err := e.srv.Client().Do(req); err != nil || resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Errorf("GET /mcp = %v %v", resp, err)
	}
	// The session of a signed-in admin doesn't open /mcp either.
	if got := e.call(root, "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, nil, nil); got != 401 {
		t.Errorf("a browser session on /mcp = %d", got)
	}

	// Each level sees only its tools.
	has := func(names []string, want ...string) bool {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		for _, w := range want {
			if !set[w] {
				return false
			}
		}
		return true
	}
	rn, an, adm := e.toolNames(read), e.toolNames(analyst), e.toolNames(admin)
	if len(rn) != 5 || !has(rn, "search_events", "get_stats", "list_alerts", "list_rules", "list_sources") || has(rn, "set_alert_status") || has(rn, "create_alert") {
		t.Errorf("read-only tools = %v", rn)
	}
	if len(an) != 7 || !has(an, "set_alert_status", "create_alert") || has(an, "create_source") {
		t.Errorf("analyst tools = %v", an)
	}
	if len(adm) != 16 || !has(adm, "create_source", "update_source", "delete_source", "save_parser", "draft_parser", "test_parser", "list_parsers", "get_parser", "delete_parser") {
		t.Errorf("admin tools = %v", adm)
	}
	for _, forbidden := range []string{"user", "password", "tls", "backup", "retention", "email", "entra", "rule"} {
		for _, n := range adm {
			if strings.Contains(n, forbidden) && n != "list_rules" {
				t.Errorf("the admin level has a %q tool: %s", forbidden, n)
			}
		}
	}
	// Guessing a tool's name above one's level doesn't work.
	if msg, isErr := e.tool(read, "create_source", map[string]any{"name": "x"}); !isErr || !strings.Contains(msg, "read-only") {
		t.Errorf("a read-only token created a source: %q %v", msg, isErr)
	}
	if msg, isErr := e.tool(analyst, "delete_source", map[string]any{"id": 1}); !isErr || !strings.Contains(msg, "analyst") {
		t.Errorf("an analyst token deleted a source: %q %v", msg, isErr)
	}

	// Removing a token cuts the agent off at once.
	var all struct {
		Tokens []struct {
			ID   int64
			Name string
		}
	}
	e.call(root, "GET", "/api/v1/integrations/mcp", nil, &all, nil)
	for _, tk := range all.Tokens {
		if tk.Name == "reader" {
			if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/integrations/mcp/tokens/%d", tk.ID), nil, nil, nil); got != 200 {
				t.Fatalf("remove = %d", got)
			}
		}
	}
	if status, _ := e.rpc(read, "tools/list", map[string]any{}, nil); status != 401 {
		t.Errorf("a removed token = %d", status)
	}

	// Switching the integration off keeps agents out and the tokens in place.
	if got := e.call(root, "POST", "/api/v1/integrations/mcp/enabled", map[string]bool{"enabled": false}, nil, nil); got != 200 {
		t.Fatalf("turn off = %d", got)
	}
	if status, _ := e.rpc(admin, "tools/list", map[string]any{}, nil); status != 403 {
		t.Errorf("with agent access off = %d", status)
	}
	e.call(root, "POST", "/api/v1/integrations/mcp/enabled", map[string]bool{"enabled": true}, nil, nil)
	if status, _ := e.rpc(admin, "tools/list", map[string]any{}, nil); status != 200 {
		t.Errorf("with agent access back on = %d", status)
	}

	// Token changes are audited.
	waitForEvent(t, e, root, "created the AI agent token ci-bot (admin)")
	waitForEvent(t, e, root, "removed the AI agent token reader (read-only)")

	// Repeated bad tokens lock the address out, like wrong passwords do.
	for i := 0; i < 12; i++ {
		e.rpc("slmcp_wrong", "ping", nil, nil)
	}
	if status, _ := e.rpc("slmcp_wrong", "ping", nil, nil); status != 429 {
		t.Errorf("after many bad tokens = %d, want 429", status)
	}
}

// waitForEvent looks for an audit event whose message contains text.
func waitForEvent(t *testing.T, e *env, c *http.Client, text string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var ev struct{ Events []struct{ Message string } }
		e.call(c, "GET", "/api/v1/search?limit=100", nil, &ev, nil)
		for _, x := range ev.Events {
			if strings.Contains(x.Message, text) {
				return
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Errorf("no event saying %q", text)
}

func TestMCPTools(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	read := e.mcpToken(root, "reader", "read")
	analyst := e.mcpToken(root, "triage", "analyst")
	admin := e.mcpToken(root, "ci-bot", "admin")
	ctx := context.Background()

	// Events to look at.
	now := time.Now()
	for i := 0; i < 3; i++ {
		ev := &ocsf.Event{Time: now.Add(-time.Duration(i) * time.Minute).UnixMilli(), CategoryUID: 3, ClassUID: 3002, ActivityID: 1, SeverityID: 3,
			Message: "failed password for root", RawData: "Oct 23 sshd: failed password for root from 10.9.8.7",
			SrcEndpoint: &ocsf.Endpoint{IP: "10.9.8.7"}}
		if err := e.worker.Submit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	e.worker.Drain(ctx)

	type searchOut struct {
		Events []map[string]any `json:"events"`
		Count  int              `json:"count"`
	}
	var res searchOut
	text, isErr := e.tool(read, "search_events", map[string]any{"q": "failed", "src_ip": "10.9.8.7", "limit": 2})
	if isErr || json.Unmarshal([]byte(text), &res) != nil || len(res.Events) != 2 {
		t.Fatalf("search_events = %q %v", text, isErr)
	}
	if _, has := res.Events[0]["raw_data"]; has {
		t.Error("search_events returned the raw line without being asked")
	}
	if res.Events[0]["src_ip"] != "10.9.8.7" || res.Events[0]["message"] != "failed password for root" {
		t.Errorf("event = %v", res.Events[0])
	}
	text, _ = e.tool(read, "search_events", map[string]any{"q": "failed", "include_raw": true, "limit": 1})
	res = searchOut{}
	json.Unmarshal([]byte(text), &res)
	if len(res.Events) != 1 || res.Events[0]["raw_data"] == nil {
		t.Errorf("include_raw = %s", text)
	}
	// Mistakes come back as text the agent can act on.
	if msg, isErr := e.tool(read, "search_events", map[string]any{"start": "yesterday"}); !isErr || !strings.Contains(msg, "start") {
		t.Errorf("a bad start = %q %v", msg, isErr)
	}
	if msg, isErr := e.tool(read, "search_events", map[string]any{"q": `"unterminated`}); !isErr || msg == "" {
		t.Errorf("a bad search = %q %v", msg, isErr)
	}
	if msg, isErr := e.tool(read, "search_events", map[string]any{"limit": "many"}); !isErr {
		t.Errorf("a limit that is not a number = %q", msg)
	}
	var stats map[string]any
	if text, isErr := e.tool(read, "get_stats", map[string]any{"hours": 24}); isErr || json.Unmarshal([]byte(text), &stats) != nil {
		t.Errorf("get_stats = %q %v", text, isErr)
	}
	for _, name := range []string{"list_rules", "list_sources", "list_alerts"} {
		if text, isErr := e.tool(read, name, map[string]any{}); isErr || !json.Valid([]byte(text)) {
			t.Errorf("%s = %q %v", name, text, isErr)
		}
	}

	// An alert to work on: an analyst can acknowledge it, a read-only token can't.
	ruleID, err := e.repo.SaveRule(ctx, storage.Rule{Name: "t", Kind: storage.RuleMatch, Enabled: true, Severity: 3, Threshold: 1, WindowMinutes: 5}, now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.RaiseAlert(ctx, storage.Rule{ID: ruleID, Name: "t", Severity: 3}, "", 1, 1, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	var alerts struct {
		Alerts []struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
	}
	text, _ = e.tool(read, "list_alerts", map[string]any{})
	if json.Unmarshal([]byte(text), &alerts) != nil || len(alerts.Alerts) != 1 || alerts.Alerts[0].Status != "open" {
		t.Fatalf("list_alerts = %s", text)
	}
	id := alerts.Alerts[0].ID
	if _, isErr := e.tool(read, "set_alert_status", map[string]any{"id": id, "status": "acknowledged"}); !isErr {
		t.Error("a read-only token acknowledged an alert")
	}
	if text, isErr := e.tool(analyst, "set_alert_status", map[string]any{"id": id, "status": "acknowledged"}); isErr {
		t.Errorf("acknowledge = %q", text)
	}
	text, _ = e.tool(read, "list_alerts", map[string]any{"status": "acknowledged"})
	if json.Unmarshal([]byte(text), &alerts) != nil || len(alerts.Alerts) != 1 || alerts.Alerts[0].Status != "acknowledged" {
		t.Errorf("after acknowledging = %s", text)
	}
	if msg, isErr := e.tool(analyst, "set_alert_status", map[string]any{"id": id, "status": "deleted"}); !isErr || !strings.Contains(msg, "status") {
		t.Errorf("a bad status = %q %v", msg, isErr)
	}
	if msg, isErr := e.tool(analyst, "set_alert_status", map[string]any{"id": id, "status": "closed"}); !isErr || !strings.Contains(msg, "why") {
		t.Errorf("closing over MCP without a note = %q %v", msg, isErr)
	}
	if text, isErr := e.tool(analyst, "set_alert_status", map[string]any{"id": id, "status": "closed", "note": "Duplicate of another alert."}); isErr || !strings.Contains(text, `"close_note":"Duplicate of another alert."`) {
		t.Errorf("closing over MCP with a note = %q %v", text, isErr)
	}
	if _, isErr := e.tool(analyst, "set_alert_status", map[string]any{"id": "x", "status": "closed", "note": "a bad id"}); !isErr {
		t.Error("a bad id was accepted")
	}
	waitForEvent(t, e, root, "agent:triage acknowledged the alert")

	// An admin token manages sources and parsers, through the same checks as the web UI.
	var made struct {
		Source struct {
			ID int64 `json:"id"`
		} `json:"source"`
		Token string `json:"token"`
	}
	text, isErr = e.tool(admin, "create_source", map[string]any{"name": "firewall"})
	if isErr || json.Unmarshal([]byte(text), &made) != nil || made.Source.ID == 0 || !strings.HasPrefix(made.Token, "slk_") {
		t.Fatalf("create_source = %q %v", text, isErr)
	}
	if msg, isErr := e.tool(admin, "create_source", map[string]any{"name": " "}); !isErr || msg == "" {
		t.Errorf("a source with no name = %q %v", msg, isErr)
	}
	if text, isErr := e.tool(admin, "update_source", map[string]any{"id": made.Source.ID, "name": "edge firewall", "enabled": false}); isErr {
		t.Errorf("update_source = %q", text)
	}
	text, _ = e.tool(read, "list_sources", map[string]any{})
	if !strings.Contains(text, "edge firewall") {
		t.Errorf("list_sources after the rename = %s", text)
	}
	lines := []string{"user=alice action=login src=10.0.0.5 result=failed", "user=bob action=login src=10.0.0.6 result=ok"}
	var draft struct {
		Definition json.RawMessage `json:"definition"`
	}
	text, isErr = e.tool(admin, "draft_parser", map[string]any{"lines": lines})
	if isErr || json.Unmarshal([]byte(text), &draft) != nil || len(draft.Definition) == 0 {
		t.Fatalf("draft_parser = %q %v", text, isErr)
	}
	if text, isErr := e.tool(admin, "test_parser", map[string]any{"definition": json.RawMessage(draft.Definition), "lines": lines}); isErr || !strings.Contains(text, "alice") {
		t.Errorf("test_parser = %q %v", text, isErr)
	}
	var def map[string]any
	json.Unmarshal(draft.Definition, &def)
	def["name"] = "login lines"
	text, isErr = e.tool(admin, "save_parser", map[string]any{"definition": def})
	if isErr {
		t.Fatalf("save_parser = %q", text)
	}
	var parsers []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	text, _ = e.tool(admin, "list_parsers", map[string]any{})
	json.Unmarshal([]byte(text), &parsers)
	var pid int64
	for _, p := range parsers {
		if p.Name == "login lines" {
			pid = p.ID
		}
	}
	if pid == 0 {
		t.Fatalf("list_parsers after save_parser = %s", text)
	}
	if text, isErr := e.tool(admin, "get_parser", map[string]any{"id": pid}); isErr || !strings.Contains(text, "login lines") {
		t.Errorf("get_parser = %q %v", text, isErr)
	}
	if msg, isErr := e.tool(admin, "save_parser", map[string]any{"definition": map[string]any{"name": "bad", "format": "pattern", "pattern": "{unclosed"}}); !isErr || msg == "" {
		t.Errorf("a bad parser = %q %v", msg, isErr)
	}
	if text, isErr := e.tool(admin, "delete_parser", map[string]any{"id": pid}); isErr {
		t.Errorf("delete_parser = %q", text)
	}
	if text, isErr := e.tool(admin, "delete_source", map[string]any{"id": made.Source.ID}); isErr {
		t.Errorf("delete_source = %q", text)
	}
	if msg, isErr := e.tool(admin, "delete_source", map[string]any{"id": 999}); !isErr || msg == "" {
		t.Errorf("deleting a source that isn't there = %q %v", msg, isErr)
	}

	// What an agent does is audited under its token's name, marked as coming through MCP.
	waitForEvent(t, e, root, "agent:ci-bot created the access token firewall")
	waitForEvent(t, e, root, "agent:ci-bot deleted the access token")
	var found bool
	for i := 0; i < 50 && !found; i++ {
		var ev struct {
			Events []struct {
				Message string
				Fields  map[string]string
			}
		}
		e.call(root, "GET", "/api/v1/search?limit=100", nil, &ev, nil)
		for _, x := range ev.Events {
			if strings.Contains(x.Message, "agent:ci-bot created the access token") && x.Fields["via"] == "mcp" {
				found = true
			}
		}
		if !found {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if !found {
		t.Error("the audit entry for an agent's change isn't marked via=mcp")
	}
}

func TestMCPLineBatchIsCapped(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	tok := e.mcpToken(root, "agent", "admin")

	many := make([]string, 1001)
	for i := range many {
		many[i] = "a"
	}
	for _, tool := range []string{"draft_parser", "test_parser"} {
		text, isErr := e.tool(tok, tool, map[string]any{"lines": many, "definition": map[string]any{"name": "x", "format": "text", "pattern": "{message}"}})
		if !isErr || !strings.Contains(text, "limit is 1000") {
			t.Errorf("%s with 1001 lines = %v %q", tool, isErr, text)
		}
	}
	big := strings.Repeat("x", 100<<10)
	text, isErr := e.tool(tok, "draft_parser", map[string]any{"lines": []string{big, big, big}})
	if !isErr || !strings.Contains(text, "bytes per call") {
		t.Errorf("oversized lines = %v %q", isErr, text)
	}
	if _, isErr := e.tool(tok, "draft_parser", map[string]any{"lines": []string{"a=1 b=2", "a=3 b=4"}}); isErr {
		t.Errorf("a small batch was refused")
	}
}

// Every tool an agent calls is audited, reads included, under the token's
// name, with the arguments and the outcome; a call the token's level refuses
// is audited as denied.
func TestMCPCallsAreAudited(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	read := e.mcpToken(root, "auditme", "read")

	if msg, isErr := e.tool(read, "search_events", map[string]any{"q": `"needle-xyz"`}); isErr {
		t.Fatalf("search_events failed: %s", msg)
	}
	if _, isErr := e.tool(read, "set_alert_status", map[string]any{"id": 1, "status": "closed"}); !isErr {
		t.Fatal("a read-only token closed an alert")
	}
	e.worker.Drain(context.Background())

	text, _ := e.tool(read, "search_events", map[string]any{"q": "auditme", "limit": 20})
	for _, want := range []string{"agent:auditme called search_events", "needle-xyz", "agent:auditme tried"} {
		if !strings.Contains(text, want) {
			t.Errorf("the audit trail lacks %q:\n%s", want, text)
		}
	}
}

// An agent can raise an alert no rule describes; raising it again updates the open one.
func TestMCPCreateAlert(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	read := e.mcpToken(root, "reader", "read")
	analyst := e.mcpToken(root, "triage", "analyst")

	args := map[string]any{"title": "Password spraying", "severity": 4, "group_by": "src_ip", "group_value": "10.1.2.3", "count": 7, "note": "7 users failed from one address"}
	if msg, isErr := e.tool(read, "create_alert", args); !isErr || !strings.Contains(msg, "analyst") {
		t.Errorf("a read-only token raised an alert: %q %v", msg, isErr)
	}
	text, isErr := e.tool(analyst, "create_alert", args)
	var a struct {
		ID         int64  `json:"id"`
		RuleID     *int64 `json:"rule_id"`
		Status     string `json:"status"`
		Count      int64  `json:"count"`
		UpdatedBy  string `json:"updated_by"`
		Note       string `json:"note"`
		GroupValue string `json:"group_value"`
	}
	if isErr || json.Unmarshal([]byte(text), &a) != nil || a.ID == 0 || a.RuleID != nil || a.Status != "open" || a.Count != 7 ||
		a.UpdatedBy != "agent:triage" || a.Note == "" || a.GroupValue != "10.1.2.3" {
		t.Fatalf("create_alert = %q %v", text, isErr)
	}
	// Again: the same alert, now with 8 events.
	args["count"] = 1
	text, _ = e.tool(analyst, "create_alert", args)
	var again struct {
		ID    int64 `json:"id"`
		Count int64 `json:"count"`
	}
	if json.Unmarshal([]byte(text), &again) != nil || again.ID != a.ID || again.Count != 8 {
		t.Errorf("a repeat = %q", text)
	}
	var list struct {
		Alerts []map[string]any `json:"alerts"`
	}
	if got := e.call(root, "GET", "/api/v1/alerts?status=open", nil, &list, nil); got != 200 || len(list.Alerts) != 1 || list.Alerts[0]["note"] == "" {
		t.Errorf("alerts = %d %+v", got, list)
	}
	// Mistakes come back as text.
	for name, bad := range map[string]map[string]any{
		"no title":      {"severity": 3},
		"bad severity":  {"title": "x", "severity": 9},
		"bad group":     {"title": "x", "severity": 3, "group_by": "port"},
		"value no kind": {"title": "x", "severity": 3, "group_value": "a"},
	} {
		if msg, isErr := e.tool(analyst, "create_alert", bad); !isErr || msg == "" {
			t.Errorf("%s: %q %v", name, msg, isErr)
		}
	}
}
