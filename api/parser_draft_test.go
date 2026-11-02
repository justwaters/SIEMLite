package api_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/search"
)

// An app's audit log, as the app prints it: pretty-printed JSON.
func prettyAuditLog(when time.Time, id int, user, action, detail, ip string) string {
	return `{
      "id": ` + strings.TrimSpace(strings.Repeat(" ", 1)) + itoa(id) + `,
      "created_at": "` + when.UTC().Format(time.RFC3339) + `",
      "username": "` + user + `",
      "user_id": null,
      "action": "` + action + `",
      "entity": null,
      "detail": "` + detail + `",
      "ip": "` + ip + `",
      "dest_ip": "",
      "via": "auto",
      "changes": null,
      "meta": {"users": ["Jonathan Martinez"], "failed": []}
    }`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestSIEMLiteDraftsAParser: pasted as it comes, SIEMLite drafts a parser for
// the log with no AI model, and the app can send it pretty-printed too.
func TestSIEMLiteDraftsAParser(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root, sam := e.client(), e.client()
	e.login(root, "root", password)
	e.login(sam, "sam", password)
	now := time.Now()
	pasted := prettyAuditLog(now.Add(-time.Hour), 1577, "system", "stipulation_digest", "Emailed digest to 1 user(s)", "") + "\n" +
		prettyAuditLog(now.Add(-time.Minute), 1580, "jmartinez", "login_failed", "Wrong password", "203.0.113.7")

	if got := e.call(sam, "POST", "/api/v1/parsers/draft", map[string]string{"text": pasted}, nil, nil); got != 403 {
		t.Errorf("standard user = %d", got)
	}
	var d struct {
		Definition map[string]any `json:"definition"`
		Matched    int            `json:"matched"`
		Total      int            `json:"total"`
		Lines      []string       `json:"lines"`
	}
	if got := e.call(root, "POST", "/api/v1/parsers/draft", map[string]string{"text": pasted}, &d, nil); got != 200 || d.Total != 2 || d.Matched != 2 || len(d.Lines) != 2 {
		t.Fatalf("draft = %d %+v", got, d)
	}
	fields, _ := d.Definition["fields"].(map[string]any)
	for k, v := range map[string]string{"created_at": "time", "username": "user", "detail": "message", "ip": "src_ip", "dest_ip": "dst_ip"} {
		if fields[k] != v {
			t.Errorf("%s -> %v, want %s", k, fields[k], v)
		}
	}
	if strings.Contains(d.Lines[0], "\n") || !strings.HasPrefix(d.Lines[0], `{"id":1577`) {
		t.Errorf("lines = %q", d.Lines)
	}
	var none map[string]string
	if got := e.call(root, "POST", "/api/v1/parsers/draft", map[string]string{"text": "  "}, &none, nil); got != 400 {
		t.Errorf("no samples = %d", got)
	}

	// Saved, used by a source, and sent as the app prints it.
	def := d.Definition
	def["name"] = "Deal tracker audit log"
	var saved struct{ ID int64 }
	if got := e.call(root, "POST", "/api/v1/parsers", def, &saved, nil); got != 200 && got != 201 {
		t.Fatalf("save parser = %d", got)
	}
	_, key, err := auth.CreateKey(ctx, e.repo, "dealtracker", &saved.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]string{
		"pretty":     pasted,
		"array":      "[" + strings.Replace(pasted, "}\n{", "},\n{", 1) + "]",
		"json lines": strings.Join(d.Lines, "\n") + "\n",
	}
	for name, body := range bodies {
		if got := e.do(e.client(), "POST", "/api/v1/logs", body, map[string]string{"Authorization": "Bearer " + key}); got.StatusCode != 202 {
			t.Fatalf("%s: send = %d", name, got.StatusCode)
		}
	}
	if err := e.worker.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var res search.Result
	e.call(root, "GET", "/api/v1/search?q="+url.QueryEscape(`"Wrong password"`), nil, &res, nil)
	if res.Count != 3 {
		t.Fatalf("events for the failed login = %d, want one per body", res.Count)
	}
	ev := res.Events[0]
	// login_failed rates Low: "fail" is Low in the default keyword ratings.
	if ev.UserName != "jmartinez" || ev.SrcIP != "203.0.113.7" || ev.SeverityID != 2 || !strings.Contains(string(ev.Fields), `"action":"login_failed"`) {
		t.Errorf("event = user %q src %q sev %d fields %s", ev.UserName, ev.SrcIP, ev.SeverityID, ev.Fields)
	}
	// Plain text still goes line by line.
	if got := e.do(e.client(), "POST", "/api/v1/logs", "first line\nsecond line\n", map[string]string{"Authorization": "Bearer " + key}); got.StatusCode != 202 {
		t.Errorf("text = %d", got.StatusCode)
	}
}
