package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/chatnotify"
	"siemlite/pkg/integrations"
)

// Slack and Teams: admin only; the address is checked, never shown back, and a test message goes out.
func TestChatIntegrations(t *testing.T) {
	hook := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hook <- string(b)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	e := newEnvWith(t, func(d *api.Deps) {
		d.Slack = chatnotify.New(chatnotify.Slack, d.Repo, filepath.Join(t.TempDir(), "k"))
		d.Teams = chatnotify.New(chatnotify.Teams, d.Repo, filepath.Join(t.TempDir(), "k2"))
		d.Slack.AnyHost = true
		d.Integrations = integrations.New(d.Slack, d.Teams)
	})
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)
	if got := e.call(ann, "GET", "/api/v1/integrations/slack", nil, nil, nil); got != 403 {
		t.Errorf("a standard user read the Slack settings: %d", got)
	}
	// Teams still insists on a Teams address.
	if got := e.call(root, "PUT", "/api/v1/integrations/teams", map[string]any{"webhook": srv.URL + "/x", "min_severity": 4}, nil, nil); got != 400 {
		t.Errorf("a wrong Teams address was accepted: %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/integrations/slack/test", map[string]string{"webhook": ""}, nil, nil); got != 400 {
		t.Errorf("a test with no address: %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/integrations/slack/test", map[string]string{"webhook": srv.URL + "/services/SECRET"}, nil, nil); got != 200 {
		t.Fatalf("test = %d", got)
	}
	if msg := <-hook; !strings.Contains(msg, "test message") {
		t.Errorf("message = %s", msg)
	}
	var v chatnotify.View
	if got := e.call(root, "PUT", "/api/v1/integrations/slack", map[string]any{"webhook": srv.URL + "/services/SECRET", "min_severity": 5}, &v, nil); got != 200 || !v.Configured || v.MinSeverity != 5 {
		t.Fatalf("save = %d %+v", got, v)
	}
	if got := e.do(root, "GET", "/api/v1/integrations/slack", "", nil); got != nil {
		b, _ := io.ReadAll(got.Body)
		if strings.Contains(string(b), "SECRET") {
			t.Errorf("the address came back: %s", b)
		}
	}
	var list struct{ Integrations []integrations.Info }
	e.call(root, "GET", "/api/v1/integrations", nil, &list, nil)
	names := ""
	for _, it := range list.Integrations {
		names += it.ID + " "
	}
	if !strings.Contains(names, "slack") || !strings.Contains(names, "teams") {
		t.Errorf("the integrations list lacks them: %s", names)
	}
}
