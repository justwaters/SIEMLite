package api_test

import (
	"context"
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
	"siemlite/pkg/storage"
)

// Friendly lists: made, filled with addresses and ranges, changed and deleted by admins only;
// bad entries are refused whole.
func TestFriendlyLists(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) { d.Intel = intel.NewService(d.Repo, intel.Config{}) })
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)
	if _, err := e.deps.Repo.AddIndicators(t.Context(), []storage.Indicator{{Type: "ip", Value: "203.0.113.7", Source: "feed"}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.deps.Intel.Load(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := e.call(ann, "GET", "/api/v1/intel/friendly", nil, nil, nil); got != 403 {
		t.Errorf("a standard user read the friendly lists: %d", got)
	}
	if got := e.call(ann, "GET", "/api/v1/intel/feeds", nil, nil, nil); got != 403 {
		t.Errorf("a standard user read the feeds: %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/intel/friendly", map[string]string{"name": " "}, nil, nil); got != 400 {
		t.Errorf("a nameless list was accepted: %d", got)
	}
	var made struct{ ID int64 }
	if got := e.call(root, "POST", "/api/v1/intel/friendly", map[string]string{"name": "Office", "description": "HQ and VPN"}, &made, nil); got != 201 || made.ID == 0 {
		t.Fatalf("create = %d %+v", got, made)
	}
	if got := e.call(root, "POST", "/api/v1/intel/friendly", map[string]string{"name": "Office"}, nil, nil); got != 409 {
		t.Errorf("a repeated name: %d", got)
	}
	entries := fmt.Sprintf("/api/v1/intel/friendly/%d/entries", made.ID)
	if got := e.call(root, "POST", entries, map[string]string{"values": "198.51.100.0/24 not-an-ip"}, nil, nil); got != 400 {
		t.Errorf("a bad entry was accepted: %d", got)
	}
	var add struct {
		Added        int
		AlreadyThere int `json:"already_there"`
	}
	if got := e.call(root, "POST", entries, map[string]string{"values": "203.0.113.7, 198.51.100.9/24\n203.0.113.7", "note": "front door"}, &add, nil); got != 200 || add.Added != 2 {
		t.Fatalf("add = %d %+v", got, add)
	}
	if got := e.call(root, "POST", entries, map[string]string{"values": "203.0.113.7"}, &add, nil); got != 200 || add.Added != 0 || add.AlreadyThere != 1 {
		t.Errorf("adding a repeat: %d %+v", got, add)
	}
	var lists []storage.FriendlyList
	if got := e.call(root, "GET", "/api/v1/intel/friendly", nil, &lists, nil); got != 200 || len(lists) != 1 || len(lists[0].Entries) != 2 {
		t.Fatalf("lists = %d %+v", got, lists)
	}
	if v := lists[0].Entries; v[0].Value != "198.51.100.0/24" && v[1].Value != "198.51.100.0/24" {
		t.Errorf("a range wasn't normalized: %+v", v)
	}
	if n := e.deps.Intel.Matcher.Size(); n != 1 {
		t.Errorf("indicators = %d", n)
	}
	if got := e.call(root, "DELETE", entries+"?value=203.0.113.7", nil, nil, nil); got != 204 {
		t.Errorf("remove entry = %d", got)
	}
	if got := e.call(root, "DELETE", entries+"?value=203.0.113.7", nil, nil, nil); got != 404 {
		t.Errorf("remove again = %d", got)
	}
	if got := e.call(root, "PATCH", fmt.Sprintf("/api/v1/intel/friendly/%d", made.ID), map[string]string{"name": "HQ"}, nil, nil); got != 204 {
		t.Errorf("rename = %d", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/intel/friendly/%d", made.ID), nil, nil, nil); got != 204 {
		t.Errorf("delete = %d", got)
	}
	if got := e.call(root, "DELETE", fmt.Sprintf("/api/v1/intel/friendly/%d", made.ID), nil, nil, nil); got != 404 {
		t.Errorf("delete again = %d", got)
	}
	vals, _ := e.deps.Repo.FriendlyValues(t.Context())
	if len(vals) != 0 {
		t.Errorf("entries left after deleting the list: %v", vals)
	}
	var feeds intel.FeedsView
	if got := e.call(root, "GET", "/api/v1/intel/feeds", nil, &feeds, nil); got != 200 || len(feeds.Feeds) < 4 {
		t.Errorf("feeds = %d %+v", got, feeds)
	}
	if got := e.call(root, "PUT", "/api/v1/intel/feeds", map[string][]string{"feeds": {"bogus"}}, nil, nil); got != 400 {
		t.Errorf("an unknown feed: %d", got)
	}
}

// The activity tray is for admins, and says nothing is running when nothing is.
func TestActivityTray(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) { d.Intel = intel.NewService(d.Repo, intel.Config{}) })
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)
	var out struct{ Tasks []api.Task }
	if got := e.call(root, "GET", "/api/v1/activity", nil, &out, nil); got != 200 || out.Tasks == nil || len(out.Tasks) != 0 {
		t.Errorf("idle: %d %+v", got, out)
	}
	if got := e.call(ann, "GET", "/api/v1/activity", nil, nil, nil); got != 403 {
		t.Errorf("a standard user read the activity: %d", got)
	}
}

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
		d.Notify = func(ctx context.Context, a chatnotify.Alert) { d.Slack.Notify(ctx, a) }
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
	// A manually raised alert is announced.
	if got := e.call(root, "POST", "/api/v1/alerts", map[string]any{"title": "Odd login", "severity": 5, "group_by": "user", "group_value": "bob"}, nil, nil); got != 201 {
		t.Fatalf("create alert = %d", got)
	}
	select {
	case msg := <-hook:
		if !strings.Contains(msg, "Odd login") || !strings.Contains(msg, "bob") {
			t.Errorf("announcement = %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Error("the new alert wasn't announced in Slack")
	}
}
