package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/update"
)

// The auto-update schedule: admins read and save it, bad times and days are refused, and it is
// kept between reads; others are refused.
func TestAutoUpdateSchedule(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) {
		c := update.New("v0.9", "/nonexistent/siemlite")
		d.Updates = c
		d.AutoUpdate = &update.Auto{Checker: c, Store: d.Repo}
	})
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann, anon := e.client(), e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)

	var st update.AutoState
	if got := e.call(root, "GET", "/api/v1/system/update/auto", nil, &st, nil); got != 200 || st.Enabled || len(st.Schedules) != 1 || st.Timezone == "" || !st.HoldForAlerts {
		t.Fatalf("default = %d %+v", got, st)
	}
	body := map[string]any{"enabled": true, "backup_first": true, "hold_for_alerts": false, "schedules": []map[string]any{
		{"days": []int{1, 2, 3, 4, 5}, "times": []string{"23:30", "04:05"}},
		{"days": []int{0, 6}, "times": []string{"06:00"}},
	}}
	if got := e.call(root, "PUT", "/api/v1/system/update/auto", body, &st, nil); got != 200 || !st.Enabled || st.Schedules[0].Times[0] != "04:05" || st.Next == 0 {
		t.Fatalf("save = %d %+v", got, st)
	}
	var again update.AutoState
	e.call(root, "GET", "/api/v1/system/update/auto", nil, &again, nil)
	if !again.Enabled || len(again.Schedules) != 2 || len(again.Schedules[1].Days) != 2 || !again.BackupFirst || again.HoldForAlerts {
		t.Errorf("not kept: %+v", again)
	}
	for name, bad := range map[string]map[string]any{
		"bad time":                {"enabled": true, "schedules": []map[string]any{{"times": []string{"25:61"}}}},
		"no schedule while on":    {"enabled": true, "schedules": []map[string]any{}},
		"empty schedule while on": {"enabled": true, "schedules": []map[string]any{{"times": []string{"01:00"}}, {"days": []int{1}, "times": []string{}}}},
		"bad day":                 {"enabled": false, "schedules": []map[string]any{{"days": []int{9}, "times": []string{"01:00"}}}},
		"five times":              {"enabled": true, "schedules": []map[string]any{{"times": []string{"01:00", "02:00", "03:00", "04:00", "05:00"}}}},
		"wrong type":              {"enabled": "yes"},
	} {
		if got := e.call(root, "PUT", "/api/v1/system/update/auto", bad, nil, nil); got != 400 {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	e.call(root, "GET", "/api/v1/system/update/auto", nil, &again, nil)
	if !again.Enabled || len(again.Schedules) != 2 {
		t.Errorf("a refused save changed the schedule: %+v", again)
	}
	if got := e.call(ann, "GET", "/api/v1/system/update/auto", nil, nil, nil); got != 403 {
		t.Errorf("standard user read = %d", got)
	}
	if got := e.call(ann, "PUT", "/api/v1/system/update/auto", body, nil, nil); got != 403 {
		t.Errorf("standard user save = %d", got)
	}
	if got := e.call(anon, "GET", "/api/v1/system/update/auto", nil, nil, nil); got != 401 {
		t.Errorf("anonymous = %d", got)
	}
}

// With update checks off there is no schedule to read or save.
func TestAutoUpdateOff(t *testing.T) {
	e := newEnvWith(t, nil)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	if got := e.call(root, "GET", "/api/v1/system/update/auto", nil, nil, nil); got != 501 {
		t.Errorf("GET = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/system/update/auto", map[string]any{"enabled": false}, nil, nil); got != 501 {
		t.Errorf("PUT = %d", got)
	}
}

// The release channel: Stable by default; an admin picks Beta, it is remembered and audited;
// anything else is refused; others can't change it.
func TestUpdateChannel(t *testing.T) {
	e := newEnvWith(t, func(d *api.Deps) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/latest") {
				fmt.Fprint(w, `{"tag_name":"v0.33","html_url":"https://example.test/s"}`)
				return
			}
			fmt.Fprint(w, `[{"tag_name":"v0.34-beta.1","html_url":"https://example.test/b","prerelease":true},{"tag_name":"v0.33","html_url":"https://example.test/s"}]`)
		}))
		t.Cleanup(srv.Close)
		c := update.New("v0.32", "/nonexistent/siemlite")
		c.API, c.ListAPI = srv.URL+"/latest", srv.URL+"/list"
		d.Updates = c
	})
	e.user("root", auth.RoleAdmin)
	e.user("ann", auth.RoleStandard)
	root, ann := e.client(), e.client()
	e.login(root, "root", password)
	e.login(ann, "ann", password)

	var st update.Status
	if got := e.call(root, "GET", "/api/v1/system/update?refresh=1", nil, &st, nil); got != 200 || st.Channel != "stable" || st.Latest != "v0.33" {
		t.Fatalf("default = %d %+v", got, st)
	}
	if got := e.call(root, "PUT", "/api/v1/system/update/channel", map[string]any{"channel": "beta"}, &st, nil); got != 200 || st.Channel != "beta" || st.Latest != "v0.34-beta.1" || !st.Prerelease {
		t.Fatalf("beta = %d %+v", got, st)
	}
	if v, _ := e.deps.Repo.Setting(t.Context(), update.ChannelKey, ""); v != "beta" {
		t.Errorf("saved channel %q", v)
	}
	e.call(root, "GET", "/api/v1/system/update", nil, &st, nil)
	if st.Channel != "beta" {
		t.Errorf("not kept: %+v", st)
	}
	for _, bad := range []any{map[string]any{"channel": "nightly"}, map[string]any{"channel": ""}, map[string]any{"channel": 5}, map[string]any{}} {
		if got := e.call(root, "PUT", "/api/v1/system/update/channel", bad, nil, nil); got != 400 {
			t.Errorf("%v = %d, want 400", bad, got)
		}
	}
	if got := e.call(ann, "PUT", "/api/v1/system/update/channel", map[string]any{"channel": "stable"}, nil, nil); got != 403 {
		t.Errorf("standard user = %d", got)
	}
	if got := e.call(e.client(), "PUT", "/api/v1/system/update/channel", map[string]any{"channel": "stable"}, nil, nil); got != 401 {
		t.Errorf("anonymous = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/system/update/channel", map[string]any{"channel": "stable"}, &st, nil); got != 200 || st.Latest != "v0.33" {
		t.Errorf("back to stable = %d %+v", got, st)
	}
}

func TestUpdateChannelOff(t *testing.T) {
	e := newEnvWith(t, nil)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	if got := e.call(root, "PUT", "/api/v1/system/update/channel", map[string]any{"channel": "beta"}, nil, nil); got != 501 {
		t.Errorf("without a checker = %d", got)
	}
}
