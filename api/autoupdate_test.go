package api_test

import (
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
	if got := e.call(root, "GET", "/api/v1/system/update/auto", nil, &st, nil); got != 200 || st.Enabled || len(st.Times) != 1 || st.Timezone == "" {
		t.Fatalf("default = %d %+v", got, st)
	}
	body := map[string]any{"enabled": true, "days": []int{1, 3}, "times": []string{"23:30", "04:05"}, "backup_first": true}
	if got := e.call(root, "PUT", "/api/v1/system/update/auto", body, &st, nil); got != 200 || !st.Enabled || st.Times[0] != "04:05" || st.Next == 0 {
		t.Fatalf("save = %d %+v", got, st)
	}
	var again update.AutoState
	e.call(root, "GET", "/api/v1/system/update/auto", nil, &again, nil)
	if !again.Enabled || len(again.Days) != 2 || !again.BackupFirst {
		t.Errorf("not kept: %+v", again)
	}
	for name, bad := range map[string]map[string]any{
		"bad time":          {"enabled": true, "times": []string{"25:61"}},
		"no times while on": {"enabled": true, "times": []string{}},
		"bad day":           {"enabled": false, "days": []int{9}, "times": []string{"01:00"}},
		"five times":        {"enabled": true, "times": []string{"01:00", "02:00", "03:00", "04:00", "05:00"}},
		"wrong type":        {"enabled": "yes"},
	} {
		if got := e.call(root, "PUT", "/api/v1/system/update/auto", bad, nil, nil); got != 400 {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	e.call(root, "GET", "/api/v1/system/update/auto", nil, &again, nil)
	if !again.Enabled || len(again.Times) != 2 {
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
