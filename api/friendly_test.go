package api_test

import (
	"fmt"
	"testing"

	"siemlite/api"
	"siemlite/pkg/auth"
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
