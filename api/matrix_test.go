package api_test

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"siemlite/pkg/auth"
)

// route is one registered API route and the permission it is registered with.
type route struct{ method, path, perm string }

// routes reads the route table from server.go, so a route added without a
// matching expectation here is still checked.
func routes(t *testing.T) []route {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	pat := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) (/[^"]*)"`)
	var out []route
	for _, ln := range strings.Split(string(src), "\n") {
		m := pat.FindStringSubmatch(ln)
		if m == nil || m[2] == "/" {
			continue
		}
		perm := "public"
		switch {
		case strings.Contains(ln, "admin("), strings.Contains(ln, "auth.PermAdmin"):
			perm = "admin"
		case strings.Contains(ln, "auth.PermSearch"):
			perm = "search"
		case strings.Contains(ln, "auth.PermIngest"):
			perm = "ingest"
		case strings.Contains(ln, "mux.Handle("):
			t.Fatalf("route without a known permission: %s", strings.TrimSpace(ln))
		}
		path := strings.NewReplacer("{id}", "999999", "{name}", "siemlite-20000101-000000-manual.db.gz").Replace(m[2])
		out = append(out, route{m[1], path, perm})
	}
	if len(out) < 35 {
		t.Fatalf("found only %d routes in server.go; has the route table moved?", len(out))
	}
	return out
}

// TestAuthMatrix checks every route against every kind of caller.
func TestAuthMatrix(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	_, key, _ := auth.CreateKey(context.Background(), e.repo, "app", nil, false)
	bearer := map[string]string{"Authorization": "Bearer " + key}
	sam, root := e.client(), e.client()
	expect(t, "sam login", e.login(sam, "sam", password), 200)
	expect(t, "root login", e.login(root, "root", password), 200)
	evil := map[string]string{"Origin": "https://evil.example"}

	allowed := func(got int) bool { return got != 401 && got != 403 }
	for _, rt := range routes(t) {
		if rt.perm == "public" {
			continue
		}
		name := rt.method + " " + rt.path
		// No credentials, a bad key and a bad cookie are all 401.
		if got := e.call(e.client(), rt.method, rt.path, map[string]any{}, nil, nil); got != 401 {
			t.Errorf("anonymous %s = %d, want 401", name, got)
		}
		if got := e.call(e.client(), rt.method, rt.path, map[string]any{}, nil, map[string]string{"Authorization": "Bearer slk_nope"}); got != 401 {
			t.Errorf("bad key %s = %d, want 401", name, got)
		}
		if got := e.call(e.client(), rt.method, rt.path, map[string]any{}, nil, map[string]string{"Cookie": auth.CookieName + "=forged"}); got != 401 {
			t.Errorf("forged cookie %s = %d, want 401", name, got)
		}

		got := e.call(e.client(), rt.method, rt.path, map[string]any{}, nil, bearer)
		if want := rt.perm == "ingest"; allowed(got) != want {
			t.Errorf("API key %s = %d (allowed %v)", name, got, want)
		}
		got = e.call(sam, rt.method, rt.path, map[string]any{}, nil, nil)
		if want := rt.perm == "search"; allowed(got) != want {
			t.Errorf("standard user %s = %d (allowed %v)", name, got, want)
		}
		// Admins reach every route, except cross-site writes.
		if got := e.call(root, rt.method, rt.path, map[string]any{}, nil, nil); !allowed(got) {
			t.Errorf("admin %s = %d, want allowed", name, got)
		}
		if rt.method != http.MethodGet {
			if got := e.call(root, rt.method, rt.path, map[string]any{}, nil, evil); got != 403 {
				t.Errorf("cross-origin admin %s = %d, want 403", name, got)
			}
		}
	}
}

// TestRestrictedUsersCannotSeeAlerts: alerts summarize every source, so a
// user limited to some sources is refused even read access.
func TestRestrictedUsersCannotSeeAlerts(t *testing.T) {
	e := newEnv(t)
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)
	var src struct {
		Source struct{ ID int64 } `json:"source"`
	}
	e.call(root, "POST", "/api/v1/sources", map[string]any{"name": "web"}, &src, nil)
	if got := e.call(root, "POST", "/api/v1/users", map[string]any{
		"username": "sam", "password": password, "role": "standard", "sources": []int64{src.Source.ID},
	}, nil, nil); got != 201 {
		t.Fatalf("create user = %d", got)
	}
	sam := e.client()
	e.login(sam, "sam", password)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/v1/alerts"}, {"PATCH", "/api/v1/alerts/1"},
	} {
		if got := e.call(sam, rt.method, rt.path, map[string]any{"status": "closed"}, nil, nil); got != 403 {
			t.Errorf("limited user %s %s = %d, want 403", rt.method, rt.path, got)
		}
	}
	var stats map[string]any
	e.call(sam, "GET", "/api/v1/stats", nil, &stats, nil)
	if _, ok := stats["open_alerts"]; ok {
		t.Errorf("limited user sees the open alert count: %v", stats["open_alerts"])
	}
}
