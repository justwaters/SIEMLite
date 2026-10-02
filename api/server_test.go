package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

const password = "correct horse battery"

type env struct {
	t    *testing.T
	srv  *httptest.Server
	repo *storage.Repository
}

func newEnv(t *testing.T) *env {
	t.Helper()
	auth.HashCost = bcrypt.MinCost // keep tests fast

	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	worker := ingest.New(repo, ingest.Config{FlushInterval: 20 * time.Millisecond})
	t.Cleanup(worker.Close)

	srv := httptest.NewTLSServer(api.NewServer("", api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: search.NewEngine(repo), Auth: auth.New(repo, nil),
	}).Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, repo: repo}
}

func (e *env) user(name, role string) {
	e.t.Helper()
	if _, err := auth.CreateUser(context.Background(), e.repo, name, password, role); err != nil {
		e.t.Fatal(err)
	}
}

// client returns an HTTP client with its own cookie jar.
func (e *env) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.srv.Client()
	c.Jar = jar
	return c
}

func (e *env) do(c *http.Client, method, path, body string, hdr map[string]string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (e *env) login(c *http.Client, user, pw string) *http.Response {
	b, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	return e.do(c, "POST", "/api/v1/login", string(b), nil)
}

func expect(t *testing.T, name string, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Errorf("%s: status %d, want %d", name, resp.StatusCode, want)
	}
}

const line = "Failed password for root from 203.0.113.7"

func TestAPIKeysCanOnlySendLogs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, key, err := auth.CreateKey(ctx, e.repo, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	revokedID, revoked, _ := auth.CreateKey(ctx, e.repo, "old")
	e.repo.RevokeKey(ctx, revokedID, time.Now().UnixMilli())
	bearer := func(k string) map[string]string { return map[string]string{"Authorization": "Bearer " + k} }
	c := e.client()

	expect(t, "logs, no credentials", e.do(c, "POST", "/api/v1/logs", line, nil), 401)
	expect(t, "logs, bad key", e.do(c, "POST", "/api/v1/logs", line, bearer("slk_nope")), 401)
	expect(t, "logs, revoked key", e.do(c, "POST", "/api/v1/logs", line, bearer(revoked)), 401)
	expect(t, "logs, valid key", e.do(c, "POST", "/api/v1/logs", line, bearer(key)), 202)
	expect(t, "events, valid key", e.do(c, "POST", "/api/v1/events", "[]", bearer(key)), 400) // authorized; empty body rejected
	expect(t, "search, key forbidden", e.do(c, "GET", "/api/v1/search", "", bearer(key)), 403)
	expect(t, "login endpoint rejects key as session", e.do(c, "GET", "/api/v1/me", "", bearer(key)), 401)
}

func TestUserSessions(t *testing.T) {
	e := newEnv(t)
	e.user("alice", auth.RoleAnalyst)
	e.user("root", auth.RoleAdmin)

	anon := e.client()
	expect(t, "search, anonymous", e.do(anon, "GET", "/api/v1/search", "", nil), 401)
	expect(t, "me, anonymous", e.do(anon, "GET", "/api/v1/me", "", nil), 401)
	expect(t, "wrong password", e.login(anon, "alice", "not the password"), 401)
	expect(t, "unknown user", e.login(anon, "nobody", password), 401)

	// Analyst: may search, may not add logs.
	alice := e.client()
	resp := e.login(alice, "ALICE", password) // usernames are case-insensitive
	expect(t, "analyst login", resp, 200)
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie must be HttpOnly, Secure and SameSite=Strict, got %+v", cookie)
	}
	expect(t, "analyst search", e.do(alice, "GET", "/api/v1/search", "", nil), 200)
	expect(t, "analyst me", e.do(alice, "GET", "/api/v1/me", "", nil), 200)
	expect(t, "analyst add logs", e.do(alice, "POST", "/api/v1/logs", line, nil), 403)

	// Admin: may do both.
	root := e.client()
	expect(t, "admin login", e.login(root, "root", password), 200)
	expect(t, "admin search", e.do(root, "GET", "/api/v1/search", "", nil), 200)
	expect(t, "admin add logs", e.do(root, "POST", "/api/v1/logs", line, nil), 202)

	// Cross-origin writes with a valid cookie are refused.
	expect(t, "cross-origin add logs", e.do(root, "POST", "/api/v1/logs", line,
		map[string]string{"Origin": "https://evil.example"}), 403)
	expect(t, "cross-origin login", e.login2(anon, "https://evil.example"), 403)

	// Sign out ends the session server-side.
	expect(t, "logout", e.do(alice, "POST", "/api/v1/logout", "", nil), 200)
	expect(t, "search after logout", e.do(alice, "GET", "/api/v1/search", "", nil), 401)
	// Changing a password signs the user out everywhere.
	if err := auth.SetPassword(context.Background(), e.repo, "root", "a brand new password"); err != nil {
		t.Fatal(err)
	}
	expect(t, "admin session after password change", e.do(root, "GET", "/api/v1/search", "", nil), 401)
	expect(t, "old password", e.login(e.client(), "root", password), 401)
	expect(t, "new password", e.login(e.client(), "root", "a brand new password"), 200)
}

func (e *env) login2(c *http.Client, origin string) *http.Response {
	b, _ := json.Marshal(map[string]string{"username": "alice", "password": password})
	return e.do(c, "POST", "/api/v1/login", string(b), map[string]string{"Origin": origin})
}

func TestHealthDetailNeedsSignIn(t *testing.T) {
	e := newEnv(t)
	e.user("alice", auth.RoleAnalyst)

	get := func(c *http.Client) string {
		req, _ := http.NewRequest("GET", e.srv.URL+"/health", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		if _, ok := body["database"]; ok {
			return "detailed"
		}
		return "basic"
	}
	anon := e.client()
	if got := get(anon); got != "basic" {
		t.Errorf("anonymous health = %s, want basic", got)
	}
	alice := e.client()
	e.login(alice, "alice", password)
	if got := get(alice); got != "detailed" {
		t.Errorf("signed-in health = %s, want detailed", got)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	e.user("alice", auth.RoleAnalyst)
	c := e.client()
	for i := 0; i < 10; i++ {
		expect(t, "failed attempt", e.login(c, "alice", "wrong password!"), 401)
	}
	// Even the right password is refused while locked out.
	expect(t, "locked out", e.login(c, "alice", password), 429)
}

func TestPasswordPolicy(t *testing.T) {
	e := newEnv(t)
	if _, err := auth.CreateUser(context.Background(), e.repo, "bob", "short", auth.RoleAdmin); err == nil {
		t.Error("short password accepted")
	}
	if _, err := auth.CreateUser(context.Background(), e.repo, "bob", password, "superuser"); err == nil {
		t.Error("unknown role accepted")
	}
}
