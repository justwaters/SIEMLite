package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

func TestRoleEnforcement(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	worker := ingest.New(repo, ingest.Config{FlushInterval: 20 * time.Millisecond})
	defer worker.Close()

	srv := httptest.NewTLSServer(api.NewServer("", api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: search.NewEngine(repo), Auth: auth.New(repo, nil),
	}).Handler())
	defer srv.Close()

	mk := func(role auth.Role) (int64, string) {
		id, key, err := auth.CreateKey(ctx, repo, string(role), role)
		if err != nil {
			t.Fatal(err)
		}
		return id, key
	}
	_, writeKey := mk(auth.RoleWrite)
	_, readKey := mk(auth.RoleRead)
	_, adminKey := mk(auth.RoleAdmin)
	revokedID, revokedKey := mk(auth.RoleAdmin)
	if _, err := repo.RevokeKey(ctx, revokedID, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}

	do := func(method, path, key, body string) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	const line = "Failed password for root from 203.0.113.7"
	cases := []struct {
		name, method, path, key, body string
		want                          int
	}{
		{"ingest no key", "POST", "/api/v1/logs", "", line, 401},
		{"ingest bad key", "POST", "/api/v1/logs", "slk_nope", line, 401},
		{"ingest revoked key", "POST", "/api/v1/logs", revokedKey, line, 401},
		{"ingest write key", "POST", "/api/v1/logs", writeKey, line, 202},
		{"ingest admin key", "POST", "/api/v1/logs", adminKey, line, 202},
		{"ingest read key forbidden", "POST", "/api/v1/logs", readKey, line, 403},
		{"search no key", "GET", "/api/v1/search", "", "", 401},
		{"search write key forbidden", "GET", "/api/v1/search", writeKey, "", 403},
		{"search read key", "GET", "/api/v1/search", readKey, "", 200},
		{"events write key", "POST", "/api/v1/events", writeKey, "[]", 400}, // authorized, empty body rejected
		{"events read key forbidden", "POST", "/api/v1/events", readKey, "[]", 403},
		{"health public", "GET", "/health", "", "", 200},
		{"ui public", "GET", "/", "", "", 200},
	}
	for _, c := range cases {
		if got := do(c.method, c.path, c.key, c.body); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
}
