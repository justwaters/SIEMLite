package api_test

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/search"
	"siemlite/pkg/secaudit"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
)

func TestSecurityAuditAPI(t *testing.T) {
	auth.HashCost = bcrypt.MinCost
	ctx := context.Background()
	dir := t.TempDir()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	worker := ingest.New(repo, ingest.Config{FlushInterval: 20 * time.Millisecond})
	t.Cleanup(worker.Close)
	key := filepath.Join(dir, "siemlite.key")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(api.NewServer("", api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: search.NewEngine(repo), Auth: auth.New(repo, nil), Router: sources.New(repo),
		Started: time.Now(), Version: "v9",
		SecAudit:  secaudit.New(repo, "testhost"),
		SecConfig: secaudit.Config{SecretKeyPath: key, Addr: "localhost:8443"},
	}).Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, repo: repo, worker: worker}
	e.user("root", auth.RoleAdmin)
	e.user("pat", auth.RoleStandard)
	root, pat := e.client(), e.client()
	e.login(root, "root", password)
	e.login(pat, "pat", password)

	// Standard users and visitors can't see how the server could be attacked.
	for _, c := range []string{"GET /api/v1/security-audit", "POST /api/v1/security-audit/run", "GET /api/v1/security-audit/report",
		"POST /api/v1/security-audit/checks/siem.perms/fix", "PUT /api/v1/security-audit/checks/siem.perms/accept"} {
		m, p, _ := strings.Cut(c, " ")
		if got := e.call(pat, m, p, nil, nil, nil); got != 403 {
			t.Errorf("standard user %s = %d, want 403", c, got)
		}
		if got := e.call(e.client(), m, p, nil, nil, nil); got != 401 {
			t.Errorf("visitor %s = %d, want 401", c, got)
		}
	}

	var st secaudit.State
	if got := e.call(root, "GET", "/api/v1/security-audit", nil, &st, nil); got != 200 || st.Last != nil || len(st.History) != 0 {
		t.Fatalf("before any run = %d %+v", got, st)
	}
	if got := e.call(root, "GET", "/api/v1/security-audit/report", nil, nil, nil); got != 409 {
		t.Errorf("report before a run = %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/security-audit/checks/siem.perms/recheck", nil, nil, nil); got != 409 {
		t.Errorf("recheck before a run = %d", got)
	}

	if got := e.call(root, "POST", "/api/v1/security-audit/run", nil, &st, nil); got != 200 || st.Last == nil || len(st.History) != 1 {
		t.Fatalf("run = %d %+v", got, st)
	}
	status := func(id string) secaudit.Result {
		for _, r := range st.Last.Results {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("no result %s", id)
		return secaudit.Result{}
	}
	if p := status("siem.perms"); p.Status != secaudit.Fail || !p.CanApply {
		t.Fatalf("perms = %+v", p)
	}
	if st.Last.By != "root" || st.Last.Host != "testhost" || st.Last.Version != "v9" || st.Last.Counts.Fail == 0 {
		t.Errorf("run = %+v", st.Last.Counts)
	}

	// Accept, then withdraw.
	if got := e.call(root, "PUT", "/api/v1/security-audit/checks/siem.perms/accept", map[string]string{"note": " "}, nil, nil); got != 400 {
		t.Errorf("accept without a reason = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/security-audit/checks/siem.perms/accept", map[string]string{"note": "lab"}, &st, nil); got != 200 || status("siem.perms").Accepted == nil {
		t.Errorf("accept = %d %+v", got, status("siem.perms"))
	}
	st = secaudit.State{}
	if got := e.call(root, "DELETE", "/api/v1/security-audit/checks/siem.perms/accept", nil, &st, nil); got != 200 || status("siem.perms").Accepted != nil {
		t.Errorf("unaccept = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/security-audit/checks/nope/accept", map[string]string{"note": "x"}, nil, nil); got != 404 {
		t.Errorf("accept unknown = %d", got)
	}

	// Fix it, and the recheck reports it resolved.
	var fixed struct {
		Message string          `json:"message"`
		Result  secaudit.Result `json:"result"`
		Counts  secaudit.Counts `json:"counts"`
	}
	if got := e.call(root, "POST", "/api/v1/security-audit/checks/siem.perms/fix", nil, &fixed, nil); got != 200 ||
		fixed.Result.Status != secaudit.Pass || fixed.Result.Change != "resolved" {
		t.Fatalf("fix = %d %+v", got, fixed)
	}
	if info, _ := os.Stat(key); info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o", info.Mode().Perm())
	}
	if got := e.call(root, "POST", "/api/v1/security-audit/checks/siem.backups/fix", nil, nil, nil); got != 409 {
		t.Errorf("fix without a fix = %d", got)
	}
	var rc struct {
		Result secaudit.Result `json:"result"`
	}
	if got := e.call(root, "POST", "/api/v1/security-audit/checks/siem.perms/recheck", nil, &rc, nil); got != 200 || rc.Result.Status != secaudit.Pass {
		t.Errorf("recheck = %d %+v", got, rc)
	}

	resp, err := root.Get(srv.URL + "/api/v1/security-audit/report")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), ".md") || !strings.Contains(string(body), "# SIEMLite security audit") {
		t.Errorf("report = %d %s %.60s", resp.StatusCode, resp.Header.Get("Content-Disposition"), body)
	}
	resp, err = root.Get(srv.URL + "/api/v1/security-audit/report?format=json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Disposition"), ".json") {
		t.Errorf("json report = %s", resp.Header.Get("Content-Disposition"))
	}
}
