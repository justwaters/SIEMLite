package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/ingest"
	"siemlite/pkg/search"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
)

func TestBackupsAPI(t *testing.T) {
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
	backups, err := backup.New(filepath.Join(dir, "backups"), db, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(api.NewServer("", api.Deps{
		DB: db, Repo: repo, Ingest: worker, Search: search.NewEngine(repo), Auth: auth.New(repo, nil), Router: sources.New(repo),
		Backups: backups, Started: time.Now(), Restart: func() { restarted <- struct{}{} },
	}).Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, repo: repo, worker: worker}
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	var sys map[string]any
	if got := e.call(root, "GET", "/api/v1/system", nil, &sys, nil); got != 200 || sys["backups"] == nil {
		t.Fatalf("system = %d %v", got, sys)
	}
	// Updates are off here (no checker): status still answers, applying doesn't.
	var upd map[string]any
	if got := e.call(root, "GET", "/api/v1/system/update", nil, &upd, nil); got != 200 || upd["available"] != false {
		t.Errorf("update status = %d %v", got, upd)
	}
	if got := e.call(root, "POST", "/api/v1/system/update", nil, nil, nil); got != 501 {
		t.Errorf("apply without a checker = %d", got)
	}
	if got := e.call(root, "POST", "/api/v1/backups", nil, nil, nil); got != 202 {
		t.Fatalf("create = %d", got)
	}
	type listing struct {
		Backups  []backup.Backup `json:"backups"`
		Status   backup.Status   `json:"status"`
		Settings backup.Settings `json:"settings"`
	}
	var l listing
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.call(root, "GET", "/api/v1/backups", nil, &l, nil)
		if !l.Status.Running && len(l.Backups) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(l.Backups) != 1 || l.Backups[0].Kind != backup.Manual || l.Status.LastError != "" {
		t.Fatalf("after create: %+v", l)
	}
	name := l.Backups[0].Name

	// Download returns the gzip file.
	resp, err := root.Get(srv.URL + "/api/v1/backups/" + name)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) < 2 || body[0] != 0x1f || !strings.Contains(resp.Header.Get("Content-Disposition"), name) {
		t.Errorf("download = %d, %d bytes, %q", resp.StatusCode, len(body), resp.Header.Get("Content-Disposition"))
	}
	// Uploading it back works; junk doesn't.
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/backups/upload", strings.NewReader(string(body)))
	if resp, err := root.Do(req); err != nil || resp.StatusCode != 201 {
		t.Errorf("upload = %v %v", resp.StatusCode, err)
	}
	if got := e.call(root, "POST", "/api/v1/backups/upload", "junk", nil, nil); got != 400 {
		t.Errorf("junk upload = %d", got)
	}

	if got := e.call(root, "PUT", "/api/v1/backups/settings", map[string]int{"interval_hours": 24, "keep": 5}, nil, nil); got != 200 {
		t.Errorf("settings = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/backups/settings", map[string]int{"interval_hours": 3, "keep": 5}, nil, nil); got != 400 {
		t.Errorf("bad settings = %d", got)
	}
	if got := e.call(root, "DELETE", "/api/v1/backups/../t.db", nil, nil, nil); got == 200 {
		t.Error("deleted outside the backups folder")
	}

	// Restore saves the current database and asks for a restart.
	var res map[string]any
	if got := e.call(root, "POST", "/api/v1/backups/"+name+"/restore", nil, &res, nil); got != 202 || res["saved_current_as"] == nil {
		t.Fatalf("restore = %d %v", got, res)
	}
	select {
	case <-restarted:
	case <-time.After(3 * time.Second):
		t.Fatal("restore didn't restart the server")
	}
	if _, err := backup.ApplyPendingRestore(db.Path(), nil); err != nil {
		t.Errorf("staged restore isn't valid: %v", err)
	}
	if got := e.call(root, "DELETE", "/api/v1/backups/"+name, nil, nil, nil); got != 200 {
		t.Errorf("delete = %d", got)
	}
}
