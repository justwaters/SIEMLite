package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"siemlite/api"
	"siemlite/pkg/alerts"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/sample"
	"siemlite/pkg/search"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
	"siemlite/pkg/syslogd"
)

const password = "correct horse battery"

var (
	quiet  = slog.New(slog.NewTextHandler(io.Discard, nil))
	errLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
)

// stack is a whole SIEMLite wired the way main.go wires it.
type stack struct {
	t       testing.TB
	dir     string
	db      *storage.DB
	repo    *storage.Repository
	worker  *ingest.Worker
	alerts  *alerts.Engine
	backups *backup.Manager
	syslog  *syslogd.Server
	srv     *httptest.Server
}

func newStack(t testing.TB, withSyslog bool) *stack {
	t.Helper()
	auth.HashCost = bcrypt.MinCost
	slog.SetDefault(quiet)
	ctx := context.Background()
	s := &stack{t: t, dir: t.TempDir()}
	var err error
	if s.db, err = storage.Open(ctx, storage.Options{Path: filepath.Join(s.dir, "siemlite.db")}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	s.repo = storage.NewRepository(s.db)
	s.worker = ingest.New(s.repo, ingest.Config{QueueSize: 50000, Logger: quiet})
	t.Cleanup(s.worker.Close)
	router := sources.New(s.repo)
	authn := auth.New(s.repo, quiet)
	s.alerts = alerts.New(s.repo, quiet)
	if s.backups, err = backup.New(filepath.Join(s.dir, "backups"), s.db, s.repo, quiet); err != nil {
		t.Fatal(err)
	}
	if withSyslog {
		syslogID, err := router.Builtin(ctx, storage.SourceSyslog)
		if err != nil {
			t.Fatal(err)
		}
		s.syslog, err = syslogd.Start(syslogd.Config{
			UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0", Allow: syslogd.DefaultAllow, Logger: quiet,
			Parse: func(ctx context.Context, line string) (*ocsf.Event, map[string]string, error) {
				return router.Parse(ctx, syslogID, line, parser.Defaults{})
			},
			Submit: func(ctx context.Context, ev *ocsf.Event, fields map[string]string) error {
				return s.worker.SubmitWith(ctx, ev, ingest.SubmitOptions{SourceID: syslogID, Fields: fields})
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.syslog.Close() })
	}
	s.srv = httptest.NewUnstartedServer(api.NewServer("", api.Deps{
		DB: s.db, Repo: s.repo, Ingest: s.worker, Search: search.NewEngine(s.repo), Auth: authn, Router: router,
		Sample: sample.NewManager(s.repo, s.worker), Backups: s.backups, Started: time.Now(), Version: "load",
		Audit: audit.New(s.worker, router, quiet), Alerts: s.alerts, Syslog: s.syslog, Logger: errLog,
	}).Handler())
	s.srv.EnableHTTP2 = true
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// client is an HTTPS client with its own cookies.
func (s *stack) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := *s.srv.Client()
	c.Jar = jar
	c.Timeout = 2 * time.Minute
	return &c
}

// call sends body (JSON-encoded unless it's a string) and decodes JSON into out.
func (s *stack) call(c *http.Client, method, path string, body, out any, hdr map[string]string) (int, error) {
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = bytes.NewBufferString(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, s.srv.URL+path, r)
	if err != nil {
		return 0, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && resp.StatusCode < 300 {
			return resp.StatusCode, fmt.Errorf("decode: %w", err)
		}
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	return resp.StatusCode, nil
}

// must is call that fails the test on transport errors or an unexpected status.
func (s *stack) must(c *http.Client, method, path string, body, out any, want int) {
	s.t.Helper()
	got, err := s.call(c, method, path, body, out, nil)
	if err != nil || got != want {
		s.t.Fatalf("%s %s = %d, %v (want %d)", method, path, got, err, want)
	}
}

func (s *stack) user(name, role string, sources []int64) *http.Client {
	s.t.Helper()
	id, err := auth.CreateUser(context.Background(), s.repo, name, password, role)
	if err != nil {
		s.t.Fatal(err)
	}
	if len(sources) > 0 {
		if err := s.repo.UpdateUserAccess(context.Background(), id, role, true, sources); err != nil {
			s.t.Fatal(err)
		}
	}
	c := s.client()
	s.must(c, "POST", "/api/v1/login", map[string]string{"username": name, "password": password}, nil, 200)
	return c
}

// token creates an access token source and returns its id and token.
func (s *stack) token(admin *http.Client, name string) (int64, string) {
	s.t.Helper()
	var res struct {
		Source storage.Source `json:"source"`
		Token  string         `json:"token"`
	}
	s.must(admin, "POST", "/api/v1/sources", map[string]any{"name": name}, &res, 201)
	return res.Source.ID, res.Token
}

func (s *stack) count(where string, args ...any) int64 {
	s.t.Helper()
	var n int64
	if err := s.db.Write.QueryRow("SELECT COUNT(*) FROM events WHERE "+where, args...).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

// healthy checks the database and search index are intact.
func (s *stack) healthy() {
	s.t.Helper()
	var res string
	if err := s.db.Write.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil || res != "ok" {
		s.t.Errorf("integrity_check = %q, %v", res, err)
	}
	if _, err := s.db.Write.Exec(`INSERT INTO events_fts(events_fts) VALUES ('integrity-check')`); err != nil {
		s.t.Errorf("search index: %v", err)
	}
}
