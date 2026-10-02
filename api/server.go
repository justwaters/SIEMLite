// Package api exposes SIEMLite over HTTP.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/intel"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
	"siemlite/pkg/syslogd"
	"siemlite/web"
)

const (
	maxBodyBytes   = 16 << 20
	maxBatchEvents = 10000
	maxLogLines    = 100000
	submitTimeout  = 5 * time.Second
)

// Deps are the components the server fronts.
type Deps struct {
	DB     *storage.DB
	Repo   *storage.Repository
	Ingest *ingest.Worker
	Search *search.Engine
	Auth   *auth.Authenticator
	Intel  *intel.Service  // optional
	Syslog *syslogd.Server // optional
	Logger *slog.Logger
}

// Server is the HTTP API.
type Server struct {
	deps Deps
	http *http.Server
}

// NewServer builds a server listening on addr once Start is called.
func NewServer(addr string, deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	s := &Server{deps: deps}
	s.http = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s
}

// Handler returns the routed handler (useful for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	a := s.deps.Auth
	// Applications authenticate with an API key (send-only); people with a
	// user session. See pkg/auth for the permission model.
	mux.Handle("POST /api/v1/events", a.Require(auth.PermIngest, http.HandlerFunc(s.handleIngest)))
	mux.Handle("POST /api/v1/logs", a.Require(auth.PermIngest, http.HandlerFunc(s.handleLogs)))
	mux.Handle("GET /api/v1/search", a.Require(auth.PermSearch, http.HandlerFunc(s.handleSearch)))
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/me", s.handleMe)
	// /health is public but only reveals up/down; detail needs a signed-in user.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /", web.Handler())
	return s.recoverer(mux)
}

// Start serves HTTPS (there is no plaintext listener) until Shutdown; it
// returns nil on a clean shutdown.
func (s *Server) Start(certFile, keyFile string) error {
	s.http.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if err := s.http.ListenAndServeTLS(certFile, keyFile); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.deps.Logger.Error("panic in handler", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type ingestError struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

type ingestResponse struct {
	Accepted int           `json:"accepted"`
	Rejected int           `json:"rejected"`
	Errors   []ingestError `json:"errors,omitempty"`
}

// handleIngest accepts a JSON array of OCSF events (a single object is also
// tolerated). Valid events are queued; invalid ones are reported by index.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}

	var events []ocsf.Event
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '{' {
		var one ocsf.Event
		if err := json.Unmarshal(trimmed, &one); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		events = []ocsf.Event{one}
	} else if err := json.Unmarshal(body, &events); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON array of events: "+err.Error())
		return
	}
	if len(events) == 0 {
		writeError(w, http.StatusBadRequest, "no events supplied")
		return
	}
	if len(events) > maxBatchEvents {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("at most %d events per request", maxBatchEvents))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), submitTimeout)
	defer cancel()

	var resp ingestResponse
	for i := range events {
		err := s.deps.Ingest.Submit(ctx, &events[i])
		var verr *ocsf.ValidationError
		switch {
		case err == nil:
			resp.Accepted++
		case errors.As(err, &verr):
			resp.Rejected++
			resp.Errors = append(resp.Errors, ingestError{Index: i, Error: err.Error()})
		default:
			// Queue saturated, shutting down, or client gone: tell the caller
			// how far we got so it can retry the remainder.
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":            "ingest queue unavailable: " + err.Error(),
				"accepted":         resp.Accepted,
				"stopped_at_index": i,
			})
			return
		}
	}

	status := http.StatusAccepted
	if resp.Accepted == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, resp)
}

// handleLogs stores raw log text: one log per line. Syslog, JSON lines and
// plain text are parsed into OCSF events; the original line is kept verbatim.
// Optional query params: source (product name), severity (override, 0-6/99).
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}

	defaults := parser.Defaults{Source: r.URL.Query().Get("source")}
	if defaults.SeverityID, err = parseOptInt(r.URL.Query().Get("severity")); err != nil {
		writeError(w, http.StatusBadRequest, "severity: "+err.Error())
		return
	}

	lines := bytes.Split(body, []byte("\n"))
	events := make([]*ocsf.Event, 0, len(lines))
	for _, l := range lines {
		if ev := parser.ParseLine(string(l), defaults); ev != nil {
			events = append(events, ev)
		}
	}
	if len(events) == 0 {
		writeError(w, http.StatusBadRequest, "no log lines supplied")
		return
	}
	if len(events) > maxLogLines {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("at most %d lines per request", maxLogLines))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), submitTimeout)
	defer cancel()

	var resp ingestResponse
	for i, ev := range events {
		err := s.deps.Ingest.Submit(ctx, ev)
		var verr *ocsf.ValidationError
		switch {
		case err == nil:
			resp.Accepted++
		case errors.As(err, &verr):
			resp.Rejected++
			if len(resp.Errors) < 20 {
				resp.Errors = append(resp.Errors, ingestError{Index: i, Error: err.Error()})
			}
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":            "ingest queue unavailable: " + err.Error(),
				"accepted":         resp.Accepted,
				"stopped_at_index": i,
			})
			return
		}
	}
	status := http.StatusAccepted
	if resp.Accepted == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, resp)
}

// handleSearch maps query parameters onto a search.Query.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query()
	q := search.Query{
		Text:     p.Get("q"),
		SrcIP:    p.Get("src_ip"),
		DstIP:    p.Get("dst_ip"),
		UserName: p.Get("user"),
		Source:   p.Get("source"),
		Host:     p.Get("host"),
		Country:  p.Get("country"),
	}
	switch p.Get("threat") {
	case "", "0", "false":
	case "1", "true":
		q.ThreatOnly = true
	default:
		writeError(w, http.StatusBadRequest, "threat: must be true or false")
		return
	}

	var err error
	if q.Start, err = parseTime(p.Get("start")); err != nil {
		writeError(w, http.StatusBadRequest, "start: "+err.Error())
		return
	}
	if q.End, err = parseTime(p.Get("end")); err != nil {
		writeError(w, http.StatusBadRequest, "end: "+err.Error())
		return
	}
	for _, f := range []struct {
		name string
		dst  **int
	}{{"severity", &q.SeverityID}, {"category", &q.CategoryUID}, {"class", &q.ClassUID}} {
		if *f.dst, err = parseOptInt(p.Get(f.name)); err != nil {
			writeError(w, http.StatusBadRequest, f.name+": "+err.Error())
			return
		}
	}
	if v := p.Get("asn"); v != "" {
		if q.ASN, err = strconv.Atoi(strings.TrimPrefix(strings.ToUpper(v), "AS")); err != nil {
			writeError(w, http.StatusBadRequest, "asn: must be a number like 15169 or AS15169")
			return
		}
	}
	if v := p.Get("limit"); v != "" {
		if q.Limit, err = strconv.Atoi(v); err != nil {
			writeError(w, http.StatusBadRequest, "limit: must be an integer")
			return
		}
	}
	if v := p.Get("offset"); v != "" {
		if q.Offset, err = strconv.Atoi(v); err != nil {
			writeError(w, http.StatusBadRequest, "offset: must be an integer")
			return
		}
	}

	res, err := s.deps.Search.Search(r.Context(), q)
	if err != nil {
		var invalid *search.InvalidQueryError
		if errors.As(err, &invalid) {
			writeError(w, http.StatusBadRequest, invalid.Error())
			return
		}
		s.deps.Logger.Error("search failed", "err", err)
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Same-site check: a login CSRF would sign the victim in as the attacker.
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON with username and password")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	token, user, err := s.deps.Auth.Login(r.Context(), host, req.Username, req.Password)
	switch {
	case errors.Is(err, auth.ErrBadCredentials):
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, auth.ErrTooManyAttempts):
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		s.deps.Logger.Error("login failed", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in unavailable")
		return
	}
	auth.SetSessionCookie(w, token)
	writeJSON(w, http.StatusOK, sessionInfo{Username: user.Username, Role: user.Role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	if err := s.deps.Auth.Logout(r); err != nil {
		s.deps.Logger.Error("logout failed", "err", err)
	}
	auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// handleMe tells the UI whether the browser has a valid session.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, err := s.deps.Auth.Authenticate(r)
	if err != nil || p.Kind != auth.KindUser {
		writeError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	writeJSON(w, http.StatusOK, sessionInfo{Username: p.Name, Role: p.Role})
}

type healthResponse struct {
	Status   string         `json:"status"`
	Time     time.Time      `json:"time"`
	Database map[string]any `json:"database,omitempty"`
	Ingest   *ingest.Stats  `json:"ingest,omitempty"`
	Intel    *intel.Stats   `json:"intel,omitempty"`
	Syslog   *syslogd.Stats `json:"syslog,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Details (counts, sizes, queue state) are only for signed-in users.
	p, _ := s.deps.Auth.Authenticate(r)
	detailed := p != nil && p.Can(auth.PermSearch)

	resp := healthResponse{Status: "ok", Time: time.Now().UTC()}
	if detailed {
		stats := s.deps.Ingest.Stats()
		resp.Ingest = &stats
		resp.Database = map[string]any{"status": "ok"}
		if s.deps.Intel != nil {
			st := s.deps.Intel.Stats()
			resp.Intel = &st
		}
		if s.deps.Syslog != nil {
			st := s.deps.Syslog.Stats()
			resp.Syslog = &st
		}
	}
	code := http.StatusOK

	degrade := func(status, msg string) {
		resp.Status, code = "degraded", http.StatusServiceUnavailable
		if detailed {
			resp.Database["status"] = status
			resp.Database["error"] = msg
		}
	}
	if err := s.deps.DB.Ping(ctx); err != nil {
		degrade("down", err.Error())
	} else if detailed {
		if st, err := s.deps.Repo.Stats(ctx); err != nil {
			degrade("error", err.Error())
		} else {
			resp.Database["stats"] = st
		}
	}
	writeJSON(w, code, resp)
}

// parseTime accepts RFC3339 or epoch milliseconds; empty means unset.
func parseTime(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.UnixMilli(ms), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, errors.New("must be RFC3339 or epoch milliseconds")
	}
	return t, nil
}

func parseOptInt(v string) (*int, error) {
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil, errors.New("must be an integer")
	}
	return &n, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
