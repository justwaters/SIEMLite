// Package api exposes SIEMLite over HTTP.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/agents"
	"siemlite/pkg/ai"
	"siemlite/pkg/alerts"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/certs"
	"siemlite/pkg/email"
	"siemlite/pkg/entra"
	"siemlite/pkg/ingest"
	"siemlite/pkg/integrations"
	"siemlite/pkg/intel"
	"siemlite/pkg/mcp"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/retention"
	"siemlite/pkg/search"
	"siemlite/pkg/secaudit"
	"siemlite/pkg/sources"
	"siemlite/pkg/storage"
	"siemlite/pkg/syslogd"
	"siemlite/pkg/update"
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
	Router *sources.Router // per-source parsers (required)
	AI     *ai.Service     // the AI Parsers integration (optional)
	Agents *agents.Service // AI agent access over MCP (optional)
	// Backups, Started and Restart serve the System page (optional).
	Backups *backup.Manager
	Started time.Time
	Restart func()
	Email   *email.Service // optional: the Email integration's settings
	// Integrations is the list the Integrations page shows (optional).
	Integrations *integrations.Registry
	// Entra signs people in with Microsoft (optional).
	Entra *entra.Service
	// Proxies are the reverse proxies whose X-Forwarded-For is believed (optional).
	Proxies *Proxies
	// Retention deletes old events; the System page sets its period (optional).
	Retention *retention.Cleaner
	// LocalAddr is the local port's address, e.g. localhost:8444 (optional).
	// Requests on it count as coming from the server itself (see signin.go).
	LocalAddr string
	// Certs chooses the HTTPS certificate (System page; optional).
	Certs   *certs.Manager
	Updates *update.Checker // optional: the System page's update card
	Version string          // e.g. "v0.7"
	Audit   *audit.Logger   // optional: records actions as INTERNAL events
	Alerts  *alerts.Engine  // optional: alert rules
	// SecAudit runs the Security audit page's checks (optional); SecConfig is
	// what they need to know of how SIEMLite was started.
	SecAudit  *secaudit.Service
	SecConfig secaudit.Config
	Logger    *slog.Logger
}

// Server is the HTTP API.
type Server struct {
	deps  Deps
	http  *http.Server
	plain *http.Server // plain HTTP, for a reverse proxy in front (optional)
	local *http.Server // the local port (optional)

	signinMuSave sync.Mutex // one sign-in settings change at a time

	checkMu sync.Mutex
	checks  map[string]time.Time // reachability checks under way (tlsapi.go)

	mcp *mcp.Server // the MCP tools (mcp.go)

	ssoMu      sync.Mutex
	ssoFlights map[[sha256.Size]byte]*ssoFlight // Microsoft callbacks lately, by state (entra.go)

	// Failed and blocked sign-ins are recorded before anyone has signed in,
	// so strangers mustn't be able to fill the database with them. Each
	// address is already locked out after a few failures; a blocked address
	// is recorded once per lockout, and a cap well above what one attacker's
	// addresses produce stops a flood from many.
	signinMu      sync.Mutex
	signinWindow  time.Time
	signinCount   int
	signinDropped int
	signinBlocked map[string]time.Time // address -> when its block was last recorded
	signinPruned  time.Time
}

const (
	signinAuditsPerMinute = 600
	signinBlockedEvery    = 15 * time.Minute // the lockout window in pkg/auth
	signinBlockedMax      = 50000            // addresses remembered at once
)

// NewServer builds a server listening on addr once Start is called.
func NewServer(addr string, deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	s := &Server{deps: deps}
	s.mcp = s.mcpServer()
	s.http = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if deps.LocalAddr != "" {
		s.local = &http.Server{
			Addr:              deps.LocalAddr,
			Handler:           s.LocalHandler(),
			ReadHeaderTimeout: s.http.ReadHeaderTimeout,
			ReadTimeout:       s.http.ReadTimeout,
			WriteTimeout:      s.http.WriteTimeout,
			IdleTimeout:       s.http.IdleTimeout,
		}
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
	mux.Handle("GET /api/v1/stats", a.Require(auth.PermSearch, http.HandlerFunc(s.handleStats)))
	mux.Handle("GET /api/v1/sources", a.Require(auth.PermSearch, http.HandlerFunc(s.handleListSources)))
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, a.Require(auth.PermAdmin, h)) }
	admin("POST /api/v1/sources", s.handleCreateSource)
	admin("PATCH /api/v1/sources/{id}", s.handleUpdateSource)
	admin("DELETE /api/v1/sources/{id}", s.handleDeleteSource)
	admin("GET /api/v1/users", s.handleListUsers)
	admin("POST /api/v1/users", s.handleCreateUser)
	admin("PATCH /api/v1/users/{id}", s.handleUpdateUser)
	admin("POST /api/v1/users/{id}/password", s.handleSetPassword)
	admin("DELETE /api/v1/users/{id}", s.handleDeleteUser)
	admin("GET /api/v1/parsers", s.handleListParsers)
	admin("GET /api/v1/parsers/templates", s.handleParserTemplates)
	admin("GET /api/v1/parsers/severity-defaults", s.handleParserSeverityDefaults)
	admin("GET /api/v1/parsers/{id}", s.handleGetParser)
	admin("POST /api/v1/parsers", s.handleSaveParser)
	admin("PUT /api/v1/parsers/{id}", s.handleSaveParser)
	admin("DELETE /api/v1/parsers/{id}", s.handleDeleteParser)
	admin("POST /api/v1/parsers/test", s.handleTestParser)
	admin("POST /api/v1/parsers/draft", s.handleDraftParser)
	admin("POST /api/v1/parsers/suggest", s.handleSuggestParser)
	admin("GET /api/v1/integrations/mcp", s.handleGetMCP)
	admin("POST /api/v1/integrations/mcp/tokens", s.handleCreateMCPToken)
	admin("DELETE /api/v1/integrations/mcp/tokens/{id}", s.handleDeleteMCPToken)
	// AI agents authenticate with their own tokens (see mcp.go), not Require.
	mux.HandleFunc("POST /mcp", s.handleMCP)
	mux.HandleFunc("GET /mcp", s.handleMCP) // answers 405: agents POST (there is no event stream to open)
	mux.Handle("GET /api/v1/alerts", a.Require(auth.PermSearch, http.HandlerFunc(s.handleListAlerts)))
	mux.Handle("PATCH /api/v1/alerts/{id}", a.Require(auth.PermSearch, http.HandlerFunc(s.handleSetAlertStatus)))
	mux.Handle("GET /api/v1/rules", a.Require(auth.PermSearch, http.HandlerFunc(s.handleListRules)))
	admin("POST /api/v1/rules", s.handleSaveRule)
	admin("PUT /api/v1/rules/{id}", s.handleSaveRule)
	admin("DELETE /api/v1/rules/{id}", s.handleDeleteRule)
	admin("GET /api/v1/system", s.handleSystem)
	admin("GET /api/v1/system/tls", s.handleGetTLS)
	admin("PUT /api/v1/system/tls", s.handleSaveTLS)
	admin("POST /api/v1/system/tls/check", s.handleCheckTLS)
	admin("GET /api/v1/system/retention", s.handleGetRetention)
	admin("PUT /api/v1/system/retention", s.handleSaveRetention)
	admin("GET /api/v1/system/raw-retention", s.handleGetRawKeep)
	admin("PUT /api/v1/system/raw-retention", s.handleSaveRawKeep)
	admin("GET /api/v1/system/signin", s.handleGetSignin)
	admin("PUT /api/v1/system/signin", s.handleSaveSignin)
	admin("GET /api/v1/system/update", s.handleUpdateStatus)
	admin("POST /api/v1/system/update", s.handleApplyUpdate)
	admin("GET /api/v1/security-audit", s.handleAuditState)
	admin("POST /api/v1/security-audit/run", s.handleAuditRun)
	admin("GET /api/v1/security-audit/report", s.handleAuditReport)
	admin("POST /api/v1/security-audit/checks/{id}/recheck", s.handleAuditRecheck)
	admin("POST /api/v1/security-audit/checks/{id}/fix", s.handleAuditFix)
	admin("PUT /api/v1/security-audit/checks/{id}/accept", s.handleAuditAccept)
	admin("DELETE /api/v1/security-audit/checks/{id}/accept", s.handleAuditUnaccept)
	admin("GET /api/v1/integrations", s.handleListIntegrations)
	admin("POST /api/v1/integrations/{id}/enabled", s.handleSetIntegrationEnabled)
	admin("GET /api/v1/integrations/email", s.handleGetEmail)
	admin("PUT /api/v1/integrations/email", s.handleSaveEmail)
	admin("POST /api/v1/integrations/email/test", s.handleTestEmail)
	admin("GET /api/v1/integrations/entra", s.handleGetEntra)
	admin("PUT /api/v1/integrations/entra", s.handleSaveEntra)
	admin("POST /api/v1/integrations/entra/test", s.handleTestEntra)
	admin("POST /api/v1/integrations/entra/sync", s.handleSyncEntra)
	admin("GET /api/v1/integrations/ai", s.handleGetAI)
	admin("PUT /api/v1/integrations/ai", s.handleSaveAI)
	admin("POST /api/v1/integrations/ai/test", s.handleTestAI)
	admin("GET /api/v1/integrations/ai/cloud-models", s.handleCloudModels)
	admin("POST /api/v1/integrations/ai/cloud-models", s.handleCloudModels)
	// Where email's settings were before the Integrations page (v0.10).
	admin("GET /api/v1/system/email", s.handleGetEmail)
	admin("PUT /api/v1/system/email", s.handleSaveEmail)
	admin("POST /api/v1/system/email/test", s.handleTestEmail)
	admin("GET /api/v1/backups", s.handleListBackups)
	admin("POST /api/v1/backups", s.handleCreateBackup)
	admin("PUT /api/v1/backups/settings", s.handleBackupSettings)
	admin("POST /api/v1/backups/upload", s.handleUploadBackup)
	admin("GET /api/v1/backups/{name}", s.handleDownloadBackup)
	admin("DELETE /api/v1/backups/{name}", s.handleDeleteBackup)
	admin("POST /api/v1/backups/{name}/restore", s.handleRestoreBackup)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	// Sign in with Microsoft: public, since they happen before anyone is signed in.
	mux.HandleFunc("GET /api/v1/auth/providers", s.handleProviders)
	// The System page's reachability check fetches this through the domain (tlsapi.go).
	mux.HandleFunc("GET /.well-known/siemlite-check/{nonce}", s.handleCheckEcho)
	mux.HandleFunc("GET /api/v1/auth/entra/start", s.handleEntraStart)
	mux.HandleFunc("GET /api/v1/auth/entra/callback", s.handleEntraCallback)
	mux.HandleFunc("GET /api/v1/me", s.handleMe)
	mux.Handle("POST /api/v1/me/password", a.Require(auth.PermSearch, http.HandlerFunc(s.handleChangeOwnPassword)))
	// /health is public but only reveals up/down; detail needs a signed-in user.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /", web.Handler())
	return s.recoverer(securityHeaders(mux))
}

// Start serves HTTPS (there is no plaintext listener) until Shutdown; it
// returns nil on a clean shutdown.
func (s *Server) Start(cfg *tls.Config) error {
	s.http.TLSConfig = cfg
	if err := s.http.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	for _, other := range []*http.Server{s.plain, s.local} {
		if other != nil {
			if oerr := other.Shutdown(ctx); err == nil {
				err = oerr
			}
		}
	}
	return err
}

// StartPlain serves plain HTTP on addr until Shutdown, for a reverse proxy or
// load balancer that does the HTTPS. It must only be reachable by the proxy:
// with trusted proxies configured, it refuses everyone else.
func (s *Server) StartPlain(addr string) error {
	s.plain = &http.Server{
		Addr:              addr,
		Handler:           s.deps.Proxies.onlyProxies(s.Handler()),
		ReadHeaderTimeout: s.http.ReadHeaderTimeout,
		ReadTimeout:       s.http.ReadTimeout,
		WriteTimeout:      s.http.WriteTimeout,
		IdleTimeout:       s.http.IdleTimeout,
	}
	if err := s.plain.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

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

	sourceID, err := s.ingestSource(r)
	if err != nil {
		s.deps.Logger.Error("resolve source failed", "err", err)
		writeError(w, http.StatusInternalServerError, "ingest unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), submitTimeout)
	defer cancel()

	var resp ingestResponse
	for i := range events {
		err := s.deps.Ingest.SubmitWith(ctx, &events[i], ingest.SubmitOptions{SourceID: sourceID})
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

	sourceID, err := s.ingestSource(r)
	if err != nil {
		s.deps.Logger.Error("resolve source failed", "err", err)
		writeError(w, http.StatusInternalServerError, "ingest unavailable")
		return
	}
	// One log per line; a body that is all JSON (pretty-printed objects, or
	// arrays of them) gives one log per object instead.
	lines := bytes.Split(body, []byte("\n"))
	if objs, ok := parser.JSONValues(body); ok {
		lines = make([][]byte, len(objs))
		for i, o := range objs {
			lines[i] = []byte(o)
		}
	}
	events := make([]*ocsf.Event, 0, len(lines))
	extras := make([]map[string]string, 0, len(lines))
	for _, l := range lines {
		ev, fields, err := s.deps.Router.Parse(r.Context(), sourceID, string(l), defaults)
		if err != nil {
			s.deps.Logger.Error("parse failed", "err", err)
			writeError(w, http.StatusInternalServerError, "ingest unavailable")
			return
		}
		if ev != nil {
			events = append(events, ev)
			extras = append(extras, fields)
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
		err := s.deps.Ingest.SubmitWith(ctx, ev, ingest.SubmitOptions{SourceID: sourceID, Fields: extras[i]})
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
	if v := p.Get("source_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if q.SourceID = id; err != nil {
			writeError(w, http.StatusBadRequest, "source_id: must be a number")
			return
		}
	}
	if pr := auth.FromContext(r.Context()); pr != nil && pr.Restricted() {
		q.Restrict, q.AllowedSources = true, pr.Sources
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
	s.showDisplayNames(r.Context(), res.Events)
	writeJSON(w, http.StatusOK, res)
}

// showDisplayNames adds, to each event whose user is an account with a display
// name, that name (UserDisplay), so the log shows the person and not only the
// account name. The events keep the account name for filtering.
func (s *Server) showDisplayNames(ctx context.Context, events []storage.Record) {
	seen := map[string]bool{}
	var names []string
	for _, ev := range events {
		if ev.UserName != "" && !seen[ev.UserName] {
			seen[ev.UserName] = true
			names = append(names, ev.UserName)
		}
	}
	display, err := s.deps.Repo.DisplayNames(ctx, names)
	if err != nil {
		s.deps.Logger.Warn("couldn't look up display names", "err", err)
		return
	}
	for i := range events {
		if d := display[events[i].UserName]; d != "" && d != events[i].UserName {
			events[i].UserDisplay = d
		}
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	// Limited users see only Sources (possibly none).
	Limited bool      `json:"limited"`
	Sources []int64   `json:"sources"`
	AI      ai.Status `json:"ai"`
	Version string    `json:"version,omitempty"`
	// AuthProvider is how the account signs in: "local" (a password) or
	// "entra" (Microsoft).
	AuthProvider string `json:"auth_provider"`
	// DisplayName is the name to show (a Microsoft account's display name), or empty.
	DisplayName string `json:"display_name,omitempty"`
}

func (s *Server) session(username, role string, limited bool, sources []int64, provider, displayName string) sessionInfo {
	if sources == nil || role == auth.RoleAdmin {
		sources = []int64{}
	}
	if provider == "" {
		provider = storage.ProviderLocal
	}
	return sessionInfo{Username: username, Role: role, Limited: limited && role != auth.RoleAdmin, Sources: sources, AI: s.deps.AI.Status(),
		Version: s.deps.Version, AuthProvider: provider, DisplayName: displayName}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Same-site check: a login CSRF would sign the victim in as the attacker.
	if auth.CrossSite(r) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON with username and password")
		return
	}
	token, user, err := s.deps.Auth.Login(r.Context(), s.clientIP(r), req.Username, req.Password)
	switch {
	case errors.Is(err, auth.ErrLocalOnly), errors.Is(err, auth.ErrPasswordsOff):
		who := s.attemptedUser(r, req.Username)
		s.auditSignin(r, audit.Entry{Action: "signin.refused", Actor: who, Class: audit.Authentication, Severity: 3,
			Message: "Password sign-in refused for " + who + ": " + map[bool]string{true: "the admin account only signs in on the server itself", false: "only sign-in with Microsoft is allowed"}[errors.Is(err, auth.ErrLocalOnly)]})
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, auth.ErrBadCredentials):
		who := s.attemptedUser(r, req.Username)
		s.auditSignin(r, audit.Entry{Action: "signin.failed", Actor: who, Class: audit.Authentication, Severity: 3,
			Message: "Sign-in failed for " + who})
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, auth.ErrTooManyAttempts):
		who := s.attemptedUser(r, req.Username)
		if !s.firstBlock(s.clientIP(r)) {
			w.Header().Set("Retry-After", "900")
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		s.auditSignin(r, audit.Entry{Action: "signin.blocked", Actor: who, Class: audit.Authentication, Severity: 4,
			Message: "Sign-in blocked for " + who + " after too many failed attempts from this address"})
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		s.deps.Logger.Error("login failed", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in unavailable")
		return
	}
	auth.SetSessionCookie(w, token)
	s.audit(r, audit.Entry{Action: "signin", Actor: user.Username, Class: audit.Authentication, Message: user.Username + " signed in"})
	limited, sources := true, []int64{} // if the lookup fails, show nothing rather than everything
	if full, err := s.deps.Repo.GetUser(r.Context(), user.ID); err == nil {
		limited, sources = full.Limited, full.Sources
	}
	writeJSON(w, http.StatusOK, s.session(user.Username, user.Role, limited, sources, user.AuthProvider, user.DisplayName))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if auth.CrossSite(r) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	if p, err := s.deps.Auth.Authenticate(r); err == nil && p.Kind == auth.KindUser {
		s.audit(r, audit.Entry{Action: "signout", Actor: p.Name, Class: audit.Authentication, Message: p.Name + " signed out"})
	}
	if err := s.deps.Auth.Logout(r); err != nil {
		s.deps.Logger.Error("logout failed", "err", err)
	}
	auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// clientIP is the caller's address.
// clientIP is the visitor's address, through a trusted reverse proxy if there
// is one (see Proxies).
func (s *Server) clientIP(r *http.Request) string { return s.deps.Proxies.ClientIP(r) }

// attemptedUser names the account a failed sign-in tried. Text that isn't an
// account name is not recorded: people sometimes type their password into
// the username field, and the audit log is readable by every analyst.
func (s *Server) attemptedUser(r *http.Request, username string) string {
	if u, _, err := s.deps.Repo.GetUserForLogin(r.Context(), username); err == nil {
		return u.Username
	}
	return "an unknown username"
}

// firstBlock reports whether a blocked sign-in from addr is the first since
// its lockout began, so a locked-out address is recorded once, not per try.
func (s *Server) firstBlock(addr string) bool {
	s.signinMu.Lock()
	defer s.signinMu.Unlock()
	now := time.Now()
	if s.signinBlocked == nil {
		s.signinBlocked = map[string]time.Time{}
	}
	if now.Sub(s.signinPruned) >= time.Minute { // at most once a minute, so it stays cheap
		for a, t := range s.signinBlocked {
			if now.Sub(t) >= signinBlockedEvery {
				delete(s.signinBlocked, a)
			}
		}
		s.signinPruned = now
	}
	if t, ok := s.signinBlocked[addr]; ok && now.Sub(t) < signinBlockedEvery {
		return false
	}
	if len(s.signinBlocked) < signinBlockedMax { // beyond it, every block is recorded (within the cap)
		s.signinBlocked[addr] = now
	}
	return true
}

// auditSignin records a failed or blocked sign-in, at most
// signinAuditsPerMinute a minute; the rest are counted in one event when the
// minute ends.
func (s *Server) auditSignin(r *http.Request, e audit.Entry) {
	s.signinMu.Lock()
	now := time.Now()
	if now.Sub(s.signinWindow) >= time.Minute {
		s.signinWindow, s.signinCount = now, 0
	}
	record := s.signinCount < signinAuditsPerMinute
	if record {
		s.signinCount++
	} else {
		s.signinDropped++
		if s.signinDropped == 1 {
			// Write the count when this minute ends, even if the flood stops.
			time.AfterFunc(time.Until(s.signinWindow.Add(time.Minute)), s.flushSignin)
		}
	}
	s.signinMu.Unlock()
	if record {
		s.audit(r, e)
	}
}

// flushSignin records how many failed or blocked sign-ins went unrecorded.
func (s *Server) flushSignin() {
	s.signinMu.Lock()
	dropped := s.signinDropped
	s.signinDropped = 0
	s.signinMu.Unlock()
	if dropped == 0 || s.deps.Audit == nil {
		return
	}
	// From many addresses, so none is named. Critical, so it raises an alert.
	s.deps.Audit.Record(context.Background(), audit.Entry{Action: "signin.failed.more", Actor: "SIEMLite",
		Class: audit.Authentication, Severity: 5,
		Message: fmt.Sprintf("%d more failed or blocked sign-ins in a minute weren't recorded one by one", dropped),
		Fields:  map[string]string{"count": strconv.Itoa(dropped)}})
}

// audit records an action from a request, filling in who and where from.
func (s *Server) audit(r *http.Request, e audit.Entry) {
	if s.deps.Audit == nil {
		return
	}
	p := auth.FromContext(r.Context())
	if p != nil && e.Actor == "" {
		e.Actor = p.Name
	}
	// Messages start with who did it; show their display name too. On
	// public routes (sign-in, sign-out) nobody is attached to the request,
	// so the account is looked up.
	if e.Actor != "" && strings.HasPrefix(e.Message, e.Actor+" ") {
		who := p
		if who == nil || who.Name != e.Actor {
			who = &auth.Principal{Name: e.Actor}
			if u, _, err := s.deps.Repo.GetUserForLogin(r.Context(), e.Actor); err == nil {
				who.DisplayName = u.DisplayName
			}
		}
		e.Message = who.Label() + e.Message[len(e.Actor):]
	}
	if e.IP == "" {
		e.IP = s.clientIP(r)
	}
	if p != nil && p.Kind == auth.KindAgent { // say it was an AI agent, whatever it did
		fields := map[string]string{"via": "mcp"}
		for k, v := range e.Fields {
			fields[k] = v
		}
		e.Fields = fields
	}
	s.deps.Audit.Record(r.Context(), e)
}

// handleMe tells the UI whether the browser has a valid session.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, err := s.deps.Auth.Authenticate(r)
	if err != nil || p.Kind != auth.KindUser {
		writeError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	writeJSON(w, http.StatusOK, s.session(p.Name, p.Role, p.Limited, p.Sources, p.AuthProvider, p.DisplayName))
}

// handleChangeOwnPassword lets a signed-in user change their own password.
// Their other sessions end; this one carries on with a new cookie.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context()) // a user: PermSearch is never granted to API keys
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	token, err := s.deps.Auth.ChangeOwnPassword(r.Context(), s.clientIP(r), p.UserID, req.Current, req.New)
	switch {
	case errors.Is(err, auth.ErrTooManyAttempts):
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case errors.Is(err, auth.ErrWrongPassword):
		s.audit(r, audit.Entry{Action: "user.password.self", Class: audit.AccountChange, Severity: 3,
			Message: p.Name + " tried to change their password, but the current password was wrong", Fields: map[string]string{"target": p.Name, "result": "failed"}})
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.As(err, new(auth.PasswordError)), errors.Is(err, auth.ErrNoPassword):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, auth.ErrInvalid):
		writeError(w, http.StatusUnauthorized, "not signed in")
		return
	case err != nil:
		s.internal(w, "change the password", err)
		return
	}
	auth.SetSessionCookie(w, token)
	s.audit(r, audit.Entry{Action: "user.password.self", Class: audit.AccountChange, Severity: 2,
		Message: p.Name + " changed their own password; their other sessions were ended", Fields: map[string]string{"target": p.Name}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed; you were signed out everywhere else"})
}

type healthResponse struct {
	Status   string         `json:"status"`
	Version  string         `json:"version,omitempty"`
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
	// Database-wide figures would reveal activity in sources a restricted
	// user can't see, so they get up/down only.
	detailed := p != nil && p.Can(auth.PermSearch) && !p.Restricted()

	resp := healthResponse{Status: "ok", Time: time.Now().UTC()}
	if detailed {
		stats := s.deps.Ingest.Stats()
		resp.Ingest = &stats
		resp.Version = s.deps.Version
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
