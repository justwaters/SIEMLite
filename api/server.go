// Package api exposes SIEMLite over HTTP.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

const (
	maxBodyBytes   = 16 << 20
	maxBatchEvents = 10000
	submitTimeout  = 5 * time.Second
)

// Deps are the components the server fronts.
type Deps struct {
	DB     *storage.DB
	Repo   *storage.Repository
	Ingest *ingest.Worker
	Search *search.Engine
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
	mux.HandleFunc("POST /api/v1/events", s.handleIngest)
	mux.HandleFunc("GET /api/v1/search", s.handleSearch)
	mux.HandleFunc("GET /health", s.handleHealth)
	return s.recoverer(mux)
}

// Start serves until Shutdown; it returns nil on a clean shutdown.
func (s *Server) Start() error {
	if err := s.http.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
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

// handleSearch maps query parameters onto a search.Query.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query()
	q := search.Query{
		Text:     p.Get("q"),
		SrcIP:    p.Get("src_ip"),
		DstIP:    p.Get("dst_ip"),
		UserName: p.Get("user"),
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

type healthResponse struct {
	Status   string         `json:"status"`
	Time     time.Time      `json:"time"`
	Database map[string]any `json:"database"`
	Ingest   ingest.Stats   `json:"ingest"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp := healthResponse{
		Status:   "ok",
		Time:     time.Now().UTC(),
		Database: map[string]any{"status": "ok"},
		Ingest:   s.deps.Ingest.Stats(),
	}
	code := http.StatusOK

	if err := s.deps.DB.Ping(ctx); err != nil {
		resp.Status, code = "degraded", http.StatusServiceUnavailable
		resp.Database["status"] = "down"
		resp.Database["error"] = err.Error()
	} else if st, err := s.deps.Repo.Stats(ctx); err != nil {
		resp.Status, code = "degraded", http.StatusServiceUnavailable
		resp.Database["status"] = "error"
		resp.Database["error"] = err.Error()
	} else {
		resp.Database["stats"] = st
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
