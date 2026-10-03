package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/ai"
	"siemlite/pkg/auth"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

// decodeJSON reads a small JSON body into v, writing a 400 on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "body must be valid JSON: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "id must be a positive number")
		return 0, false
	}
	return id, true
}

// ingestSource is the source an ingest request belongs to: the access
// token's source, or "Added in the UI" for a signed-in admin.
func (s *Server) ingestSource(r *http.Request) (int64, error) {
	p := auth.FromContext(r.Context())
	id := p.SourceID
	if p.Kind != auth.KindKey {
		var err error
		if id, err = s.deps.Router.Builtin(r.Context(), storage.SourceUpload); err != nil {
			return 0, err
		}
	}
	s.deps.Auth.TouchSource(r.Context(), id)
	return id, nil
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.deps.Logger.Error(what+" failed", "err", err)
	writeError(w, http.StatusInternalServerError, what+" failed")
}

// --- Dashboard ---

// handleStats summarizes the last `hours` (default 24) for the dashboard.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 24*90 {
			writeError(w, http.StatusBadRequest, "hours must be 1-2160")
			return
		}
		hours = n
	}
	// About 24-30 bars whatever the range, aligned so the last bar is now.
	bucket := time.Hour
	switch {
	case hours > 24*7:
		bucket = 24 * time.Hour
	case hours > 48:
		bucket = 6 * time.Hour
	}
	n := int64((time.Duration(hours)*time.Hour + bucket - 1) / bucket)
	end := time.Now().Truncate(bucket).Add(bucket)
	start := end.Add(-time.Duration(n) * bucket)

	f := storage.Filter{}
	if p := auth.FromContext(r.Context()); p.Restricted() {
		f.Restrict, f.AllowedSources = true, p.Sources
	}
	ov, err := s.deps.Repo.Overview(r.Context(), start.UnixMilli(), end.UnixMilli(), bucket.Milliseconds(), f)
	if err != nil {
		s.internal(w, "stats", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hours": hours, "start": start.UnixMilli(), "end": end.UnixMilli(), "bucket_ms": bucket.Milliseconds(), "overview": ov,
	})
}

// --- Sources ---

type sourceView struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// handleListSources lists every source for admins, and the sources a user
// may see (names only) for everyone else, for the Database filter.
func (s *Server) handleListSources(w http.ResponseWriter, r *http.Request) {
	list, err := s.deps.Repo.ListSources(r.Context())
	if err != nil {
		s.internal(w, "list sources", err)
		return
	}
	if list == nil {
		list = []storage.Source{}
	}
	p := auth.FromContext(r.Context())
	if p.Can(auth.PermAdmin) {
		writeJSON(w, http.StatusOK, list)
		return
	}
	allowed := map[int64]bool{}
	for _, id := range p.Sources {
		allowed[id] = true
	}
	out := []sourceView{}
	for _, src := range list {
		if !p.Restricted() || allowed[src.ID] {
			out = append(out, sourceView{src.ID, src.Name, src.Kind})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) checkParser(ctx context.Context, w http.ResponseWriter, id *int64) bool {
	if id == nil {
		return true
	}
	if _, err := s.deps.Repo.GetParser(ctx, *id); err != nil {
		if errors.Is(err, storage.ErrParserNotFound) {
			writeError(w, http.StatusBadRequest, "that parser doesn't exist")
		} else {
			s.internal(w, "get parser", err)
		}
		return false
	}
	return true
}

func (s *Server) handleCreateSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		ParserID *int64 `json:"parser_id"`
	}
	if !decodeJSON(w, r, &req, 4<<10) || !s.checkParser(r.Context(), w, req.ParserID) {
		return
	}
	id, token, err := auth.CreateKey(r.Context(), s.deps.Repo, req.Name, req.ParserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	src, err := s.deps.Repo.GetSource(r.Context(), id)
	if err != nil {
		s.internal(w, "get source", err)
		return
	}
	s.deps.Logger.Info("source created", "source", src.Name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, http.StatusCreated, map[string]any{"source": src, "token": token})
}

// handleUpdateSource renames a source or sets its parser ("parser_id": null
// returns it to automatic parsing).
func (s *Server) handleUpdateSource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if !decodeJSON(w, r, &raw, 4<<10) {
		return
	}
	var name *string
	if v, ok := raw["name"]; ok {
		var n string
		if json.Unmarshal(v, &n) != nil || strings.TrimSpace(n) == "" || len(n) > 80 {
			writeError(w, http.StatusBadRequest, "name must be 1-80 characters")
			return
		}
		n = strings.TrimSpace(n)
		name = &n
	}
	var parserID *int64
	clear := false
	if v, ok := raw["parser_id"]; ok {
		if string(v) == "null" {
			clear = true
		} else {
			var pid int64
			if json.Unmarshal(v, &pid) != nil {
				writeError(w, http.StatusBadRequest, "parser_id must be a number or null")
				return
			}
			parserID = &pid
		}
	}
	if !s.checkParser(r.Context(), w, parserID) {
		return
	}
	err := s.deps.Repo.UpdateSource(r.Context(), id, name, parserID, clear)
	switch {
	case errors.Is(err, storage.ErrSourceNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil && strings.Contains(err.Error(), "built-in"):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.internal(w, "update source", err)
		return
	}
	s.deps.Router.Invalidate()
	src, _ := s.deps.Repo.GetSource(r.Context(), id)
	writeJSON(w, http.StatusOK, src)
}

func (s *Server) handleRevokeSource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	src, err := s.deps.Repo.GetSource(r.Context(), id)
	if errors.Is(err, storage.ErrSourceNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get source", err)
		return
	}
	if src.Kind != storage.SourceToken {
		writeError(w, http.StatusBadRequest, "built-in sources can't be revoked")
		return
	}
	if _, err := s.deps.Repo.RevokeSource(r.Context(), id, time.Now().UnixMilli()); err != nil {
		s.internal(w, "revoke source", err)
		return
	}
	s.deps.Logger.Info("source revoked", "source", src.Name, "by", auth.FromContext(r.Context()).Name)
	src, _ = s.deps.Repo.GetSource(r.Context(), id)
	writeJSON(w, http.StatusOK, src)
}

// --- Users ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.deps.Repo.ListUsers(r.Context())
	if err != nil {
		s.internal(w, "list users", err)
		return
	}
	if users == nil {
		users = []storage.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

// validSources checks every id names an existing source.
func (s *Server) validSources(ctx context.Context, w http.ResponseWriter, ids []int64) bool {
	if len(ids) == 0 {
		return true
	}
	list, err := s.deps.Repo.ListSources(ctx)
	if err != nil {
		s.internal(w, "list sources", err)
		return false
	}
	known := map[int64]bool{}
	for _, src := range list {
		known[src.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			writeError(w, http.StatusBadRequest, "source "+strconv.FormatInt(id, 10)+" doesn't exist")
			return false
		}
	}
	return true
}

// errNoSources refuses a limit that would let a user see nothing by mistake.
const errNoSources = "choose at least one source, or let them see every source"

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string  `json:"username"`
		Password string  `json:"password"`
		Role     string  `json:"role"`
		Limited  *bool   `json:"limited"`
		Sources  []int64 `json:"sources"`
	}
	if !decodeJSON(w, r, &req, 8<<10) || !s.validSources(r.Context(), w, req.Sources) {
		return
	}
	role, err := auth.ParseUserRole(req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Sources without an explicit "limited" mean the user is limited to them.
	limited := len(req.Sources) > 0
	if req.Limited != nil {
		limited = *req.Limited
	}
	limited = limited && role != auth.RoleAdmin
	if limited && len(req.Sources) == 0 {
		writeError(w, http.StatusBadRequest, errNoSources)
		return
	}
	id, err := auth.CreateUser(r.Context(), s.deps.Repo, req.Username, req.Password, role)
	switch {
	case errors.Is(err, storage.ErrUserExists):
		writeError(w, http.StatusConflict, "that username is taken")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.deps.Repo.UpdateUserAccess(r.Context(), id, role, limited, req.Sources); err != nil {
		s.internal(w, "set user sources", err)
		return
	}
	s.deps.Logger.Info("user created", "user", req.Username, "role", role, "limited", limited, "by", auth.FromContext(r.Context()).Name)
	u, _ := s.deps.Repo.GetUser(r.Context(), id)
	writeJSON(w, http.StatusCreated, u)
}

// handleUpdateUser changes a user's role, limit or sources. Fields left out
// keep their current values, so a partial update never widens access.
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Role    *string  `json:"role"`
		Limited *bool    `json:"limited"`
		Sources *[]int64 `json:"sources"`
	}
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	cur, err := s.deps.Repo.GetUser(r.Context(), id)
	if errors.Is(err, storage.ErrUserNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get user", err)
		return
	}
	role, limited, sources := cur.Role, cur.Limited, cur.Sources
	if req.Role != nil {
		if role, err = auth.ParseUserRole(*req.Role); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Sources != nil {
		sources = *req.Sources
		if req.Limited == nil && len(sources) > 0 {
			limited = true
		}
	}
	if req.Limited != nil {
		limited = *req.Limited
	}
	if !s.validSources(r.Context(), w, sources) {
		return
	}
	limited = limited && role != auth.RoleAdmin
	if limited && len(sources) == 0 {
		writeError(w, http.StatusBadRequest, errNoSources)
		return
	}
	switch err := s.deps.Repo.UpdateUserAccess(r.Context(), id, role, limited, sources); {
	case errors.Is(err, storage.ErrLastAdmin):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, "update user", err)
		return
	}
	u, _ := s.deps.Repo.GetUser(r.Context(), id)
	s.deps.Logger.Info("user access changed", "user", u.Username, "role", role, "limited", limited,
		"sources", len(sources), "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	u, err := s.deps.Repo.GetUser(r.Context(), id)
	if errors.Is(err, storage.ErrUserNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get user", err)
		return
	}
	if err := auth.SetPassword(r.Context(), s.deps.Repo, u.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.deps.Logger.Info("password changed", "user", u.Username, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed; the user was signed out"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if p := auth.FromContext(r.Context()); p.UserID == id {
		writeError(w, http.StatusBadRequest, "you can't delete your own account")
		return
	}
	u, err := s.deps.Repo.GetUser(r.Context(), id)
	if errors.Is(err, storage.ErrUserNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get user", err)
		return
	}
	switch err := s.deps.Repo.DeleteUserByID(r.Context(), id); {
	case errors.Is(err, storage.ErrLastAdmin):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, "delete user", err)
		return
	}
	s.deps.Logger.Info("user deleted", "user", u.Username, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Parsers ---

type parserSummary struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Format      string `json:"format"`
	UsedBy      int    `json:"used_by"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (s *Server) handleListParsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.deps.Repo.ListParsers(r.Context())
	if err != nil {
		s.internal(w, "list parsers", err)
		return
	}
	out := []parserSummary{}
	for _, p := range list {
		var def parser.Definition
		_ = json.Unmarshal([]byte(p.Definition), &def)
		out = append(out, parserSummary{p.ID, p.Name, def.Description, def.Format, p.UsedBy, p.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleParserTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, parser.Templates)
}

func (s *Server) handleGetParser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.deps.Repo.GetParser(r.Context(), id)
	if errors.Is(err, storage.ErrParserNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get parser", err)
		return
	}
	var def parser.Definition
	_ = json.Unmarshal([]byte(p.Definition), &def)
	def.Name = p.Name
	writeJSON(w, http.StatusOK, map[string]any{"id": p.ID, "used_by": p.UsedBy, "updated_at": p.UpdatedAt, "definition": def})
}

const maxParserBody = 256 << 10

// handleSaveParser creates (POST) or replaces (PUT /{id}) a parser.
func (s *Server) handleSaveParser(w http.ResponseWriter, r *http.Request) {
	var def parser.Definition
	if !decodeJSON(w, r, &def, maxParserBody) {
		return
	}
	compiled, err := parser.Compile(def)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	def = compiled.Definition()
	if len(def.Samples) > 50 {
		def.Samples = def.Samples[:50]
	}
	b, _ := json.Marshal(def)
	now := time.Now().UnixMilli()
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
		err = s.deps.Repo.UpdateParser(r.Context(), id, def.Name, string(b), now)
	} else {
		id, err = s.deps.Repo.CreateParser(r.Context(), def.Name, string(b), now)
	}
	switch {
	case errors.Is(err, storage.ErrParserExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, storage.ErrParserNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		s.internal(w, "save parser", err)
		return
	}
	s.deps.Router.Invalidate()
	s.deps.Logger.Info("parser saved", "parser", def.Name, "by", auth.FromContext(r.Context()).Name)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"id": id, "definition": def})
}

func (s *Server) handleDeleteParser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	switch err := s.deps.Repo.DeleteParser(r.Context(), id); {
	case errors.Is(err, storage.ErrParserNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		s.internal(w, "delete parser", err)
		return
	}
	s.deps.Router.Invalidate()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type testedLine struct {
	Line    string            `json:"line"`
	Matched bool              `json:"matched"`
	Error   string            `json:"error,omitempty"`
	Event   map[string]any    `json:"event,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"` // every extracted value
}

// handleTestParser runs a (possibly unsaved) parser over sample lines, for
// the live preview in the parser editor.
func (s *Server) handleTestParser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Definition parser.Definition `json:"definition"`
		Lines      []string          `json:"lines"`
	}
	if !decodeJSON(w, r, &req, maxParserBody) {
		return
	}
	if req.Definition.Name == "" {
		req.Definition.Name = "preview"
	}
	p, err := parser.Compile(req.Definition)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now()
	out := []testedLine{}
	for _, line := range req.Lines {
		if len(out) == 200 {
			break
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(line) > 8<<10 {
			line = line[:8<<10]
		}
		t := testedLine{Line: line}
		res, err := p.Parse(line, parser.Defaults{Now: now})
		if err != nil {
			t.Error = err.Error()
		} else {
			t.Matched = true
			ev := res.Event
			t.Event = map[string]any{"time": ev.Time, "severity_id": ev.SeverityID, "category_uid": ev.CategoryUID,
				"class_uid": ev.ClassUID, "message": ev.Message}
			for k, v := range map[string]string{"src_ip": ev.SrcIP(), "dst_ip": ev.DstIP(), "user": ev.UserName(),
				"host": ev.DeviceName(), "app": ev.ProductName()} {
				if v != "" {
					t.Event[k] = v
				}
			}
			if ev.SrcEndpoint != nil && ev.SrcEndpoint.Port != 0 {
				t.Event["src_port"] = ev.SrcEndpoint.Port
			}
			if ev.DstEndpoint != nil && ev.DstEndpoint.Port != 0 {
				t.Event["dst_port"] = ev.DstEndpoint.Port
			}
			t.Extra, t.Fields = res.Extra, res.Fields
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (s *Server) handleSuggestParser(w http.ResponseWriter, r *http.Request) {
	if s.deps.AI == nil {
		writeError(w, http.StatusNotFound, "AI help isn't set up. Set SIEMLITE_AI_URL to an Ollama server to turn it on.")
		return
	}
	var req struct {
		Lines []string `json:"lines"`
	}
	if !decodeJSON(w, r, &req, maxParserBody) {
		return
	}
	// A CPU-only model can take minutes; outlast the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	sug, err := s.deps.AI.Suggest(ctx, req.Lines)
	switch {
	case errors.Is(err, ai.ErrNotReady):
		writeError(w, http.StatusServiceUnavailable, "The AI model is still downloading or Ollama isn't reachable. Try again in a few minutes.")
		return
	case err != nil:
		s.deps.Logger.Warn("parser suggestion failed", "err", err)
		writeError(w, http.StatusBadGateway, "The AI model couldn't suggest a parser: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sug)
}
