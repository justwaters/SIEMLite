package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/storage"
)

// canSeeAlerts: alerts summarize events across sources, so users limited to
// some sources don't see them (fail closed).
func (s *Server) canSeeAlerts(w http.ResponseWriter, r *http.Request) bool {
	if p := auth.FromContext(r.Context()); p == nil || p.Restricted() {
		writeError(w, http.StatusForbidden, "alerts aren't available to users limited to some sources")
		return false
	}
	return true
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.canSeeAlerts(w, r) {
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", "all":
		status = ""
	case storage.AlertOpen, storage.AlertAcknowledged, storage.AlertClosed:
	default:
		writeError(w, http.StatusBadRequest, "status must be open, acknowledged, closed or all")
		return
	}
	list, counts, err := s.deps.Repo.ListAlerts(r.Context(), status, 500)
	if err != nil {
		s.internal(w, "list alerts", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": list, "counts": counts})
}

// handleSetAlertStatus acknowledges, closes or reopens an alert.
func (s *Server) handleSetAlertStatus(w http.ResponseWriter, r *http.Request) {
	if !s.canSeeAlerts(w, r) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	switch req.Status {
	case storage.AlertOpen, storage.AlertAcknowledged, storage.AlertClosed:
	default:
		writeError(w, http.StatusBadRequest, "status must be open, acknowledged or closed")
		return
	}
	by := auth.FromContext(r.Context()).Name
	a, err := s.deps.Repo.SetAlertStatus(r.Context(), id, req.Status, by, time.Now().UnixMilli())
	if errors.Is(err, storage.ErrAlertNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "set alert status", err)
		return
	}
	verb := map[string]string{storage.AlertOpen: "reopened", storage.AlertAcknowledged: "acknowledged", storage.AlertClosed: "closed"}[req.Status]
	what := a.RuleName
	if a.GroupValue != "" {
		what += " (" + a.GroupValue + ")"
	}
	s.audit(r, audit.Entry{Action: "alert." + req.Status, Message: fmt.Sprintf("%s %s the alert %s", by, verb, what),
		Fields: map[string]string{"target": what}})
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if !s.canSeeAlerts(w, r) {
		return
	}
	list, err := s.deps.Repo.ListRules(r.Context())
	if err != nil {
		s.internal(w, "list rules", err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// validRule checks a rule, including that its search runs.
func (s *Server) validRule(w http.ResponseWriter, r *http.Request, ru *storage.Rule) bool {
	ru.Name = strings.TrimSpace(ru.Name)
	ru.Query = strings.TrimSpace(ru.Query)
	bad := func(msg string) bool { writeError(w, http.StatusBadRequest, msg); return false }
	switch {
	case ru.Name == "" || len(ru.Name) > 80:
		return bad("name must be 1-80 characters")
	case ru.Severity < 1 || ru.Severity > 6:
		return bad("severity must be 1-6")
	case ru.Threshold < 1 || ru.Threshold > 1_000_000:
		return bad("the number of events must be 1-1,000,000")
	case ru.WindowMinutes < 1 || ru.WindowMinutes > 7*24*60:
		return bad("the time window must be 1 minute to 7 days")
	case ru.MinSeverity != nil && (*ru.MinSeverity < 0 || *ru.MinSeverity > 6):
		return bad("minimum severity must be 0-6")
	case len(ru.Description) > 300:
		return bad("description must be at most 300 characters")
	}
	switch ru.GroupBy {
	case "", "src_ip", "dst_ip", "user", "host":
	default:
		return bad("group by must be src_ip, dst_ip, user, host or nothing")
	}
	if ru.SourceID != nil {
		if _, err := s.deps.Repo.GetSource(r.Context(), *ru.SourceID); err != nil {
			return bad("that source doesn't exist")
		}
	}
	if ru.Query != "" {
		if _, err := s.deps.Search.Search(r.Context(), searchProbe(ru.Query)); err != nil {
			return bad("the search doesn't work: " + err.Error())
		}
	}
	return true
}

// handleSaveRule creates (POST) or replaces (PUT /{id}) a rule.
func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request) {
	var ru storage.Rule
	if !decodeJSON(w, r, &ru, 8<<10) || !s.validRule(w, r, &ru) {
		return
	}
	ru.ID = 0
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		ru.ID = id
	}
	id, err := s.deps.Repo.SaveRule(r.Context(), ru, time.Now().UnixMilli())
	switch {
	case errors.Is(err, storage.ErrRuleExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, storage.ErrRuleNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		s.internal(w, "save rule", err)
		return
	}
	saved, _ := s.deps.Repo.GetRule(r.Context(), id)
	verb := map[bool]string{true: "updated", false: "created"}[r.Method == http.MethodPut]
	s.audit(r, audit.Entry{Action: "rule.save", Message: fmt.Sprintf("%s %s the alert rule %s", auth.FromContext(r.Context()).Name, verb, ru.Name),
		Fields: map[string]string{"target": ru.Name, "enabled": fmt.Sprint(ru.Enabled)}})
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, saved)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ru, err := s.deps.Repo.GetRule(r.Context(), id)
	if errors.Is(err, storage.ErrRuleNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "get rule", err)
		return
	}
	if ru.Builtin {
		writeError(w, http.StatusBadRequest, "built-in rules can't be deleted; switch them off instead")
		return
	}
	if err := s.deps.Repo.DeleteRule(r.Context(), id); err != nil {
		s.internal(w, "delete rule", err)
		return
	}
	s.audit(r, audit.Entry{Action: "rule.delete", Severity: 2, Message: auth.FromContext(r.Context()).Name + " deleted the alert rule " + ru.Name,
		Fields: map[string]string{"target": ru.Name}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
