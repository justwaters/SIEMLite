package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/chatnotify"
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
	if a.GroupLabel != "" {
		what += " (" + a.GroupLabel + ")"
	} else if a.GroupValue != "" {
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
	if storage.HasRepeatMark(ru.Query) {
		return bad("the search has a control character in it")
	}
	switch ru.GroupBy {
	case "", "src_ip", "dst_ip", "user", "host", "source":
	default:
		return bad("group by must be src_ip, dst_ip, user, host, source or nothing")
	}
	switch ru.Kind {
	case "":
		ru.Kind = storage.RuleMatch
	case storage.RuleMatch, storage.RuleVolumeOver, storage.RuleVolumeUnder,
		storage.RuleRepeatSeverity, storage.RuleRepeatKeyword, storage.RuleRepeatBoth:
	default:
		return bad("kind must be match, volume_over, volume_under, repeat_severity, repeat_keyword or repeat_both")
	}
	if ru.IsVolume() {
		// A volume rule counts everything one source sends, so it has no
		// search or grouping of its own.
		if ru.SourceID == nil {
			return bad("choose the source to watch")
		}
		ru.Query, ru.MinSeverity, ru.ThreatOnly, ru.GroupBy = "", nil, false, ""
	}
	if ru.IsRepeat() {
		// A repeat rule counts one user's events, so it is always grouped by user.
		ru.GroupBy = "user"
		if ru.Threshold < 2 {
			return bad("a repeat rule needs at least 2 events")
		}
		if ru.Kind != storage.RuleRepeatSeverity {
			if strings.IndexFunc(ru.Query, unicode.IsControl) >= 0 {
				return bad("keywords can't contain line breaks or control characters")
			}
			kw := storage.RepeatKeywords(ru.Query)
			switch {
			case len(kw) == 0:
				return bad("give at least one keyword, separated by commas")
			case len(kw) > 20:
				return bad("give at most 20 keywords")
			}
			for _, k := range kw {
				if len([]rune(k)) > 100 {
					return bad("each keyword must be at most 100 characters")
				}
				if _, err := s.deps.Search.Search(r.Context(), searchProbe(storage.KeywordPhrase(k))); err != nil {
					return bad(fmt.Sprintf("the keyword %q doesn't work: %v", k, err))
				}
			}
			ru.Query = strings.Join(kw, ", ")
		}
	}
	if ru.SourceID != nil {
		if _, err := s.deps.Repo.GetSource(r.Context(), *ru.SourceID); err != nil {
			return bad("that source doesn't exist")
		}
	}
	if ru.Query != "" && (!ru.IsRepeat() || ru.Kind == storage.RuleRepeatSeverity) {
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
		// The improbable travel rule is found by its name and runs as a match rule: those stay.
		if cur, err := s.deps.Repo.GetRule(r.Context(), id); err == nil && cur.Builtin && strings.EqualFold(cur.Name, storage.TravelRuleName) &&
			(ru.Name != cur.Name || ru.Kind != storage.RuleMatch) {
			writeError(w, http.StatusBadRequest, "the name and kind of the "+cur.Name+" rule can't be changed")
			return
		}
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

// handleCreateAlert opens an alert by hand: something a person or an AI agent
// found that no rule describes. Raising the same title and group again updates
// the open alert instead of opening another.
func (s *Server) handleCreateAlert(w http.ResponseWriter, r *http.Request) {
	if !s.canSeeAlerts(w, r) {
		return
	}
	var req struct {
		Title      string `json:"title"`
		Severity   int    `json:"severity"`
		GroupBy    string `json:"group_by"`
		GroupValue string `json:"group_value"`
		Count      int64  `json:"count"`
		Note       string `json:"note"`
	}
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	req.Title, req.GroupValue, req.Note = strings.TrimSpace(req.Title), strings.TrimSpace(req.GroupValue), strings.TrimSpace(req.Note)
	if req.Count == 0 {
		req.Count = 1
	}
	bad := func(msg string) { writeError(w, http.StatusBadRequest, msg) }
	switch {
	case req.Title == "" || len([]rune(req.Title)) > 80:
		bad("title must be 1-80 characters")
		return
	case req.Severity < 1 || req.Severity > 6:
		bad("severity must be 1-6")
		return
	case req.Count < 1 || req.Count > 1_000_000:
		bad("count must be 1-1,000,000")
		return
	case len([]rune(req.GroupValue)) > 200:
		bad("group_value must be at most 200 characters")
		return
	case len([]rune(req.Note)) > 1000:
		bad("note must be at most 1000 characters")
		return
	}
	switch req.GroupBy {
	case "", "src_ip", "dst_ip", "user", "host":
	default:
		bad("group_by must be src_ip, dst_ip, user, host or nothing")
		return
	}
	if req.GroupBy == "" && req.GroupValue != "" {
		bad("group_value needs group_by")
		return
	}
	by := auth.FromContext(r.Context()).Name
	a, created, err := s.deps.Repo.RaiseManualAlert(r.Context(), storage.Alert{RuleName: req.Title, Severity: req.Severity,
		GroupBy: req.GroupBy, GroupValue: req.GroupValue, Count: req.Count, Note: req.Note, UpdatedBy: by}, time.Now().UnixMilli())
	if err != nil {
		s.internal(w, "create alert", err)
		return
	}
	what := a.RuleName
	if a.GroupLabel != "" {
		what += " (" + a.GroupLabel + ")"
	} else if a.GroupValue != "" {
		what += " (" + a.GroupValue + ")"
	}
	verb, action, status := "raised", "alert.create", http.StatusCreated
	if !created {
		verb, action, status = "added to", "alert.update", http.StatusOK
	}
	s.audit(r, audit.Entry{Action: action, Severity: 2, Message: fmt.Sprintf("%s %s the alert %s", by, verb, what),
		Fields: map[string]string{"target": what, "alert_severity": fmt.Sprint(a.Severity)}})
	if created {
		s.notifyChat(chatnotify.Alert{Title: a.RuleName, Severity: a.Severity, GroupBy: a.GroupBy, GroupValue: a.GroupValue, Count: a.Count, Note: a.Note, At: time.Now(), Manual: true})
	}
	writeJSON(w, status, a)
}
