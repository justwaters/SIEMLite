package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/aialerts"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/integrations"
	"siemlite/pkg/storage"
)

// The AI Alerts card on the Integrations page (pkg/aialerts): the model proposes
// alert rules, and a person accepts or dismisses each one.

func (s *Server) aiAlertsReady(w http.ResponseWriter) bool {
	if s.deps.AIAlerts == nil {
		writeError(w, http.StatusNotImplemented, "this server can't use AI Alerts")
		return false
	}
	return true
}

func (s *Server) handleGetAIAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.aiAlertsReady(w) {
		return
	}
	v, err := s.deps.AIAlerts.Get(r.Context())
	if err != nil {
		s.internal(w, "read the AI Alerts settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveAIAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.aiAlertsReady(w) {
		return
	}
	var req aialerts.Settings
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if err := s.deps.AIAlerts.Save(r.Context(), req); err != nil {
		var bad integrations.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save the AI Alerts settings", err)
		return
	}
	s.audit(r, audit.Entry{Action: "system.aialerts.save", Severity: 2,
		Message: fmt.Sprintf("%s set AI Alerts to look every %d hours at the last %d hours", auth.FromContext(r.Context()).Name, req.IntervalHours, req.LookbackHours)})
	s.handleGetAIAlerts(w, r)
}

// handleRunAIAlerts starts a look now; it runs in the background.
func (s *Server) handleRunAIAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.aiAlertsReady(w) {
		return
	}
	if err := s.deps.AIAlerts.RunNow(r.Context()); err != nil {
		var bad integrations.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "start AI Alerts", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "all":
		status = ""
	case storage.ProposalPending, storage.ProposalAccepted, storage.ProposalDismissed:
	default:
		writeError(w, http.StatusBadRequest, "status must be pending, accepted, dismissed or all")
		return
	}
	list, err := s.deps.Repo.ListProposals(r.Context(), status, 200)
	if err != nil {
		s.internal(w, "list proposed rules", err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// handleAcceptProposal makes a proposed rule a real one, switched on, through
// the same checks as a rule made by hand.
func (s *Server) handleAcceptProposal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.deps.Repo.GetProposal(r.Context(), id)
	if err == nil && p.Status != storage.ProposalPending {
		err = storage.ErrProposalNotFound
	}
	if errors.Is(err, storage.ErrProposalNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "read a proposed rule", err)
		return
	}
	ru := p.Rule()
	if !s.validRule(w, r, &ru) {
		return
	}
	now := time.Now().UnixMilli()
	ruleID, err := s.deps.Repo.SaveRule(r.Context(), ru, now)
	switch {
	case errors.Is(err, storage.ErrRuleExists):
		writeError(w, http.StatusConflict, "a rule named "+ru.Name+" already exists; dismiss this proposal or rename that rule")
		return
	case err != nil:
		s.internal(w, "save the rule", err)
		return
	}
	by := auth.FromContext(r.Context()).Name
	if err := s.deps.Repo.DecideProposal(r.Context(), id, storage.ProposalAccepted, by, now); err != nil && !errors.Is(err, storage.ErrProposalNotFound) {
		s.internal(w, "mark the proposal accepted", err)
		return
	}
	s.audit(r, audit.Entry{Action: "rule.save", Message: fmt.Sprintf("%s accepted the AI-proposed alert rule %s", by, ru.Name),
		Fields: map[string]string{"target": ru.Name, "enabled": "true", "proposed_by": "ai"}})
	saved, _ := s.deps.Repo.GetRule(r.Context(), ruleID)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDismissProposal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.deps.Repo.GetProposal(r.Context(), id)
	if err == nil {
		err = s.deps.Repo.DecideProposal(r.Context(), id, storage.ProposalDismissed, auth.FromContext(r.Context()).Name, time.Now().UnixMilli())
	}
	if errors.Is(err, storage.ErrProposalNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "dismiss a proposed rule", err)
		return
	}
	s.audit(r, audit.Entry{Action: "aialerts.dismiss", Message: fmt.Sprintf("%s dismissed the AI-proposed alert rule %s", auth.FromContext(r.Context()).Name, p.Name),
		Fields: map[string]string{"target": p.Name}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "dismissed"})
}
