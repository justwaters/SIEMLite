package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/secaudit"
)

// The Security audit page: repeatable checks of SIEMLite and the server it
// runs on (see pkg/secaudit). Admin only, since the findings describe how to
// attack this installation.

func (s *Server) auditReady(w http.ResponseWriter) bool {
	if s.deps.SecAudit == nil {
		writeError(w, http.StatusNotImplemented, "the security audit isn't available on this server")
		return false
	}
	return true
}

// auditEnv returns the checks' view of this installation: the flags it was
// started with plus what the database knows now.
func (s *Server) auditEnv(ctx context.Context) (*secaudit.Env, error) {
	cfg := s.deps.SecConfig
	cfg.Version = s.deps.Version
	cfg.TrustedProxies = s.deps.Proxies.Configured()
	if cfg.LocalAddr == "" {
		cfg.LocalAddr = s.deps.LocalAddr
	}
	users, err := s.deps.Repo.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Role == auth.RoleAdmin && !u.Disabled {
			cfg.EnabledAdmins++
		}
	}
	sg, err := s.signinState(ctx)
	if err != nil {
		return nil, err
	}
	cfg.BuiltinAdmin, cfg.AdminLocalOnly = sg.AdminAccount, sg.Enforced.AdminLocalOnly
	if s.deps.Certs != nil {
		st := s.deps.Certs.Status(ctx)
		served := st.SelfSigned
		if st.LetsEncrypt != nil {
			served = *st.LetsEncrypt
		}
		if served.NotAfter != 0 {
			cfg.CertNotAfter, cfg.CertSelfSigned = time.UnixMilli(served.NotAfter), served.SelfSigned
		}
	}
	if s.deps.Backups != nil {
		if set, err := s.deps.Backups.Settings(ctx); err == nil {
			cfg.BackupIntervalHours = set.IntervalHours
		}
		if list, err := s.deps.Backups.List(); err == nil && len(list) > 0 {
			cfg.LastBackup = time.UnixMilli(list[0].CreatedAt) // newest first
		}
		cfg.BackupDir = s.deps.Backups.Dir()
	}
	if s.deps.Updates != nil {
		st := s.deps.Updates.Check(ctx, false)
		cfg.UpdateChecks, cfg.UpdateAvailable, cfg.LatestVersion = true, st.Available, st.Latest
	}
	return secaudit.NewEnv(cfg), nil
}

func (s *Server) handleAuditState(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	st, err := s.deps.SecAudit.State(r.Context())
	if err != nil {
		s.internal(w, "security audit state", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func auditSummary(who string, c secaudit.Counts) string {
	return fmt.Sprintf("%s ran a security audit: %d failed, %d warnings, %d passed, %d skipped, %d accepted", who, c.Fail, c.Warn, c.Pass, c.Skip, c.Accepted)
}

func (s *Server) handleAuditRun(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	env, err := s.auditEnv(r.Context())
	if err != nil {
		s.internal(w, "security audit", err)
		return
	}
	who := auth.FromContext(r.Context()).Name
	run, err := s.deps.SecAudit.Run(r.Context(), env, who)
	if err != nil {
		s.internal(w, "security audit", err)
		return
	}
	sev := ocsf.SeverityInformational
	if run.Counts.Fail > 0 {
		sev = ocsf.SeverityMedium
	}
	s.audit(r, audit.Entry{Action: "security_audit.run", Severity: sev, Message: auditSummary(who, run.Counts)})
	writeJSON(w, http.StatusOK, s.stateWith(r.Context(), run))
}

// stateWith returns the page's state with run as the last run, so the reply
// to a run has the history that includes it.
func (s *Server) stateWith(ctx context.Context, run *secaudit.Run) secaudit.State {
	st, _ := s.deps.SecAudit.State(ctx)
	if run != nil {
		st.Last = run
	}
	return st
}

// auditError turns the service's errors into replies.
func (s *Server) auditError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, secaudit.ErrUnknown):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, secaudit.ErrNoFix), errors.Is(err, secaudit.ErrNoRun), errors.Is(err, secaudit.ErrNotOpen):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, secaudit.ErrNoteEmpty):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.internal(w, what, err)
	}
}

func (s *Server) handleAuditRecheck(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	env, err := s.auditEnv(r.Context())
	if err != nil {
		s.internal(w, "security audit", err)
		return
	}
	run, res, err := s.deps.SecAudit.Recheck(r.Context(), env, r.PathValue("id"))
	if err != nil {
		s.auditError(w, "recheck", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "counts": run.Counts})
}

func (s *Server) handleAuditFix(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	env, err := s.auditEnv(r.Context())
	if err != nil {
		s.internal(w, "security audit", err)
		return
	}
	id, who := r.PathValue("id"), auth.FromContext(r.Context()).Name
	msg, run, res, err := s.deps.SecAudit.Apply(r.Context(), env, id)
	if err != nil {
		s.auditError(w, "apply fix", err)
		return
	}
	s.deps.Logger.Warn("security audit fix applied", "check", id, "by", who)
	s.audit(r, audit.Entry{Action: "security_audit.fix", Severity: ocsf.SeverityMedium,
		Message: fmt.Sprintf("%s applied the security audit fix for %q: %s", who, res.Title, msg), Fields: map[string]string{"target": id}})
	writeJSON(w, http.StatusOK, map[string]any{"message": msg, "result": res, "counts": run.Counts})
}

func (s *Server) handleAuditAccept(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	id, who := r.PathValue("id"), auth.FromContext(r.Context()).Name
	if err := s.deps.SecAudit.Accept(r.Context(), id, who, req.Note); err != nil {
		s.auditError(w, "accept risk", err)
		return
	}
	s.audit(r, audit.Entry{Action: "security_audit.accept", Severity: ocsf.SeverityMedium,
		Message: fmt.Sprintf("%s accepted the risk of security audit check %s: %s", who, id, req.Note), Fields: map[string]string{"target": id}})
	writeJSON(w, http.StatusOK, s.stateWith(r.Context(), nil))
}

func (s *Server) handleAuditUnaccept(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	id, who := r.PathValue("id"), auth.FromContext(r.Context()).Name
	if err := s.deps.SecAudit.Unaccept(r.Context(), id); err != nil {
		s.auditError(w, "unaccept risk", err)
		return
	}
	s.audit(r, audit.Entry{Action: "security_audit.unaccept", Message: fmt.Sprintf("%s withdrew the accepted risk of security audit check %s", who, id),
		Fields: map[string]string{"target": id}})
	writeJSON(w, http.StatusOK, s.stateWith(r.Context(), nil))
}

// handleAuditReport downloads the last run: ?format=md (default) or json.
func (s *Server) handleAuditReport(w http.ResponseWriter, r *http.Request) {
	if !s.auditReady(w) {
		return
	}
	st, err := s.deps.SecAudit.State(r.Context())
	if err != nil {
		s.internal(w, "security audit report", err)
		return
	}
	if st.Last == nil {
		writeError(w, http.StatusConflict, secaudit.ErrNoRun.Error())
		return
	}
	name := "siemlite-security-audit-" + time.UnixMilli(st.Last.At).UTC().Format("20060102-1504")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, http.StatusOK, st.Last)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.md"`)
	_, _ = w.Write([]byte(st.Last.Markdown()))
}
