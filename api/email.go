package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/email"
	"siemlite/pkg/integrations"
)

// emailRequest is the System page's email form. Password is a pointer so the
// form can say "keep the saved one" (absent) or "replace it" (a string; an
// empty one removes it).
type emailRequest struct {
	email.Config
	Password *string `json:"password"`
	To       string  `json:"to"` // test only
}

const maxPasswordLen = 512

func (s *Server) emailReady(w http.ResponseWriter) bool {
	if s.deps.Email == nil {
		writeError(w, http.StatusNotImplemented, "this server can't send email")
		return false
	}
	return true
}

func (r emailRequest) check() error {
	if r.Password != nil && len(*r.Password) > maxPasswordLen {
		return errors.New("The password is too long.")
	}
	return nil
}

// handleGetEmail returns the saved mail server settings, never the password.
func (s *Server) handleGetEmail(w http.ResponseWriter, r *http.Request) {
	if !s.emailReady(w) {
		return
	}
	v, err := s.deps.Email.Get(r.Context())
	if err != nil {
		s.internal(w, "read email settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleSaveEmail saves the mail server settings. A body with no host clears them.
func (s *Server) handleSaveEmail(w http.ResponseWriter, r *http.Request) {
	if !s.emailReady(w) {
		return
	}
	var req emailRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	if err := req.check(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	who := auth.FromContext(r.Context()).Name
	if err := s.deps.Email.Save(r.Context(), req.Config, req.Password); err != nil {
		var bad email.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save email settings", err)
		return
	}
	host := strings.TrimSpace(req.Host)
	msg := who + " cleared the email settings"
	if host != "" {
		msg = fmt.Sprintf("%s set SIEMLite to send email through %s:%d (%s)", who, host, req.Port, req.Security)
		if req.Password != nil {
			msg += ", and changed the password"
		}
	}
	s.deps.Logger.Info("email settings changed", "by", who, "host", host)
	s.audit(r, audit.Entry{Action: "system.email.save", Severity: 3, Message: msg, Fields: map[string]string{"target": host}})
	v, err := s.deps.Email.Get(r.Context())
	if err != nil {
		s.internal(w, "read email settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleTestEmail sends a test message with the settings in the form (using
// the saved password unless the form has one), so they can be checked before
// they are saved.
func (s *Server) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	if !s.emailReady(w) {
		return
	}
	var req emailRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	if err := req.check(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if err := req.Config.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(90 * time.Second))
	who := auth.FromContext(r.Context()).Name
	host, _ := os.Hostname()
	body := fmt.Sprintf("This is a test email from SIEMLite %s%s.\n\nIt was sent by %s through %s:%d. If you can read it, email is set up.\n",
		s.deps.Version, onHost(host), who, req.Host, req.Port)
	err := s.deps.Email.SendWith(r.Context(), req.Config, req.Password, email.Message{To: []string{req.To}, Subject: "SIEMLite test email", Body: body})
	var bad email.InputError
	if errors.As(err, &bad) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.deps.Logger.Warn("test email failed", "by", who, "host", req.Host, "err", err)
		s.audit(r, audit.Entry{Action: "system.email.test", Severity: 2, Message: fmt.Sprintf("%s tried to send a test email through %s:%d and it failed", who, req.Host, req.Port),
			Fields: map[string]string{"target": req.Host, "result": "failed"}})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.deps.Logger.Info("test email sent", "by", who, "host", req.Host)
	s.audit(r, audit.Entry{Action: "system.email.test", Message: fmt.Sprintf("%s sent a test email through %s:%d", who, req.Host, req.Port),
		Fields: map[string]string{"target": req.Host, "result": "sent"}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func onHost(h string) string {
	if h == "" {
		return ""
	}
	return " on " + h
}

// handleListIntegrations lists the built-in integrations and their state.
func (s *Server) handleListIntegrations(w http.ResponseWriter, r *http.Request) {
	if s.deps.Integrations == nil {
		writeJSON(w, http.StatusOK, map[string]any{"integrations": []integrations.Info{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": s.deps.Integrations.List(r.Context())})
}

// handleSetIntegrationEnabled turns an integration on or off, keeping its settings.
func (s *Server) handleSetIntegrationEnabled(w http.ResponseWriter, r *http.Request) {
	if s.deps.Integrations == nil {
		writeError(w, http.StatusNotFound, "there are no integrations on this server")
		return
	}
	it, ok := s.deps.Integrations.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "there is no integration called "+r.PathValue("id"))
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &body, 1<<10) {
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, `Send {"enabled": true} or {"enabled": false}.`)
		return
	}
	who := auth.FromContext(r.Context()).Name
	if err := it.SetEnabled(r.Context(), *body.Enabled); err != nil {
		var bad integrations.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "turn "+it.ID()+" on or off", err)
		return
	}
	verb := "turned off"
	if *body.Enabled {
		verb = "turned on"
	}
	s.deps.Logger.Info("integration switched", "integration", it.ID(), "enabled", *body.Enabled, "by", who)
	s.audit(r, audit.Entry{Action: "integration." + map[bool]string{true: "enable", false: "disable"}[*body.Enabled], Severity: 3,
		Message: fmt.Sprintf("%s %s the %s integration", who, verb, it.Name()), Fields: map[string]string{"target": it.ID()}})
	writeJSON(w, http.StatusOK, integrations.Describe(r.Context(), it))
}
