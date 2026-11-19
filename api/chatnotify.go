package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/chatnotify"
	"siemlite/pkg/integrations"
)

// The Slack and Microsoft Teams integrations: an incoming-webhook address, and the lowest severity to post.

type chatRequest struct {
	Webhook     *string `json:"webhook"` // nil keeps the saved address; "" removes it
	MinSeverity int     `json:"min_severity"`
}

func (s *Server) chatSvc(w http.ResponseWriter, svc *chatnotify.Service) bool {
	if svc == nil {
		writeError(w, http.StatusNotImplemented, "this server can't post to chat")
		return false
	}
	return true
}

func (s *Server) chatGet(svc func() *chatnotify.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.chatSvc(w, svc()) {
			return
		}
		v, err := svc().Get(r.Context())
		if err != nil {
			s.internal(w, "read the chat settings", err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) chatSave(svc func() *chatnotify.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := svc()
		if !s.chatSvc(w, c) {
			return
		}
		var req chatRequest
		if !decodeJSON(w, r, &req, 8<<10) {
			return
		}
		if err := c.Save(r.Context(), req.Webhook, req.MinSeverity); err != nil {
			var bad integrations.InputError
			if errors.As(err, &bad) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.internal(w, "save the chat settings", err)
			return
		}
		s.audit(r, audit.Entry{Action: "system." + c.ID() + ".save", Severity: 2,
			Message: fmt.Sprintf("%s changed the %s settings (posting alerts of %s and above)", auth.FromContext(r.Context()).Name, c.Name(), chatnotify.SeverityName(req.MinSeverity))})
		s.chatGet(svc)(w, r)
	}
}

func (s *Server) chatTest(svc func() *chatnotify.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := svc()
		if !s.chatSvc(w, c) {
			return
		}
		var req struct {
			Webhook string `json:"webhook"`
		}
		if !decodeJSON(w, r, &req, 8<<10) {
			return
		}
		who := auth.FromContext(r.Context()).Name
		err := c.Test(r.Context(), req.Webhook, who)
		var bad integrations.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			s.audit(r, audit.Entry{Action: "system." + c.ID() + ".test", Severity: 2, Message: fmt.Sprintf("%s sent a test message to %s and it failed", who, c.Name())})
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		s.audit(r, audit.Entry{Action: "system." + c.ID() + ".test", Message: fmt.Sprintf("%s sent a test message to %s", who, c.Name())})
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
	}
}

// notifyChat announces an alert in every chat integration that is on and wants it.
func (s *Server) notifyChat(a chatnotify.Alert) {
	if s.deps.Notify == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		s.deps.Notify(ctx, a)
	}()
}
