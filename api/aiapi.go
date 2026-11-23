package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/ai"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
)

// The AI Parsers card on the Integrations page (pkg/ai).

// aiRequest is the card's form. APIKey is a pointer so the form can keep the
// saved key (absent), replace it, or remove it (""); it is for the cloud
// service KeyFor, or the chosen provider. OpenRouterKey is its name from v0.19.
type aiRequest struct {
	ai.Settings
	APIKey        *string `json:"api_key"`
	KeyFor        string  `json:"key_for"`
	OpenRouterKey *string `json:"openrouter_key"`
}

func (r aiRequest) key() (string, *string) {
	if r.APIKey != nil {
		return r.KeyFor, r.APIKey
	}
	if r.OpenRouterKey != nil {
		return ai.ProviderCloud, r.OpenRouterKey
	}
	return r.KeyFor, nil
}

func (s *Server) aiReady(w http.ResponseWriter) bool {
	if s.deps.AI == nil {
		writeError(w, http.StatusNotImplemented, "this server can't use AI Parsers")
		return false
	}
	return true
}

func (s *Server) handleGetAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	v, err := s.deps.AI.Get(r.Context())
	if err != nil {
		s.internal(w, "read the AI Parsers settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var req aiRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	keyFor, key := req.key()
	if err := s.deps.AI.Save(r.Context(), req.Settings, keyFor, key); err != nil {
		var bad ai.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save the AI Parsers settings", err)
		return
	}
	who := auth.FromContext(r.Context()).Name
	msg := fmt.Sprintf("%s set AI Parsers to run on this server with Ollama at %s, model %s", who, req.OllamaURL, req.LocalModel)
	if svc, ok := cloudServiceNamed(req.Provider); ok {
		msg = fmt.Sprintf("%s set AI Parsers to run in the cloud with %s, model %s, addresses %s", who, svc, req.CloudModel,
			map[bool]string{false: "replaced before sending", true: "sent as they are"}[req.SendAddresses]) +
			map[bool]string{false: "", true: ", free models allowed"}[req.AllowFree]
	}
	if key != nil {
		if keyFor == "" {
			keyFor = req.Provider
		}
		name, _ := cloudServiceNamed(keyFor)
		msg += map[bool]string{true: ", and removed the " + name + " key", false: ", and changed the " + name + " key"}[*key == ""]
	}
	s.deps.Logger.Info("AI Parsers settings changed", "by", who, "provider", req.Provider)
	s.audit(r, audit.Entry{Action: "system.ai.save", Severity: 3, Message: msg})
	v, err := s.deps.AI.Get(r.Context())
	if err != nil {
		s.internal(w, "read the AI Parsers settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleTestAI checks the form's settings against Ollama or OpenRouter without saving.
func (s *Server) handleTestAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var req aiRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	_, key := req.key()
	res, err := s.deps.AI.Test(r.Context(), req.Settings, key)
	var bad ai.InputError
	switch {
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleCloudModels lists a cloud service's models for the card: GET with
// ?provider= uses the saved key; POST {"provider", "api_key"} the one typed.
func (s *Server) handleCloudModels(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	req := struct {
		Provider string  `json:"provider"`
		APIKey   *string `json:"api_key"`
	}{Provider: r.URL.Query().Get("provider")}
	if r.Method == http.MethodPost && !decodeJSON(w, r, &req, 2<<10) {
		return
	}
	if req.Provider == "" {
		req.Provider = ai.ProviderCloud
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	models, rec, err := s.deps.AI.CloudModels(r.Context(), req.Provider, req.APIKey)
	var bad ai.InputError
	switch {
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if models == nil {
		models = []ai.CloudModel{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models, "recommended": rec})
}

func cloudServiceNamed(id string) (string, bool) {
	for _, c := range ai.CloudServices {
		if c.ID == id {
			return c.Name, true
		}
	}
	return "", false
}
