package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/integrations"
	"siemlite/pkg/intel"
	"siemlite/pkg/storage"
)

// The Intel page: an admin picks free
// blocklists (pkg/intel presets) to download on a schedule.

func (s *Server) handleGetThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download threat feeds")
		return
	}
	v, err := s.deps.Intel.Feeds(r.Context())
	if err != nil {
		s.internal(w, "read the threat feeds", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download threat feeds")
		return
	}
	var req struct {
		Feeds []string `json:"feeds"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if err := s.deps.Intel.SetFeeds(r.Context(), req.Feeds); err != nil {
		var bad integrations.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save the threat feeds", err)
		return
	}
	list := strings.Join(req.Feeds, ", ")
	if list == "" {
		list = "none"
	}
	s.audit(r, audit.Entry{Action: "system.threatfeeds.save", Severity: 2,
		Message: fmt.Sprintf("%s chose the threat feeds: %s", auth.FromContext(r.Context()).Name, list)})
	s.handleGetThreatFeeds(w, r)
}

// handleRefreshThreatFeeds downloads the chosen feeds now, in the background.
func (s *Server) handleRefreshThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		writeError(w, http.StatusNotImplemented, "this server can't download threat feeds")
		return
	}
	s.deps.Intel.RefreshAsync()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// Friendly lists: addresses and ranges the threat intel check never flags.

func (s *Server) friendlyReady(w http.ResponseWriter) bool {
	if s.deps.Intel == nil {
		writeError(w, http.StatusNotImplemented, "this server has no threat intel")
		return false
	}
	return true
}

func (s *Server) handleListFriendly(w http.ResponseWriter, r *http.Request) {
	lists, err := s.deps.Repo.FriendlyLists(r.Context())
	if err != nil {
		s.internal(w, "list the friendly lists", err)
		return
	}
	if lists == nil {
		lists = []storage.FriendlyList{}
	}
	writeJSON(w, http.StatusOK, lists)
}

// friendlyFields checks a list's name and description.
func friendlyFields(name, desc string) (string, string, string) {
	name, desc = strings.TrimSpace(name), strings.TrimSpace(desc)
	switch {
	case name == "" || len([]rune(name)) > 60:
		return "", "", "Give the list a name of up to 60 characters."
	case len([]rune(desc)) > 300:
		return "", "", "Keep the description to 300 characters."
	}
	return name, desc, ""
}

func (s *Server) handleCreateFriendly(w http.ResponseWriter, r *http.Request) {
	if !s.friendlyReady(w) {
		return
	}
	var req struct{ Name, Description string }
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	name, desc, msg := friendlyFields(req.Name, req.Description)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	lists, err := s.deps.Repo.FriendlyLists(r.Context())
	if err != nil {
		s.internal(w, "list the friendly lists", err)
		return
	}
	if len(lists) >= intel.MaxFriendlyLists {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("There are already %d lists; delete one first.", intel.MaxFriendlyLists))
		return
	}
	id, err := s.deps.Repo.CreateFriendlyList(r.Context(), name, desc, time.Now().UnixMilli())
	if errors.Is(err, storage.ErrFriendlyNameTaken) {
		writeError(w, http.StatusConflict, err.Error())
		return
	} else if err != nil {
		s.internal(w, "create a friendly list", err)
		return
	}
	s.audit(r, audit.Entry{Action: "intel.friendly.create", Severity: 2, Fields: map[string]string{"target": name},
		Message: fmt.Sprintf("%s created the friendly list %s", auth.FromContext(r.Context()).Name, name)})
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) handleUpdateFriendly(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.friendlyReady(w) {
		return
	}
	var req struct{ Name, Description string }
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	name, desc, msg := friendlyFields(req.Name, req.Description)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	err := s.deps.Repo.UpdateFriendlyList(r.Context(), id, name, desc)
	switch {
	case errors.Is(err, storage.ErrFriendlyListNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case errors.Is(err, storage.ErrFriendlyNameTaken):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, "update a friendly list", err)
		return
	}
	s.audit(r, audit.Entry{Action: "intel.friendly.update", Severity: 2, Fields: map[string]string{"target": name},
		Message: fmt.Sprintf("%s changed the friendly list %s", auth.FromContext(r.Context()).Name, name)})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteFriendly(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.friendlyReady(w) {
		return
	}
	name, err := s.deps.Repo.DeleteFriendlyList(r.Context(), id)
	if errors.Is(err, storage.ErrFriendlyListNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "delete a friendly list", err)
		return
	}
	_ = s.deps.Intel.Load(r.Context()) // take effect now, not at the next check
	s.audit(r, audit.Entry{Action: "intel.friendly.delete", Severity: 3, Fields: map[string]string{"target": name},
		Message: fmt.Sprintf("%s deleted the friendly list %s", auth.FromContext(r.Context()).Name, name)})
	w.WriteHeader(http.StatusNoContent)
}

// handleAddFriendlyEntries adds addresses and ranges, written as text, to a list.
// Anything that can't be read is reported and nothing is added.
func (s *Server) handleAddFriendlyEntries(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.friendlyReady(w) {
		return
	}
	var req struct {
		Values string `json:"values"`
		Note   string `json:"note"`
	}
	if !decodeJSON(w, r, &req, 256<<10) {
		return
	}
	note := strings.TrimSpace(req.Note)
	if len([]rune(note)) > 200 {
		writeError(w, http.StatusBadRequest, "Keep the note to 200 characters.")
		return
	}
	values, bad := intel.ParseFriendly(req.Values)
	switch {
	case len(bad) > 0:
		if len(bad) > 5 {
			bad = append(bad[:5], "…")
		}
		writeError(w, http.StatusBadRequest, "These aren't IP addresses or ranges: "+strings.Join(bad, ", ")+". Nothing was added.")
		return
	case len(values) == 0:
		writeError(w, http.StatusBadRequest, "Enter at least one IP address or range, such as 203.0.113.7 or 198.51.100.0/24.")
		return
	case len(values) > intel.MaxFriendlyAdd:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Add up to %d at a time.", intel.MaxFriendlyAdd))
		return
	}
	lists, err := s.deps.Repo.FriendlyLists(r.Context())
	if err != nil {
		s.internal(w, "list the friendly lists", err)
		return
	}
	var cur *storage.FriendlyList
	for i := range lists {
		if lists[i].ID == id {
			cur = &lists[i]
		}
	}
	if cur == nil {
		writeError(w, http.StatusNotFound, storage.ErrFriendlyListNotFound.Error())
		return
	}
	if len(cur.Entries)+len(values) > intel.MaxFriendlyEntries {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("A list holds up to %d entries.", intel.MaxFriendlyEntries))
		return
	}
	added, err := s.deps.Repo.AddFriendlyEntries(r.Context(), id, values, note, time.Now().UnixMilli())
	if err != nil {
		s.internal(w, "add to a friendly list", err)
		return
	}
	sample := strings.Join(values[:min(len(values), 5)], ", ")
	if len(values) > 5 {
		sample += ", …"
	}
	_ = s.deps.Intel.Load(r.Context()) // take effect now, not at the next check
	s.audit(r, audit.Entry{Action: "intel.friendly.add", Severity: 2, Fields: map[string]string{"target": cur.Name},
		Message: fmt.Sprintf("%s added %d %s to the friendly list %s: %s", auth.FromContext(r.Context()).Name, added, plural(added, "entry", "entries"), cur.Name, sample)})
	writeJSON(w, http.StatusOK, map[string]int{"added": added, "already_there": len(values) - added})
}

func (s *Server) handleDeleteFriendlyEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.friendlyReady(w) {
		return
	}
	value := r.URL.Query().Get("value")
	found, err := s.deps.Repo.DeleteFriendlyEntry(r.Context(), id, value)
	if err != nil {
		s.internal(w, "remove a friendly entry", err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "that entry isn't in the list")
		return
	}
	_ = s.deps.Intel.Load(r.Context()) // take effect now, not at the next check
	s.audit(r, audit.Entry{Action: "intel.friendly.remove", Severity: 2, Fields: map[string]string{"target": value},
		Message: fmt.Sprintf("%s removed %s from a friendly list", auth.FromContext(r.Context()).Name, value)})
	w.WriteHeader(http.StatusNoContent)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
