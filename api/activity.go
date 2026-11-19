package api

import (
	"fmt"
	"net/http"
)

// Task is one download or other long job running on the server, for the activity tray.
// Total is 0 when its size isn't known, and the tray shows a spinner instead of a bar.
type Task struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Done   int64  `json:"done"`
	Total  int64  `json:"total"`
	Bytes  bool   `json:"bytes,omitempty"` // Done and Total are bytes
}

// handleActivity lists what the server is downloading or working on now. The jobs run on the
// server whatever page anyone has open; this only reports them.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	tasks := []Task{}
	if s.deps.Intel != nil {
		if now, done, total := s.deps.Intel.Activity(); total > 0 {
			tasks = append(tasks, Task{ID: "feeds", Label: "Downloading threat feeds", Detail: fmt.Sprintf("%s (%d of %d)", now, done+1, total), Done: int64(done), Total: int64(total)})
		}
	}
	if s.deps.AI != nil {
		if p, ok := s.deps.AI.PullProgress(); ok {
			t := Task{ID: "ai-model", Label: "Downloading the AI model", Detail: p.Model, Done: p.Completed, Total: p.Total, Bytes: true}
			if p.Total == 0 {
				t.Detail = p.Model + ": " + p.Status
			}
			tasks = append(tasks, t)
		}
	}
	if s.deps.Backups != nil {
		if st := s.deps.Backups.Status(); st.Running {
			tasks = append(tasks, Task{ID: "backup", Label: "Creating a backup", Detail: "Logging carries on while it runs."})
		}
	}
	if s.deps.Updates != nil {
		if active, done, total := s.deps.Updates.Progress(); active {
			tasks = append(tasks, Task{ID: "update", Label: "Downloading the update", Done: done, Total: total, Bytes: true})
		}
	}
	writeJSON(w, http.StatusOK, map[string][]Task{"tasks": tasks})
}
