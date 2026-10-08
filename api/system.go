package api

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/storage"
	"siemlite/pkg/update"
)

// maxUpload bounds an uploaded backup.
const maxUpload = 64 << 30

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func (s *Server) backupsReady(w http.ResponseWriter) bool {
	if s.deps.Backups == nil {
		writeError(w, http.StatusNotFound, "backups aren't available")
		return false
	}
	return true
}

// handleSystem reports the database, uptime and backups folder.
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Repo.Stats(r.Context())
	if err != nil {
		s.internal(w, "system status", err)
		return
	}
	out := map[string]any{
		"database": map[string]any{"path": absPath(s.deps.DB.Path()), "size_bytes": st.SizeBytes, "events": st.Events,
			"schema_version": storage.SchemaVersion, "days": st.Days, "events_dir": absPath(storage.EventsDir(s.deps.DB.Path())),
			"moving_events": s.deps.DB.MovingEvents()},
		"started_at": s.deps.Started.UnixMilli(),
		"version":    s.deps.Version,
	}
	if s.deps.Backups != nil {
		out["backups"] = map[string]any{"dir": s.deps.Backups.Dir(), "free_bytes": s.deps.Backups.Free()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	list, err := s.deps.Backups.List()
	if err != nil {
		s.internal(w, "list backups", err)
		return
	}
	set, err := s.deps.Backups.Settings(r.Context())
	if err != nil {
		s.internal(w, "backup settings", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": list, "status": s.deps.Backups.Status(), "settings": set})
}

// handleCreateBackup starts a backup in the background; poll the list for
// its status.
func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	if err := s.deps.Backups.Start(backup.Manual); errors.Is(err, backup.ErrBusy) {
		writeError(w, http.StatusConflict, err.Error())
		return
	} else if err != nil {
		s.internal(w, "start backup", err)
		return
	}
	s.deps.Logger.Info("backup started", "by", auth.FromContext(r.Context()).Name)
	s.audit(r, audit.Entry{Action: "backup.create", Message: auth.FromContext(r.Context()).Name + " started a backup"})
	writeJSON(w, http.StatusAccepted, s.deps.Backups.Status())
}

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	var set backup.Settings
	if !decodeJSON(w, r, &set, 1<<10) {
		return
	}
	if err := s.deps.Backups.SetSettings(r.Context(), set); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.deps.Logger.Info("backup schedule changed", "every_hours", set.IntervalHours, "keep", set.Keep, "by", auth.FromContext(r.Context()).Name)
	s.audit(r, audit.Entry{Action: "backup.schedule", Message: fmt.Sprintf("%s set automatic backups to every %d hours, keeping %d (0 hours means off)",
		auth.FromContext(r.Context()).Name, set.IntervalHours, set.Keep)})
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	f, err := s.deps.Backups.Open(r.PathValue("name"))
	if errors.Is(err, backup.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "open backup", err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		s.internal(w, "open backup", err)
		return
	}
	// Large backups take a while; outlast the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+info.Name()+`"`)
	s.deps.Logger.Info("backup downloaded", "name", info.Name(), "by", auth.FromContext(r.Context()).Name)
	s.audit(r, audit.Entry{Action: "backup.download", Severity: 2, Message: auth.FromContext(r.Context()).Name + " downloaded the backup " + info.Name(),
		Fields: map[string]string{"target": info.Name()}})
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// handleUploadBackup stores a backup from another server (the request body
// is the .db.gz or .db file).
func (s *Server) handleUploadBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(time.Hour))
	_ = rc.SetWriteDeadline(time.Now().Add(time.Hour))
	b, err := s.deps.Backups.Upload(r.Context(), http.MaxBytesReader(w, r.Body, maxUpload))
	if err != nil {
		writeError(w, http.StatusBadRequest, "That file can't be used as a backup: "+err.Error())
		return
	}
	s.deps.Logger.Info("backup uploaded", "name", b.Name, "by", auth.FromContext(r.Context()).Name)
	s.audit(r, audit.Entry{Action: "backup.upload", Message: auth.FromContext(r.Context()).Name + " uploaded the backup " + b.Name,
		Fields: map[string]string{"target": b.Name}})
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	name := r.PathValue("name")
	if err := s.deps.Backups.Delete(name); errors.Is(err, backup.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	} else if err != nil {
		s.internal(w, "delete backup", err)
		return
	}
	s.deps.Logger.Info("backup deleted", "name", name, "by", auth.FromContext(r.Context()).Name)
	s.audit(r, audit.Entry{Action: "backup.delete", Severity: 2, Message: auth.FromContext(r.Context()).Name + " deleted the backup " + name,
		Fields: map[string]string{"target": name}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleRestoreBackup checks the backup, saves the current database, then
// restarts SIEMLite, which swaps the backup in before opening the database.
func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	if !s.backupsReady(w) {
		return
	}
	if s.deps.Restart == nil {
		writeError(w, http.StatusNotImplemented, "this server can't restart itself")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	name := r.PathValue("name")
	safety, err := s.deps.Backups.StageRestore(r.Context(), name)
	switch {
	case errors.Is(err, backup.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case errors.Is(err, backup.ErrBusy):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "Nothing was changed: "+err.Error())
		return
	}
	s.deps.Logger.Warn("restore requested", "backup", name, "saved_current_as", safety.Name, "by", auth.FromContext(r.Context()).Name)
	// Recorded before the restart. It's in the database that was just saved
	// as safety, and the restored database won't contain it, so the restart
	// records the restore again once it's back (see main).
	s.audit(r, audit.Entry{Action: "backup.restore", Severity: 4, Message: auth.FromContext(r.Context()).Name + " restored the backup " + name +
		"; the database before it was saved as " + safety.Name, Fields: map[string]string{"target": name, "saved_as": safety.Name}})
	writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true, "saved_current_as": safety.Name})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// Restart after the reply has gone out.
	go func() {
		time.Sleep(300 * time.Millisecond)
		s.deps.Restart()
	}()
}

// handleUpdateStatus reports the running version and whether a newer release
// exists. ?refresh=1 checks GitHub now instead of using the cached answer.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Updates == nil {
		writeJSON(w, http.StatusOK, update.Status{Current: s.deps.Version, WhyNot: "Update checks are turned off on this server."})
		return
	}
	writeJSON(w, http.StatusOK, s.deps.Updates.Check(r.Context(), r.URL.Query().Get("refresh") == "1"))
}

// handleApplyUpdate installs the latest release over the running program,
// then restarts SIEMLite so the new one takes over.
func (s *Server) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.deps.Updates == nil || s.deps.Restart == nil {
		writeError(w, http.StatusNotImplemented, "this server can't update itself")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Minute))
	who := auth.FromContext(r.Context()).Name
	from := s.deps.Version
	to, err := s.deps.Updates.Apply(r.Context())
	switch {
	case errors.Is(err, update.ErrNotAvailable):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.deps.Logger.Warn("update failed", "err", err, "by", who)
		writeError(w, http.StatusBadGateway, "Nothing was changed: "+err.Error())
		return
	}
	s.deps.Logger.Warn("update installed", "from", from, "to", to, "by", who)
	s.audit(r, audit.Entry{Action: "system.update", Severity: 3, Message: fmt.Sprintf("%s updated SIEMLite from %s to %s", who, from, to),
		Fields: map[string]string{"from": from, "to": to}})
	writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true, "version": to})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		s.deps.Restart()
	}()
}
