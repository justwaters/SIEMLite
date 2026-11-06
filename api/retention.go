package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/retention"
	"siemlite/pkg/storage"
)

// The System page's retention setting: how many days events are kept.

type retentionView struct {
	Days      int  `json:"days"`
	Default   int  `json:"default"`
	Min       int  `json:"min"`
	Max       int  `json:"max"`
	Saved     bool `json:"saved"` // chosen on the page, rather than -retention-days
	LateAfter int  `json:"late_after_days"`
	LateBurst int  `json:"late_burst"`
	Cleaning  bool `json:"cleaning,omitempty"`
}

func (s *Server) retentionState(ctx context.Context) retentionView {
	v := retentionView{Days: s.deps.Retention.Days(), Default: retention.DefaultDays, Min: retention.MinDays, Max: retention.MaxDays,
		LateAfter: int(ingest.LateAfter.Hours() / 24), LateBurst: ingest.LateBurst}
	if saved, err := s.deps.Repo.Setting(ctx, retention.SettingKey, ""); err == nil && saved != "" {
		v.Saved = true
	}
	return v
}

func (s *Server) handleGetRetention(w http.ResponseWriter, r *http.Request) {
	if s.deps.Retention == nil {
		writeError(w, http.StatusNotImplemented, "this server can't change how long events are kept")
		return
	}
	writeJSON(w, http.StatusOK, s.retentionState(r.Context()))
}

func (s *Server) handleSaveRetention(w http.ResponseWriter, r *http.Request) {
	if s.deps.Retention == nil {
		writeError(w, http.StatusNotImplemented, "this server can't change how long events are kept")
		return
	}
	var req struct {
		Days int `json:"days"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if req.Days < retention.MinDays || req.Days > retention.MaxDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Keep events between %d and %d days.", retention.MinDays, retention.MaxDays))
		return
	}
	was := s.deps.Retention.Days()
	if err := s.deps.Repo.SetSetting(r.Context(), retention.SettingKey, strconv.Itoa(req.Days)); err != nil {
		s.internal(w, "save the retention period", err)
		return
	}
	s.deps.Retention.SetDays(req.Days)
	if s.deps.Ingest != nil {
		s.deps.Ingest.SetMaxAge(time.Duration(req.Days) * 24 * time.Hour)
	}
	v := s.retentionState(r.Context())
	if req.Days < was {
		// Shorter: delete what is now too old straight away, not at the next daily clean.
		v.Cleaning = true
		go func() {
			n, err := s.deps.Retention.RunOnce(context.Background())
			if err != nil {
				s.deps.Logger.Error("cleaning up after the retention period was shortened failed", "err", err)
				return
			}
			s.deps.Logger.Info("retention period shortened; old events deleted", "days", req.Days, "deleted", n)
		}()
	}
	who := auth.FromContext(r.Context()).Name
	s.deps.Logger.Info("retention period changed", "from", was, "to", req.Days, "by", who)
	s.audit(r, audit.Entry{Action: "system.retention", Severity: map[bool]int{true: 4, false: 2}[req.Days < was],
		Message: fmt.Sprintf("%s set events to be kept %d days (was %d)", who, req.Days, was)})
	writeJSON(w, http.StatusOK, v)
}

// How long the original line of an event is kept after it arrives. The parsed
// event stays for the whole retention period; only the line as it arrived goes.

type rawKeepView struct {
	Hours    int  `json:"hours"` // 0 keeps original lines as long as their events
	Default  int  `json:"default"`
	Max      int  `json:"max"`
	Saved    bool `json:"saved"`
	Cleaning bool `json:"cleaning,omitempty"`
}

func (s *Server) rawKeepState(ctx context.Context) (rawKeepView, error) {
	hours, saved, err := s.deps.Repo.RawKeepHours(ctx)
	return rawKeepView{Hours: hours, Default: int(storage.RawKeep / time.Hour), Max: storage.MaxRawKeepHours, Saved: saved}, err
}

func (s *Server) handleGetRawKeep(w http.ResponseWriter, r *http.Request) {
	v, err := s.rawKeepState(r.Context())
	if err != nil {
		s.internal(w, "read how long original lines are kept", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveRawKeep(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours *int `json:"hours"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if req.Hours == nil || *req.Hours < 0 || *req.Hours > storage.MaxRawKeepHours {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Keep original lines between 0 (always) and %d hours.", storage.MaxRawKeepHours))
		return
	}
	was, err := s.rawKeepState(r.Context())
	if err != nil {
		s.internal(w, "read how long original lines are kept", err)
		return
	}
	if err := s.deps.Repo.SetRawKeepHours(r.Context(), *req.Hours); err != nil {
		s.internal(w, "save how long original lines are kept", err)
		return
	}
	v, err := s.rawKeepState(r.Context())
	if err != nil {
		s.internal(w, "read how long original lines are kept", err)
		return
	}
	// Shorter (0 is the longest): remove what is now too old at once, not at the next hourly pass.
	if v.Hours != 0 && (was.Hours == 0 || v.Hours < was.Hours) {
		v.Cleaning = true
		go func() {
			n, err := s.deps.Repo.PurgeRawLines(context.Background(), time.Now())
			if err != nil {
				s.deps.Logger.Error("removing original lines after the time was shortened failed", "err", err)
				return
			}
			s.deps.Logger.Info("original lines' keep time shortened; old lines removed", "hours", v.Hours, "removed", n)
		}()
	}
	describe := func(h int) string {
		if h == 0 {
			return "as long as their events"
		}
		return fmt.Sprintf("%d hours", h)
	}
	who := auth.FromContext(r.Context()).Name
	s.deps.Logger.Info("original lines' keep time changed", "from", was.Hours, "to", v.Hours, "by", who)
	s.audit(r, audit.Entry{Action: "system.raw_retention", Severity: map[bool]int{true: 4, false: 2}[v.Cleaning],
		Message: fmt.Sprintf("%s set original lines to be kept %s (was %s)", who, describe(v.Hours), describe(was.Hours))})
	writeJSON(w, http.StatusOK, v)
}
