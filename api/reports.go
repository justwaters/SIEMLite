package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/integrations"
	"siemlite/pkg/report"
	"siemlite/pkg/storage"
)

// The Reports page: a summary of a period, made into a PDF on demand or on a schedule.

func (s *Server) reportsReady(w http.ResponseWriter) bool {
	if s.deps.Reports == nil {
		writeError(w, http.StatusNotImplemented, "this server can't make reports")
		return false
	}
	return true
}

func (s *Server) reportErr(w http.ResponseWriter, what string, err error) {
	var bad integrations.InputError
	switch {
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, storage.ErrReportNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		s.internal(w, what, err)
	}
}

// reportPeriod reads ?days=N (the last N days, ending now) or from= and to= (milliseconds).
func reportPeriod(r *http.Request, body *periodBody) (start, end int64, msg string) {
	var days int
	var from, to int64
	if body != nil {
		days, from, to = body.Days, body.From, body.To
	} else {
		q := r.URL.Query()
		days, _ = strconv.Atoi(q.Get("days"))
		from, _ = strconv.ParseInt(q.Get("from"), 10, 64)
		to, _ = strconv.ParseInt(q.Get("to"), 10, 64)
	}
	switch {
	case days > 0:
		if days > report.MaxPeriodDays {
			return 0, 0, fmt.Sprintf("A report covers at most %d days.", report.MaxPeriodDays)
		}
		end = time.Now().Truncate(time.Minute).UnixMilli()
		return end - int64(days)*24*3600_000, end, ""
	case from > 0 && to > from:
		return from, to, ""
	}
	return 0, 0, "Choose the last 24 hours, 7 days or 30 days, or a date range."
}

type periodBody struct {
	Days int   `json:"days"`
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

func (s *Server) handleReportSummary(w http.ResponseWriter, r *http.Request) {
	if !s.reportsReady(w) {
		return
	}
	start, end, msg := reportPeriod(r, nil)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	d, err := s.deps.Reports.Summary(r.Context(), start, end)
	if err != nil {
		s.reportErr(w, "build a report", err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// handleMakeReport makes a report, keeps its PDF and returns its record.
func (s *Server) handleMakeReport(w http.ResponseWriter, r *http.Request) {
	if !s.reportsReady(w) {
		return
	}
	var req periodBody
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	start, end, msg := reportPeriod(r, &req)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
	run, _, err := s.deps.Reports.Generate(r.Context(), "Report", "manual", nil, start, end)
	if err != nil {
		s.reportErr(w, "make a report", err)
		return
	}
	s.audit(r, audit.Entry{Action: "report.create", Fields: map[string]string{"target": fmt.Sprint(run.ID)},
		Message: fmt.Sprintf("%s made a report covering %s to %s", auth.FromContext(r.Context()).Name, time.UnixMilli(start).Format("Jan 2"), time.UnixMilli(end).Format("Jan 2"))})
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) handleListReportRuns(w http.ResponseWriter, r *http.Request) {
	if !s.reportsReady(w) {
		return
	}
	runs, err := s.deps.Reports.Store().ReportRuns(r.Context(), storage.MaxReportRuns)
	if err != nil {
		s.reportErr(w, "list reports", err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.reportsReady(w) {
		return
	}
	run, err := s.deps.Reports.Store().GetReportRun(r.Context(), id)
	if err != nil {
		s.reportErr(w, "read a report", err)
		return
	}
	s.audit(r, audit.Entry{Action: "report.download", Fields: map[string]string{"target": fmt.Sprint(id)},
		Message: auth.FromContext(r.Context()).Name + " downloaded a report"})
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+report.FileName(run, time.Local)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(run.PDF)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(run.PDF)
}

func (s *Server) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.reportsReady(w) {
		return
	}
	if err := s.deps.Reports.Store().DeleteReportRun(r.Context(), id); err != nil {
		s.reportErr(w, "delete a report", err)
		return
	}
	s.audit(r, audit.Entry{Action: "report.delete", Severity: 2, Fields: map[string]string{"target": fmt.Sprint(id)},
		Message: auth.FromContext(r.Context()).Name + " deleted a report"})
	w.WriteHeader(http.StatusNoContent)
}

// --- Schedules ---

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	if !s.reportsReady(w) {
		return
	}
	list, err := s.deps.Reports.Store().ReportSchedules(r.Context())
	if err != nil {
		s.reportErr(w, "list report schedules", err)
		return
	}
	emailOn := s.deps.Email != nil && s.deps.Email.Configured(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"schedules": list, "email_ready": emailOn, "cover_days": report.CoverDays})
}

func (s *Server) handleSaveSchedule(create bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.reportsReady(w) {
			return
		}
		var id int64
		if !create {
			var ok bool
			if id, ok = pathID(w, r); !ok {
				return
			}
		}
		var req storage.ReportSchedule
		if !decodeJSON(w, r, &req, 8<<10) {
			return
		}
		req.ID = id
		sc, err := s.deps.Reports.Validate(req)
		if err != nil {
			s.reportErr(w, "save a report schedule", err)
			return
		}
		who := auth.FromContext(r.Context()).Name
		verb := "created"
		if create {
			if list, err := s.deps.Reports.Store().ReportSchedules(r.Context()); err == nil && len(list) >= 20 {
				writeError(w, http.StatusBadRequest, "There are already 20 schedules; delete one first.")
				return
			}
			sc.Enabled = true
			if sc.ID, err = s.deps.Reports.Store().CreateReportSchedule(r.Context(), sc, time.Now().UnixMilli()); err != nil {
				s.reportErr(w, "save a report schedule", err)
				return
			}
		} else {
			verb = "changed"
			if err := s.deps.Reports.Store().UpdateReportSchedule(r.Context(), sc); err != nil {
				s.reportErr(w, "save a report schedule", err)
				return
			}
		}
		s.audit(r, audit.Entry{Action: "report.schedule.save", Severity: 2, Fields: map[string]string{"target": sc.Name},
			Message: fmt.Sprintf("%s %s the report schedule %s (%s, covering %d days)", who, verb, sc.Name, sc.Frequency, sc.CoversDays)})
		out, _ := s.deps.Reports.Store().GetReportSchedule(r.Context(), sc.ID)
		status := http.StatusOK
		if create {
			status = http.StatusCreated
		}
		writeJSON(w, status, out)
	}
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.reportsReady(w) {
		return
	}
	name, err := s.deps.Reports.Store().DeleteReportSchedule(r.Context(), id)
	if err != nil {
		s.reportErr(w, "delete a report schedule", err)
		return
	}
	s.audit(r, audit.Entry{Action: "report.schedule.delete", Severity: 2, Fields: map[string]string{"target": name},
		Message: fmt.Sprintf("%s deleted the report schedule %s", auth.FromContext(r.Context()).Name, name)})
	w.WriteHeader(http.StatusNoContent)
}

// handleRunSchedule makes a schedule's report now (and emails it); it doesn't change when the schedule next runs.
func (s *Server) handleRunSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || !s.reportsReady(w) {
		return
	}
	sc, err := s.deps.Reports.Store().GetReportSchedule(r.Context(), id)
	if err != nil {
		s.reportErr(w, "read a report schedule", err)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(3 * time.Minute))
	run, err := s.deps.Reports.RunSchedule(r.Context(), sc, "manual")
	if err != nil {
		s.reportErr(w, "make a report", err)
		return
	}
	writeJSON(w, http.StatusCreated, run)
}
