package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrReportNotFound is returned for an unknown schedule or report.
var ErrReportNotFound = errors.New("there is no such report")

// MaxReportRuns is how many made reports are kept; the oldest are removed beyond that.
const MaxReportRuns = 100

// ReportSchedule is a report that is made on a schedule and sent by email.
type ReportSchedule struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Frequency  string `json:"frequency"`    // daily, weekly or monthly
	Weekday    int    `json:"weekday"`      // 0 (Sunday) to 6, for weekly
	DayOfMonth int    `json:"day_of_month"` // 1 to 28, for monthly
	Hour       int    `json:"hour"`         // 0 to 23, server time
	CoversDays int    `json:"covers_days"`  // how far back each report looks
	Recipients string `json:"recipients"`   // comma-separated addresses
	Enabled    bool   `json:"enabled"`
	NextRun    int64  `json:"next_run"`
	LastRun    int64  `json:"last_run,omitempty"`
	LastStatus string `json:"last_status,omitempty"`
	CreatedAt  int64  `json:"created_at"`
}

// ReportRun is a report that was made. The PDF is only loaded by GetReportRun.
type ReportRun struct {
	ID          int64  `json:"id"`
	ScheduleID  *int64 `json:"schedule_id,omitempty"`
	Name        string `json:"name"`
	Trigger     string `json:"trigger"` // manual or schedule
	CreatedAt   int64  `json:"created_at"`
	PeriodStart int64  `json:"period_start"`
	PeriodEnd   int64  `json:"period_end"`
	Size        int64  `json:"size"`
	Emailed     string `json:"emailed,omitempty"` // who it was sent to
	Note        string `json:"note,omitempty"`    // why it wasn't, or what went wrong
	PDF         []byte `json:"-"`
}

const scheduleCols = `id, name, frequency, weekday, day_of_month, hour, covers_days, recipients, enabled, next_run, last_run, last_status, created_at`

func scanSchedule(sc interface{ Scan(...any) error }) (ReportSchedule, error) {
	var s ReportSchedule
	var en int
	var last sql.NullInt64
	err := sc.Scan(&s.ID, &s.Name, &s.Frequency, &s.Weekday, &s.DayOfMonth, &s.Hour, &s.CoversDays, &s.Recipients, &en, &s.NextRun, &last, &s.LastStatus, &s.CreatedAt)
	s.Enabled = en != 0
	s.LastRun = last.Int64
	return s, err
}

// CreateReportSchedule adds a schedule and returns its id.
func (r *Repository) CreateReportSchedule(ctx context.Context, s ReportSchedule, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx, `INSERT INTO report_schedules (name, frequency, weekday, day_of_month, hour, covers_days, recipients, enabled, next_run, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.Name, s.Frequency, s.Weekday, s.DayOfMonth, s.Hour, s.CoversDays, s.Recipients, boolInt(s.Enabled), s.NextRun, nowMs)
	if err != nil {
		return 0, fmt.Errorf("create report schedule: %w", err)
	}
	return res.LastInsertId()
}

// UpdateReportSchedule changes a schedule's settings (and when it next runs).
func (r *Repository) UpdateReportSchedule(ctx context.Context, s ReportSchedule) error {
	res, err := r.db.Write.ExecContext(ctx, `UPDATE report_schedules SET name = ?, frequency = ?, weekday = ?, day_of_month = ?, hour = ?, covers_days = ?,
		recipients = ?, enabled = ?, next_run = ? WHERE id = ?`, s.Name, s.Frequency, s.Weekday, s.DayOfMonth, s.Hour, s.CoversDays, s.Recipients, boolInt(s.Enabled), s.NextRun, s.ID)
	if err != nil {
		return fmt.Errorf("update report schedule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReportNotFound
	}
	return nil
}

// DeleteReportSchedule removes a schedule; the reports it made stay.
func (r *Repository) DeleteReportSchedule(ctx context.Context, id int64) (string, error) {
	var name string
	if err := r.db.Read.QueryRowContext(ctx, `SELECT name FROM report_schedules WHERE id = ?`, id).Scan(&name); err != nil {
		return "", ErrReportNotFound
	}
	if _, err := r.db.Write.ExecContext(ctx, `DELETE FROM report_schedules WHERE id = ?`, id); err != nil {
		return "", err
	}
	_, _ = r.db.Write.ExecContext(ctx, `UPDATE report_runs SET schedule_id = NULL WHERE schedule_id = ?`, id)
	return name, nil
}

// GetReportSchedule returns one schedule.
func (r *Repository) GetReportSchedule(ctx context.Context, id int64) (ReportSchedule, error) {
	s, err := scanSchedule(r.db.Read.QueryRowContext(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrReportNotFound
	}
	return s, err
}

// ReportSchedules returns every schedule, by name.
func (r *Repository) ReportSchedules(ctx context.Context) ([]ReportSchedule, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+scheduleCols+` FROM report_schedules ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, fmt.Errorf("list report schedules: %w", err)
	}
	defer rows.Close()
	out := []ReportSchedule{}
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DueReportSchedules returns the enabled schedules whose time has come.
func (r *Repository) DueReportSchedules(ctx context.Context, nowMs int64) ([]ReportSchedule, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+scheduleCols+` FROM report_schedules WHERE enabled = 1 AND next_run <= ? ORDER BY next_run`, nowMs)
	if err != nil {
		return nil, fmt.Errorf("due report schedules: %w", err)
	}
	defer rows.Close()
	var out []ReportSchedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// MarkReportScheduleRan records a run of a schedule and when it runs next.
func (r *Repository) MarkReportScheduleRan(ctx context.Context, id, ranMs, nextMs int64, status string) error {
	_, err := r.db.Write.ExecContext(ctx, `UPDATE report_schedules SET last_run = ?, next_run = ?, last_status = ? WHERE id = ?`, ranMs, nextMs, status, id)
	return err
}

// AddReportRun keeps a made report and removes the oldest beyond MaxReportRuns.
func (r *Repository) AddReportRun(ctx context.Context, run ReportRun) (int64, error) {
	var sid any
	if run.ScheduleID != nil {
		sid = *run.ScheduleID
	}
	res, err := r.db.Write.ExecContext(ctx, `INSERT INTO report_runs (schedule_id, name, trigger, created_at, period_start, period_end, size, emailed, note, pdf)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, sid, run.Name, run.Trigger, run.CreatedAt, run.PeriodStart, run.PeriodEnd, len(run.PDF), run.Emailed, run.Note, run.PDF)
	if err != nil {
		return 0, fmt.Errorf("keep report: %w", err)
	}
	id, _ := res.LastInsertId()
	_, _ = r.db.Write.ExecContext(ctx, `DELETE FROM report_runs WHERE id NOT IN (SELECT id FROM report_runs ORDER BY created_at DESC, id DESC LIMIT ?)`, MaxReportRuns)
	return id, nil
}

// SetReportRunDelivery records who a report was emailed to, or why it wasn't.
func (r *Repository) SetReportRunDelivery(ctx context.Context, id int64, emailed, note string) error {
	_, err := r.db.Write.ExecContext(ctx, `UPDATE report_runs SET emailed = ?, note = ? WHERE id = ?`, emailed, note, id)
	return err
}

// ReportRuns lists the reports made, newest first, without their PDFs.
func (r *Repository) ReportRuns(ctx context.Context, limit int) ([]ReportRun, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, schedule_id, name, trigger, created_at, period_start, period_end, size, emailed, note
		FROM report_runs ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()
	out := []ReportRun{}
	for rows.Next() {
		var x ReportRun
		var sid sql.NullInt64
		if err := rows.Scan(&x.ID, &sid, &x.Name, &x.Trigger, &x.CreatedAt, &x.PeriodStart, &x.PeriodEnd, &x.Size, &x.Emailed, &x.Note); err != nil {
			return nil, err
		}
		if sid.Valid {
			x.ScheduleID = &sid.Int64
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetReportRun returns a made report with its PDF.
func (r *Repository) GetReportRun(ctx context.Context, id int64) (ReportRun, error) {
	var x ReportRun
	var sid sql.NullInt64
	err := r.db.Read.QueryRowContext(ctx, `SELECT id, schedule_id, name, trigger, created_at, period_start, period_end, size, emailed, note, pdf
		FROM report_runs WHERE id = ?`, id).Scan(&x.ID, &sid, &x.Name, &x.Trigger, &x.CreatedAt, &x.PeriodStart, &x.PeriodEnd, &x.Size, &x.Emailed, &x.Note, &x.PDF)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrReportNotFound
	}
	if sid.Valid {
		x.ScheduleID = &sid.Int64
	}
	return x, err
}

// DeleteReportRun removes a made report.
func (r *Repository) DeleteReportRun(ctx context.Context, id int64) error {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM report_runs WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrReportNotFound
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
