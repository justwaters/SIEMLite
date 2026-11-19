package report

import (
	"context"
	"fmt"
	"log/slog"
	netmail "net/mail"
	"os"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/email"
	"siemlite/pkg/storage"
)

// Choices for what a scheduled report covers, in days.
var CoverDays = []int{1, 7, 30}

// Limits.
const (
	MaxRecipients = 10
	MaxPeriodDays = 366
)

// Store is the storage the service needs (storage.Repository).
type Store interface {
	Source
	CreateReportSchedule(ctx context.Context, s storage.ReportSchedule, nowMs int64) (int64, error)
	UpdateReportSchedule(ctx context.Context, s storage.ReportSchedule) error
	DeleteReportSchedule(ctx context.Context, id int64) (string, error)
	GetReportSchedule(ctx context.Context, id int64) (storage.ReportSchedule, error)
	ReportSchedules(ctx context.Context) ([]storage.ReportSchedule, error)
	DueReportSchedules(ctx context.Context, nowMs int64) ([]storage.ReportSchedule, error)
	MarkReportScheduleRan(ctx context.Context, id, ranMs, nextMs int64, status string) error
	AddReportRun(ctx context.Context, run storage.ReportRun) (int64, error)
	SetReportRunDelivery(ctx context.Context, id int64, emailed, note string) error
	ReportRuns(ctx context.Context, limit int) ([]storage.ReportRun, error)
	GetReportRun(ctx context.Context, id int64) (storage.ReportRun, error)
	DeleteReportRun(ctx context.Context, id int64) error
}

// Mailer sends the email a scheduled report goes out in (email.Service).
type Mailer interface {
	Send(ctx context.Context, m email.Message) error
	Configured(ctx context.Context) bool
}

// Service makes reports, keeps them, and runs the schedules.
type Service struct {
	store   Store
	mail    Mailer
	audit   *audit.Logger
	log     *slog.Logger
	version string
	// Feeds names the threat feeds in use (optional).
	Feeds func(ctx context.Context) []string
	now   func() time.Time
	loc   *time.Location
	host  string

	mu sync.Mutex // one report at a time
}

// New returns a Service. mail and auditLog may be nil.
func New(store Store, mail Mailer, auditLog *audit.Logger, version string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	host, _ := os.Hostname()
	return &Service{store: store, mail: mail, audit: auditLog, log: log, version: version, now: time.Now, loc: time.Local, host: host}
}

// Summary builds a report's data without keeping it, for the page.
func (s *Service) Summary(ctx context.Context, start, end int64) (*Data, error) {
	if err := checkPeriod(start, end); err != nil {
		return nil, err
	}
	var feeds []string
	if s.Feeds != nil {
		feeds = s.Feeds(ctx)
	}
	return Build(ctx, s.store, start, end, s.version, s.host, feeds, s.now())
}

func checkPeriod(start, end int64) error {
	switch {
	case end <= start:
		return email.InputError("The report has to end after it starts.")
	case end-start > int64(MaxPeriodDays)*24*3600_000:
		return email.InputError(fmt.Sprintf("A report covers at most %d days.", MaxPeriodDays))
	}
	return nil
}

// Generate makes a report, keeps its PDF and returns the record.
func (s *Service) Generate(ctx context.Context, name, trigger string, scheduleID *int64, start, end int64) (storage.ReportRun, *Data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.Summary(ctx, start, end)
	if err != nil {
		return storage.ReportRun{}, nil, err
	}
	pdf, err := d.PDF()
	if err != nil {
		return storage.ReportRun{}, nil, fmt.Errorf("draw the report: %w", err)
	}
	run := storage.ReportRun{ScheduleID: scheduleID, Name: name, Trigger: trigger, CreatedAt: s.now().UnixMilli(), PeriodStart: start, PeriodEnd: end, PDF: pdf}
	id, err := s.store.AddReportRun(ctx, run)
	if err != nil {
		return run, d, err
	}
	run.ID, run.Size = id, int64(len(pdf))
	return run, d, nil
}

// FileName is a download name for a report: "siemlite-report-2026-11-18.pdf".
func FileName(run storage.ReportRun, loc *time.Location) string {
	if loc == nil {
		loc = time.Local
	}
	return "siemlite-report-" + time.UnixMilli(run.PeriodEnd-1).In(loc).Format("2006-01-02") + ".pdf"
}

// Recipients splits and checks a list of addresses (commas or spaces between them).
func Recipients(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
		a, err := netmail.ParseAddress(t)
		if err != nil || a.Name != "" {
			return nil, email.InputError(fmt.Sprintf("%q isn't a valid email address.", t))
		}
		if k := strings.ToLower(a.Address); !seen[k] {
			seen[k] = true
			out = append(out, a.Address)
		}
	}
	if len(out) > MaxRecipients {
		return nil, email.InputError(fmt.Sprintf("Send to at most %d addresses.", MaxRecipients))
	}
	return out, nil
}

// Validate checks a schedule's settings and fills in when it next runs.
func (s *Service) Validate(in storage.ReportSchedule) (storage.ReportSchedule, error) {
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "" || len([]rune(in.Name)) > 80:
		return in, email.InputError("Give the schedule a name of up to 80 characters.")
	case in.Frequency != "daily" && in.Frequency != "weekly" && in.Frequency != "monthly":
		return in, email.InputError("Choose daily, weekly or monthly.")
	case in.Hour < 0 || in.Hour > 23:
		return in, email.InputError("The hour must be from 0 to 23.")
	case in.Frequency == "weekly" && (in.Weekday < 0 || in.Weekday > 6):
		return in, email.InputError("Choose a day of the week.")
	case in.Frequency == "monthly" && (in.DayOfMonth < 1 || in.DayOfMonth > 28):
		return in, email.InputError("Choose a day of the month from 1 to 28.")
	}
	ok := false
	for _, d := range CoverDays {
		ok = ok || d == in.CoversDays
	}
	if !ok {
		return in, email.InputError("A report covers the last day, 7 days or 30 days.")
	}
	rcpts, err := Recipients(in.Recipients)
	if err != nil {
		return in, err
	}
	in.Recipients = strings.Join(rcpts, ", ")
	in.NextRun = NextRun(in, s.now(), s.loc).UnixMilli()
	return in, nil
}

// NextRun is the first time after t that the schedule is due, in loc.
func NextRun(sc storage.ReportSchedule, t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	at := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, sc.Hour, 0, 0, 0, loc) }
	switch sc.Frequency {
	case "weekly":
		c := at(t.Year(), t.Month(), t.Day())
		c = c.AddDate(0, 0, (sc.Weekday-int(c.Weekday())+7)%7)
		if !c.After(t) {
			c = c.AddDate(0, 0, 7)
		}
		return c
	case "monthly":
		c := at(t.Year(), t.Month(), sc.DayOfMonth)
		if !c.After(t) {
			c = at(t.Year(), t.Month()+1, sc.DayOfMonth)
		}
		return c
	}
	c := at(t.Year(), t.Month(), t.Day())
	if !c.After(t) {
		c = c.AddDate(0, 0, 1)
	}
	return c
}

// RunSchedule makes a schedule's report for the period ending now, emails it, and sets the next run.
// trigger is "schedule" or "manual" (run now).
func (s *Service) RunSchedule(ctx context.Context, sc storage.ReportSchedule, trigger string) (storage.ReportRun, error) {
	now := s.now()
	end := now.Truncate(time.Minute).UnixMilli()
	start := end - int64(sc.CoversDays)*24*3600_000
	id := sc.ID
	run, d, err := s.Generate(ctx, sc.Name, trigger, &id, start, end)
	status := "Made " + now.In(s.loc).Format("Jan 2 15:04")
	if err != nil {
		status = "Failed: " + err.Error()
		s.log.Warn("scheduled report failed", "schedule", sc.Name, "err", err)
	} else {
		emailed, note := s.deliver(ctx, sc, run, d)
		if emailed != "" {
			status += ", sent to " + emailed
		} else if note != "" {
			status += "; " + note
		}
		_ = s.store.SetReportRunDelivery(ctx, run.ID, emailed, note)
		run.Emailed, run.Note = emailed, note
	}
	next := NextRun(sc, now, s.loc)
	if trigger == "manual" {
		next = time.UnixMilli(sc.NextRun) // running one now doesn't move the schedule
	}
	if merr := s.store.MarkReportScheduleRan(ctx, sc.ID, now.UnixMilli(), next.UnixMilli(), status); merr != nil && err == nil {
		err = merr
	}
	if s.audit != nil {
		sev, msg := 1, fmt.Sprintf("The report %s was made (%s)", sc.Name, trigger)
		if err != nil {
			sev, msg = 3, fmt.Sprintf("The report %s could not be made: %v", sc.Name, err)
		}
		s.audit.Record(ctx, audit.Entry{Action: "report.run", Actor: "SIEMLite", Severity: sev, Message: msg, Fields: map[string]string{"target": sc.Name, "result": status}})
	}
	return run, err
}

// deliver emails a report. It says who it went to, or why it didn't (note); neither is an error,
// because the report is made and kept either way.
func (s *Service) deliver(ctx context.Context, sc storage.ReportSchedule, run storage.ReportRun, d *Data) (emailed, note string) {
	rcpts, _ := Recipients(sc.Recipients)
	switch {
	case len(rcpts) == 0:
		return "", ""
	case s.mail == nil || !s.mail.Configured(ctx):
		return "", "not emailed: email isn't set up or is turned off"
	}
	msg := email.Message{To: rcpts, Subject: fmt.Sprintf("SIEMLite report: %s", sc.Name), Body: d.Text(),
		Attachments: []email.Attachment{{Name: FileName(run, s.loc), ContentType: "application/pdf", Data: run.PDF}}}
	if len(run.PDF) == 0 { // the run record from Generate has the PDF; fetch it if a caller dropped it
		if full, err := s.store.GetReportRun(ctx, run.ID); err == nil {
			msg.Attachments[0].Data = full.PDF
		}
	}
	if err := s.mail.Send(ctx, msg); err != nil {
		s.log.Warn("couldn't email the report", "schedule", sc.Name, "err", err)
		return "", "not emailed: " + err.Error()
	}
	return strings.Join(rcpts, ", "), ""
}

// Run checks the schedules every 30 seconds until ctx is done. A schedule that came due while
// SIEMLite was off runs once, at start.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		s.runDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) runDue(ctx context.Context) {
	due, err := s.store.DueReportSchedules(ctx, s.now().UnixMilli())
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("couldn't read the report schedules", "err", err)
		}
		return
	}
	for _, sc := range due {
		if ctx.Err() != nil {
			return
		}
		if _, err := s.RunSchedule(ctx, sc, "schedule"); err != nil && ctx.Err() == nil {
			s.log.Warn("scheduled report", "schedule", sc.Name, "err", err)
		}
	}
}

// Store gives the API the storage for listing and downloading.
func (s *Service) Store() Store { return s.store }

// ErrNotFound is storage's, re-exported for callers.
var ErrNotFound = storage.ErrReportNotFound
