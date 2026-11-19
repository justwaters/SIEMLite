package report

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"siemlite/pkg/email"
	"siemlite/pkg/storage"
)

type fakeMail struct {
	mu   sync.Mutex
	on   bool
	sent []email.Message
}

func (f *fakeMail) Configured(context.Context) bool { return f.on }
func (f *fakeMail) Send(_ context.Context, m email.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func newService(t *testing.T, mail Mailer) (*Service, *storage.Repository) {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "r.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	return New(repo, mail, nil, "v-test", nil), repo
}

func TestNextRun(t *testing.T) {
	loc := time.UTC
	at := func(s string) time.Time { v, _ := time.ParseInLocation("2006-01-02 15:04", s, loc); return v }
	for _, tc := range []struct {
		name string
		sc   storage.ReportSchedule
		from string
		want string
	}{
		{"daily, hour still to come", storage.ReportSchedule{Frequency: "daily", Hour: 8}, "2026-11-18 06:30", "2026-11-18 08:00"},
		{"daily, hour passed", storage.ReportSchedule{Frequency: "daily", Hour: 8}, "2026-11-18 08:00", "2026-11-19 08:00"},
		{"weekly, later this week", storage.ReportSchedule{Frequency: "weekly", Weekday: 5, Hour: 9}, "2026-11-18 12:00", "2026-11-20 09:00"}, // Wed -> Fri
		{"weekly, same day passed", storage.ReportSchedule{Frequency: "weekly", Weekday: 3, Hour: 9}, "2026-11-18 12:00", "2026-11-25 09:00"},
		{"weekly, same day to come", storage.ReportSchedule{Frequency: "weekly", Weekday: 3, Hour: 15}, "2026-11-18 12:00", "2026-11-18 15:00"},
		{"monthly, this month", storage.ReportSchedule{Frequency: "monthly", DayOfMonth: 25, Hour: 7}, "2026-11-18 12:00", "2026-11-25 07:00"},
		{"monthly, next month", storage.ReportSchedule{Frequency: "monthly", DayOfMonth: 5, Hour: 7}, "2026-11-18 12:00", "2026-12-05 07:00"},
		{"monthly, across the year end", storage.ReportSchedule{Frequency: "monthly", DayOfMonth: 5, Hour: 7}, "2026-12-18 12:00", "2027-01-05 07:00"},
	} {
		if got := NextRun(tc.sc, at(tc.from), loc); !got.Equal(at(tc.want)) {
			t.Errorf("%s: got %s, want %s", tc.name, got.Format("2006-01-02 15:04"), tc.want)
		}
	}
}

func TestValidateSchedule(t *testing.T) {
	s, _ := newService(t, nil)
	good := storage.ReportSchedule{Name: " Weekly ", Frequency: "weekly", Weekday: 1, Hour: 8, CoversDays: 7, Recipients: "a@example.com; B@example.com a@example.com"}
	got, err := s.Validate(good)
	if err != nil || got.Name != "Weekly" || got.Recipients != "a@example.com, B@example.com" || got.NextRun <= time.Now().UnixMilli() {
		t.Fatalf("Validate = %+v, %v", got, err)
	}
	for name, mod := range map[string]func(*storage.ReportSchedule){
		"no name":       func(x *storage.ReportSchedule) { x.Name = "" },
		"odd frequency": func(x *storage.ReportSchedule) { x.Frequency = "hourly" },
		"bad hour":      func(x *storage.ReportSchedule) { x.Hour = 24 },
		"bad weekday":   func(x *storage.ReportSchedule) { x.Weekday = 7 },
		"bad covers":    func(x *storage.ReportSchedule) { x.CoversDays = 3 },
		"bad address":   func(x *storage.ReportSchedule) { x.Recipients = "not an address" },
		"named address": func(x *storage.ReportSchedule) { x.Recipients = "Bob <b@example.com>" },
		"too many": func(x *storage.ReportSchedule) {
			x.Recipients = "a@e.com,b@e.com,c@e.com,d@e.com,e@e.com,f@e.com,g@e.com,h@e.com,i@e.com,j@e.com,k@e.com"
		},
		"bad day":   func(x *storage.ReportSchedule) { x.Frequency, x.DayOfMonth = "monthly", 31 },
		"long name": func(x *storage.ReportSchedule) { x.Name = strings.Repeat("x", 81) },
	} {
		bad := good
		mod(&bad)
		if _, err := s.Validate(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A due schedule is run once, its PDF is kept and emailed with the file attached, and it moves on.
func TestDueScheduleRunsAndEmails(t *testing.T) {
	ctx := context.Background()
	mail := &fakeMail{on: true}
	s, repo := newService(t, mail)
	now := time.Now()
	sc, err := s.Validate(storage.ReportSchedule{Name: "Weekly", Frequency: "daily", Hour: 8, CoversDays: 7, Recipients: "soc@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	sc.Enabled = true
	sc.NextRun = now.Add(-time.Minute).UnixMilli() // due
	id, err := repo.CreateReportSchedule(ctx, sc, now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	s.runDue(ctx)
	runs, _ := repo.ReportRuns(ctx, 10)
	if len(runs) != 1 || runs[0].Trigger != "schedule" || runs[0].Emailed != "soc@example.com" || runs[0].Size == 0 {
		t.Fatalf("runs = %+v", runs)
	}
	if len(mail.sent) != 1 || len(mail.sent[0].Attachments) != 1 || !strings.HasPrefix(string(mail.sent[0].Attachments[0].Data), "%PDF-") ||
		mail.sent[0].Attachments[0].ContentType != "application/pdf" || !strings.HasSuffix(mail.sent[0].Attachments[0].Name, ".pdf") {
		t.Fatalf("mail = %+v", mail.sent)
	}
	got, _ := repo.GetReportSchedule(ctx, id)
	if got.NextRun <= now.UnixMilli() || got.LastRun == 0 || !strings.Contains(got.LastStatus, "sent to soc@example.com") {
		t.Errorf("schedule after the run = %+v", got)
	}
	s.runDue(ctx) // not due any more
	if runs, _ := repo.ReportRuns(ctx, 10); len(runs) != 1 {
		t.Errorf("ran again: %d reports", len(runs))
	}
}

func TestReportIsKeptButNotSentWhenEmailIsOff(t *testing.T) {
	ctx := context.Background()
	mail := &fakeMail{on: false}
	s, repo := newService(t, mail)
	sc, _ := s.Validate(storage.ReportSchedule{Name: "W", Frequency: "weekly", Weekday: 1, Hour: 8, CoversDays: 1, Recipients: "soc@example.com"})
	id, _ := repo.CreateReportSchedule(ctx, sc, time.Now().UnixMilli())
	sc.ID = id
	run, err := s.RunSchedule(ctx, sc, "manual")
	if err != nil || len(mail.sent) != 0 || run.Emailed != "" || !strings.Contains(run.Note, "email isn't set up") {
		t.Fatalf("run = %+v, err = %v, sent = %d", run, err, len(mail.sent))
	}
	// Running one by hand doesn't move when it next runs.
	if got, _ := repo.GetReportSchedule(ctx, id); got.NextRun != sc.NextRun {
		t.Errorf("a manual run moved the schedule: %d -> %d", sc.NextRun, got.NextRun)
	}
	// No recipients: nothing to send, nothing to explain.
	sc2 := sc
	sc2.Recipients = ""
	run, _ = s.RunSchedule(ctx, sc2, "manual")
	if run.Emailed != "" || run.Note != "" {
		t.Errorf("a schedule with no recipients: %+v", run)
	}
}

func TestOnlyTheNewestReportsAreKept(t *testing.T) {
	ctx := context.Background()
	_, repo := newService(t, nil)
	for i := 0; i < storage.MaxReportRuns+5; i++ {
		if _, err := repo.AddReportRun(ctx, storage.ReportRun{Name: "r", Trigger: "manual", CreatedAt: int64(1000 + i), PeriodStart: 1, PeriodEnd: 2, PDF: []byte("%PDF-x")}); err != nil {
			t.Fatal(err)
		}
	}
	runs, _ := repo.ReportRuns(ctx, 1000)
	if len(runs) != storage.MaxReportRuns || runs[0].CreatedAt != int64(1000+storage.MaxReportRuns+4) {
		t.Errorf("kept %d, newest %d", len(runs), runs[0].CreatedAt)
	}
}
