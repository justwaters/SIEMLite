// Package aialerts is the AI Alerts integration: now and then it gives a
// model a summary of recent logs and the rules already in place, and the model
// proposes alert rules worth adding. A proposal changes nothing; a person
// reads why it was made and accepts it (it becomes an ordinary rule) or
// dismisses it. The model never raises, closes or edits an alert itself.
//
// It uses the model chosen on the AI Parsers card, local or in the cloud, and
// the cloud masking that goes with it.
package aialerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/ai"
	"siemlite/pkg/audit"
	"siemlite/pkg/integrations"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

const settingKey = "aialerts"

// Limits on what one run reads and keeps.
const (
	maxProposalsPerRun = 5
	maxPending         = 25
	minEvents          = 20 // fewer than this in the window isn't worth a model's time
	runTimeout         = 15 * time.Minute
)

// Choices offered for how often it runs and how far back it looks, in hours.
var (
	Intervals = []int{1, 6, 24}
	Lookbacks = []int{1, 6, 24, 168}
)

// Settings are what an admin chooses.
type Settings struct {
	Enabled       bool `json:"enabled"`
	IntervalHours int  `json:"interval_hours"` // how often it looks
	LookbackHours int  `json:"lookback_hours"` // how much of the logs each look covers
}

type stored struct {
	Settings
	LastRun     int64  `json:"last_run,omitempty"` // when the last look began, in milliseconds
	LastMessage string `json:"last_message,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

func (st *stored) defaults() {
	if st.IntervalHours == 0 {
		st.IntervalHours = 6
	}
	if st.LookbackHours == 0 {
		st.LookbackHours = 24
	}
}

// Model is the model AI Alerts asks: *ai.Service.
type Model interface {
	Ask(ctx context.Context, system, user string, schema any) (string, error)
	Info(ctx context.Context) (integrations.Info, error)
	Using(ctx context.Context) (string, bool)
}

// Service is the integration.
type Service struct {
	repo   *storage.Repository
	search *search.Engine
	model  Model
	audit  *audit.Logger
	log    *slog.Logger

	mu      sync.Mutex // guards the saved settings (read, change, write) and running
	running bool
	base    context.Context
}

// New returns the service. audit may be nil.
func New(repo *storage.Repository, eng *search.Engine, model Model, auditLog *audit.Logger, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{repo: repo, search: eng, model: model, audit: auditLog, log: log, base: context.Background()}
}

// ID, Name and Description are shown on its card.
func (s *Service) ID() string   { return "aialerts" }
func (s *Service) Name() string { return "AI Alerts" }
func (s *Service) Description() string {
	return "A model reads a summary of your recent logs now and then and proposes alert rules to add. You accept or dismiss each one; nothing changes until you do."
}

func (s *Service) load(ctx context.Context) (stored, error) {
	raw, err := s.repo.Setting(ctx, settingKey, "")
	if err != nil {
		return stored{}, err
	}
	var st stored
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return stored{}, fmt.Errorf("saved AI Alerts settings are damaged: %w", err)
		}
	}
	st.defaults()
	return st, nil
}

func (s *Service) save(ctx context.Context, st stored) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.repo.SetSetting(ctx, settingKey, string(b))
}

// update reads the settings, changes them and writes them back, one at a time.
func (s *Service) update(ctx context.Context, fn func(*stored)) (stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(ctx)
	if err != nil {
		return st, err
	}
	fn(&st)
	return st, s.save(ctx, st)
}

// Info reports the card's state.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	st, err := s.load(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	m, err := s.model.Info(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: m.Configured, Enabled: m.Configured && st.Enabled}
	if !m.Configured {
		info.Summary = "Needs a model: set one up under AI Parsers first."
		return info, nil
	}
	info.Summary = fmt.Sprintf("Looks at the last %s every %s with %s.", hoursText(st.LookbackHours), hoursText(st.IntervalHours), m.Summary)
	if n, _ := s.repo.CountPendingProposals(ctx); n > 0 && info.Enabled {
		info.Summary += fmt.Sprintf(" %d proposed %s waiting.", n, plural(n, "rule", "rules"))
	}
	return info, nil
}

// SetEnabled turns it on or off, keeping the settings.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	if on {
		m, err := s.model.Info(ctx)
		if err != nil {
			return err
		}
		if !m.Configured {
			return integrations.InputError("Set up a model under AI Parsers first; AI Alerts uses it.")
		}
	}
	_, err := s.update(ctx, func(st *stored) { st.Enabled = on })
	return err
}

// View is what the settings dialog shows.
type View struct {
	Settings
	Configured  bool   `json:"configured"` // a model is set up
	Model       string `json:"model,omitempty"`
	Cloud       bool   `json:"cloud"` // asking it sends data off this server
	Running     bool   `json:"running"`
	LastRun     int64  `json:"last_run,omitempty"`
	LastMessage string `json:"last_message,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	Pending     int    `json:"pending"`
	Intervals   []int  `json:"intervals"`
	Lookbacks   []int  `json:"lookbacks"`
}

// Get returns the settings and what the last look found.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	m, err := s.model.Info(ctx)
	if err != nil {
		return View{}, err
	}
	v := View{Settings: st.Settings, Configured: m.Configured, LastRun: st.LastRun, LastMessage: st.LastMessage, LastError: st.LastError,
		Intervals: Intervals, Lookbacks: Lookbacks}
	if m.Configured {
		v.Model, v.Cloud = s.model.Using(ctx)
	}
	s.mu.Lock()
	v.Running = s.running
	s.mu.Unlock()
	v.Pending, _ = s.repo.CountPendingProposals(ctx)
	return v, nil
}

func hasInt(list []int, n int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

// Save stores how often it looks and how far back. Whether it's on is the card's switch.
func (s *Service) Save(ctx context.Context, in Settings) error {
	if !hasInt(Intervals, in.IntervalHours) {
		return integrations.InputError("Choose how often AI Alerts looks: every hour, 6 hours or day.")
	}
	if !hasInt(Lookbacks, in.LookbackHours) {
		return integrations.InputError("Choose how far back each look goes: 1 hour, 6 hours, a day or a week.")
	}
	_, err := s.update(ctx, func(st *stored) { st.IntervalHours, st.LookbackHours = in.IntervalHours, in.LookbackHours })
	return err
}

// Run looks at the logs when it's time, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := s.load(ctx)
		if err != nil || !st.Enabled {
			continue
		}
		if st.LastRun != 0 && time.Since(time.UnixMilli(st.LastRun)) < time.Duration(st.IntervalHours)*time.Hour {
			continue
		}
		if m, err := s.model.Info(ctx); err != nil || !m.Configured {
			continue
		}
		if err := s.start(false); err != nil && !errors.Is(err, errBusy) {
			s.log.Warn("AI Alerts couldn't start a look", "err", err)
		}
	}
}

var errBusy = integrations.InputError("AI Alerts is already looking at the logs.")

// RunNow starts a look now, in the background. A look needs a model but not the switch.
func (s *Service) RunNow(ctx context.Context) error {
	m, err := s.model.Info(ctx)
	if err != nil {
		return err
	}
	if !m.Configured {
		return integrations.InputError("Set up a model under AI Parsers first; AI Alerts uses it.")
	}
	return s.start(true)
}

func (s *Service) start(manual bool) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errBusy
	}
	s.running = true
	base := s.base
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(base), runTimeout)
		defer cancel()
		s.look(ctx, manual)
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	return nil
}

// look is one pass: summarize the logs, ask, keep what holds up, and note the outcome.
func (s *Service) look(ctx context.Context, manual bool) {
	st, err := s.load(ctx)
	if err != nil {
		s.log.Warn("AI Alerts settings unreadable", "err", err)
		return
	}
	began := time.Now()
	out, err := s.propose(ctx, st.Settings)
	n, events, msg := out.Proposed, out.Events, out.Message
	notReady := errors.Is(err, ai.ErrNotReady)
	_, _ = s.update(ctx, func(c *stored) {
		if !notReady { // the local model is still downloading: look again next minute, not next interval
			c.LastRun = began.UnixMilli()
		}
		c.LastMessage, c.LastError = msg, ""
		if err != nil {
			c.LastMessage, c.LastError = "", errorText(err)
		}
	})
	if err != nil {
		s.log.Warn("AI Alerts look failed", "err", err)
	} else {
		s.log.Info("AI Alerts looked at the logs", "events", events, "proposed", n)
	}
	if s.audit != nil && !notReady {
		model, cloud := s.model.Using(ctx)
		e := audit.Entry{Action: "aialerts.run", Actor: "SIEMLite", Severity: 1,
			Fields: map[string]string{"model": model, "sent_off_server": fmt.Sprint(cloud), "events": fmt.Sprint(events), "proposed": fmt.Sprint(n),
				"started_by": map[bool]string{true: "a person", false: "the schedule"}[manual]}}
		switch {
		case err != nil:
			e.Severity, e.Message = 3, "AI Alerts couldn't finish a look at the logs: "+errorText(err)
		case out.TooFew:
			e.Message = "AI Alerts found too few events to look at, so the model wasn't asked"
		default:
			where := "with " + model
			if cloud {
				where += " (a summary of the logs left this server)"
			}
			e.Message = fmt.Sprintf("AI Alerts looked at %d events %s and proposed %d %s", events, where, n, plural(n, "rule", "rules"))
		}
		s.audit.Record(ctx, e)
	}
}

func errorText(err error) string {
	switch {
	case errors.Is(err, ai.ErrNotReady):
		return "The model isn't ready yet; it will be asked again shortly."
	case errors.Is(err, ai.ErrOff):
		return "No model is set up under AI Parsers."
	case errors.Is(err, context.DeadlineExceeded):
		return "The model took too long to answer."
	}
	return err.Error()
}

func hoursText(h int) string {
	switch {
	case h == 1:
		return "hour"
	case h == 24:
		return "day"
	case h == 168:
		return "week"
	}
	return fmt.Sprintf("%d hours", h)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ruleLine is how a rule is told to the model.
func ruleLine(r storage.Rule) string {
	var b strings.Builder
	b.WriteString("- " + r.Name)
	if r.Query != "" {
		b.WriteString(": " + r.Query)
	}
	if r.MinSeverity != nil && *r.MinSeverity > 0 {
		fmt.Fprintf(&b, " (severity %d and above)", *r.MinSeverity)
	}
	if r.ThreatOnly {
		b.WriteString(" (threat list matches)")
	}
	if r.IsVolume() {
		b.WriteString(" (volume of one source)")
	}
	return b.String()
}
