package secaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Settings keys the Service keeps in the database.
const (
	keyLast     = "secaudit.last"
	keyHistory  = "secaudit.history"
	keyAccepted = "secaudit.accepted"

	historyKept = 30
	maxNote     = 500
)

// Errors the API turns into replies.
var (
	ErrUnknown   = errors.New("there is no such check")
	ErrNoFix     = errors.New("this check has no automatic fix")
	ErrNoRun     = errors.New("run the audit first")
	ErrNotOpen   = errors.New("only a warning or failure can be accepted")
	ErrNoteEmpty = errors.New("say why the risk is acceptable")
)

// Store is where the Service keeps its state; *storage.Repository satisfies it.
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Acceptance records that an admin decided to live with a finding.
type Acceptance struct {
	By     string `json:"by"`
	At     int64  `json:"at"` // unix milliseconds
	Note   string `json:"note"`
	Status Status `json:"status"` // the status it was accepted at; a worse one reopens it
}

// Run is one audit of the installation.
type Run struct {
	At         int64    `json:"at"` // unix milliseconds
	By         string   `json:"by"`
	DurationMs int64    `json:"duration_ms"`
	Host       string   `json:"host,omitempty"`
	Version    string   `json:"version,omitempty"`
	Counts     Counts   `json:"counts"`
	Results    []Result `json:"results"`
}

// Summary is a past run without its results.
type Summary struct {
	At         int64  `json:"at"`
	By         string `json:"by"`
	Counts     Counts `json:"counts"`
	DurationMs int64  `json:"duration_ms"`
}

// State is everything the page shows.
type State struct {
	Last    *Run      `json:"last"`
	History []Summary `json:"history"`
}

// Service runs audits and keeps their results.
type Service struct {
	store Store
	host  string
	mu    sync.Mutex // one change to the saved state at a time
}

// New returns a Service. host names the machine in reports.
func New(store Store, host string) *Service { return &Service{store: store, host: host} }

func (s *Service) load(ctx context.Context, key string, into any) error {
	raw, err := s.store.Setting(ctx, key, "")
	if err != nil || raw == "" {
		return err
	}
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	return nil
}

func (s *Service) save(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, key, string(b))
}

func (s *Service) accepted(ctx context.Context) (map[string]Acceptance, error) {
	m := map[string]Acceptance{}
	return m, s.load(ctx, keyAccepted, &m)
}

// apply attaches acceptances to the results and totals them. An acceptance
// only holds while the finding is no worse than when it was accepted.
func apply(r *Run, acc map[string]Acceptance) {
	for i := range r.Results {
		res := &r.Results[i]
		res.Accepted = nil
		if a, ok := acc[res.ID]; ok && res.Status.Open() && res.Status.rank() <= a.Status.rank() {
			res.Accepted = &a
		}
	}
	r.Counts = count(r.Results)
}

// State returns the last run and the history.
func (s *Service) State(ctx context.Context) (State, error) {
	var st State
	var last Run
	if err := s.load(ctx, keyLast, &last); err != nil {
		return st, err
	}
	if last.At != 0 {
		acc, err := s.accepted(ctx)
		if err != nil {
			return st, err
		}
		apply(&last, acc)
		st.Last = &last
	}
	if err := s.load(ctx, keyHistory, &st.History); err != nil {
		return st, err
	}
	if st.History == nil {
		st.History = []Summary{}
	}
	return st, nil
}

// Run audits everything and saves the result as the new last run.
func (s *Service) Run(ctx context.Context, e *Env, by string) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev Run
	if err := s.load(ctx, keyLast, &prev); err != nil {
		return nil, err
	}
	start := time.Now()
	results := RunAll(ctx, e)
	sortResults(results)
	if prev.At != 0 {
		annotate(results, prev.Results)
	}
	run := &Run{At: start.UnixMilli(), By: by, Host: s.host, Version: e.Cfg.Version, Results: results,
		DurationMs: time.Since(start).Milliseconds()}
	acc, err := s.accepted(ctx)
	if err != nil {
		return nil, err
	}
	apply(run, acc)
	if err := s.save(ctx, keyLast, run); err != nil {
		return nil, err
	}
	var hist []Summary
	if err := s.load(ctx, keyHistory, &hist); err != nil {
		return nil, err
	}
	hist = append(hist, Summary{At: run.At, By: by, Counts: run.Counts, DurationMs: run.DurationMs})
	if len(hist) > historyKept {
		hist = hist[len(hist)-historyKept:]
	}
	return run, s.save(ctx, keyHistory, hist)
}

// Recheck runs one check again and replaces its result in the last run, so a
// fix can be verified without auditing everything. It returns the run and the
// new result.
func (s *Service) Recheck(ctx context.Context, e *Env, id string) (*Run, Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := Find(id)
	if !ok {
		return nil, Result{}, ErrUnknown
	}
	var run Run
	if err := s.load(ctx, keyLast, &run); err != nil {
		return nil, Result{}, err
	}
	if run.At == 0 {
		return nil, Result{}, ErrNoRun
	}
	res := RunCheck(ctx, e, c)
	replaced := false
	for i, old := range run.Results {
		if old.ID == id {
			one := []Result{res}
			annotate(one, []Result{old})
			res = one[0]
			if res.Change == "" && old.Status == res.Status {
				res.Change = old.Change // unchanged by this recheck: keep what the last run said
			}
			run.Results[i], replaced = res, true
		}
	}
	if !replaced {
		run.Results = append(run.Results, res)
		sortResults(run.Results)
	}
	acc, err := s.accepted(ctx)
	if err != nil {
		return nil, Result{}, err
	}
	apply(&run, acc)
	if err := s.save(ctx, keyLast, run); err != nil {
		return nil, Result{}, err
	}
	for _, r := range run.Results {
		if r.ID == id {
			res = r
		}
	}
	return &run, res, nil
}

// Apply makes a check's automatic fix, then rechecks it.
func (s *Service) Apply(ctx context.Context, e *Env, id string) (message string, run *Run, res Result, err error) {
	c, ok := Find(id)
	switch {
	case !ok:
		return "", nil, Result{}, ErrUnknown
	case c.Apply == nil:
		return "", nil, Result{}, ErrNoFix
	}
	if message, err = c.Apply(ctx, e); err != nil {
		return "", nil, Result{}, err
	}
	run, res, err = s.Recheck(ctx, e, id)
	return message, run, res, err
}

// Accept records that the risk of a warning or failure is accepted.
func (s *Service) Accept(ctx context.Context, id, by, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	note = strings.TrimSpace(note)
	switch {
	case note == "":
		return ErrNoteEmpty
	case len(note) > maxNote:
		note = note[:maxNote]
	}
	var run Run
	if err := s.load(ctx, keyLast, &run); err != nil {
		return err
	}
	var status Status
	for _, r := range run.Results {
		if r.ID == id {
			status = r.Status
		}
	}
	if _, ok := Find(id); !ok {
		return ErrUnknown
	}
	if !status.Open() {
		return ErrNotOpen
	}
	acc, err := s.accepted(ctx)
	if err != nil {
		return err
	}
	acc[id] = Acceptance{By: by, At: time.Now().UnixMilli(), Note: note, Status: status}
	return s.save(ctx, keyAccepted, acc)
}

// Unaccept takes an acceptance back.
func (s *Service) Unaccept(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, err := s.accepted(ctx)
	if err != nil {
		return err
	}
	delete(acc, id)
	return s.save(ctx, keyAccepted, acc)
}

// Markdown writes the run as a report.
func (r *Run) Markdown() string {
	var b strings.Builder
	when := time.UnixMilli(r.At).UTC().Format("2006-01-02 15:04 UTC")
	fmt.Fprintf(&b, "# SIEMLite security audit\n\n")
	fmt.Fprintf(&b, "- Host: %s\n- SIEMLite: %s\n- Run: %s by %s\n", orDash(r.Host), orDash(r.Version), when, orDash(r.By))
	fmt.Fprintf(&b, "- Result: %d failed, %d warnings, %d passed, %d skipped, %d accepted risks\n",
		r.Counts.Fail, r.Counts.Warn, r.Counts.Pass, r.Counts.Skip, r.Counts.Accepted)
	for _, cat := range Categories {
		var rows []Result
		for _, res := range r.Results {
			if res.Category == cat {
				rows = append(rows, res)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n", cat)
		for _, res := range rows {
			state := strings.ToUpper(string(res.Status))
			if res.Accepted != nil {
				state += ", ACCEPTED"
			}
			fmt.Fprintf(&b, "\n### [%s] %s\n\n", state, res.Title)
			if res.Status.Open() {
				fmt.Fprintf(&b, "Severity: %s\n\n", res.Severity)
			}
			fmt.Fprintf(&b, "%s\n", res.Detail)
			if res.Fix != "" {
				fmt.Fprintf(&b, "\n**To fix:** %s\n", res.Fix)
			}
			if a := res.Accepted; a != nil {
				fmt.Fprintf(&b, "\n**Risk accepted** by %s on %s: %s\n", a.By, time.UnixMilli(a.At).UTC().Format("2006-01-02"), a.Note)
			}
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
