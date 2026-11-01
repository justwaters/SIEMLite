// Package secaudit audits the SIEMLite installation and the server it runs
// on: file permissions, listeners, certificates, accounts, backups, and (on
// Linux) SSH, the firewall, local accounts and kernel settings.
//
// A run is repeatable and read-only. Each check reports pass, warn, fail or
// skip with what it found and how to fix it, and the Service keeps the last
// run, a short history and any risks an admin has accepted, so a finding can
// be fixed and then rechecked until it passes. The only changes SIEMLite makes
// itself are tightening the permissions of its own files; everything on the
// host (SSH, firewall, accounts) is advice, never an edit.
package secaudit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Status is the outcome of one check.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	// Skip means the check couldn't run here (another OS, a container, no
	// permission to look); Detail says why. A skip is not a pass.
	Skip Status = "skip"
)

// rank orders statuses by how much attention they need.
func (s Status) rank() int {
	switch s {
	case Fail:
		return 3
	case Warn:
		return 2
	case Skip:
		return 1
	}
	return 0
}

// Open reports whether the status is a finding to act on.
func (s Status) Open() bool { return s == Warn || s == Fail }

// Severity is how much a finding matters when its check doesn't pass.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Categories group the checks on the page, in this order.
const (
	CatSIEMLite = "SIEMLite"
	CatNetwork  = "Network"
	CatAccess   = "Access"
	CatHost     = "Host"
)

// Categories lists the categories in display order.
var Categories = []string{CatSIEMLite, CatNetwork, CatAccess, CatHost}

// Outcome is what a check's Run returns.
type Outcome struct {
	Status Status
	// Detail says what was found, in a sentence or two.
	Detail string
	// Fix says what to do about it. Empty for a pass.
	Fix string
}

// Check is one audit. Run must only read; Apply, when set, makes the one
// safe change that resolves the finding.
type Check struct {
	ID       string
	Category string
	Title    string
	Severity Severity
	Run      func(ctx context.Context, e *Env) Outcome
	// Apply changes SIEMLite's own state to resolve the finding and says what
	// it did. ApplyLabel is the button text.
	Apply      func(ctx context.Context, e *Env) (string, error)
	ApplyLabel string
}

// Result is a check's outcome in a run.
type Result struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Status    Status   `json:"status"`
	Detail    string   `json:"detail"`
	Fix       string   `json:"fix,omitempty"`
	CanApply  bool     `json:"can_apply,omitempty"`
	ApplyText string   `json:"apply_label,omitempty"`
	// Change compares with the previous run: "new" (it passed or wasn't
	// there), "worse", or "resolved" (it was open and now passes).
	Change string `json:"change,omitempty"`
	// Accepted is set when an admin has accepted this risk (see Service).
	Accepted *Acceptance `json:"accepted,omitempty"`
}

// Open is whether the result still needs action: it is a warning or failure
// and nobody has accepted the risk.
func (r Result) Open() bool { return r.Status.Open() && r.Accepted == nil }

// Env is what the checks look at. Tests replace the pieces.
type Env struct {
	Root string // the file system's root; "/" outside tests
	GOOS string
	Euid int
	Now  func() time.Time
	// Exec runs a program with a fixed argument list (never a shell) and
	// returns its standard output.
	Exec func(ctx context.Context, name string, args ...string) (string, error)
	Cfg  Config
}

// NewEnv returns an Env for this machine.
func NewEnv(cfg Config) *Env {
	return &Env{Root: "/", GOOS: runtime.GOOS, Euid: os.Geteuid(), Now: time.Now, Exec: run, Cfg: cfg}
}

func (e *Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e *Env) read(p string) (string, error) {
	b, err := os.ReadFile(e.path(p))
	return string(b), err
}

func (e *Env) exists(p string) bool {
	_, err := os.Lstat(e.path(p))
	return err == nil
}

// inContainer reports whether SIEMLite runs in a container, where the host's
// SSH, firewall and accounts aren't visible.
func (e *Env) inContainer() bool {
	if e.exists("/.dockerenv") || e.exists("/run/.containerenv") {
		return true
	}
	cg, _ := e.read("/proc/1/cgroup")
	for _, w := range []string{"docker", "kubepods", "containerd", "libpod"} {
		if strings.Contains(cg, w) {
			return true
		}
	}
	return false
}

// hostSkip returns a Skip outcome when host checks can't apply here.
func (e *Env) hostSkip() (Outcome, bool) {
	if e.GOOS != "linux" {
		return Outcome{Status: Skip, Detail: "Host checks support Linux only; this server runs " + e.GOOS + "."}, true
	}
	if e.inContainer() {
		return Outcome{Status: Skip, Detail: "SIEMLite is running in a container, so the host's own settings can't be seen from here. " +
			"Run SIEMLite directly on the host to audit it, or audit the host with its own tools."}, true
	}
	return Outcome{}, false
}

const (
	execTimeout = 10 * time.Second
	execMaxOut  = 64 << 10
)

// run is the real Exec: a bounded, shell-free command with a minimal
// environment.
func run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out limited
	cmd.Stdout = &out
	err = cmd.Run()
	return out.String(), err
}

// limited keeps the first execMaxOut bytes written and discards the rest.
type limited struct{ b []byte }

func (l *limited) Write(p []byte) (int, error) {
	if room := execMaxOut - len(l.b); room > 0 {
		l.b = append(l.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (l *limited) String() string { return string(l.b) }

// Checks returns every check, in display order.
func Checks() []Check {
	var all []Check
	all = append(all, siemChecks()...)
	all = append(all, networkChecks()...)
	all = append(all, accessChecks()...)
	all = append(all, hostChecks()...)
	return all
}

// Find returns the check with the id.
func Find(id string) (Check, bool) {
	for _, c := range Checks() {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// RunCheck runs one check. A panic or timeout in a check becomes a Skip, so
// one broken check can't stop the audit.
func RunCheck(ctx context.Context, e *Env, c Check) (res Result) {
	res = Result{ID: c.ID, Category: c.Category, Title: c.Title, Severity: c.Severity,
		CanApply: c.Apply != nil, ApplyText: c.ApplyLabel}
	defer func() {
		if p := recover(); p != nil {
			res.Status, res.Detail, res.Fix = Skip, fmt.Sprintf("The check failed to run: %v", p), ""
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	o := c.Run(ctx, e)
	res.Status, res.Detail, res.Fix = o.Status, o.Detail, o.Fix
	if res.Status == Pass {
		res.Fix = ""
	}
	return res
}

// RunAll runs every check.
func RunAll(ctx context.Context, e *Env) []Result {
	checks := Checks()
	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		out = append(out, RunCheck(ctx, e, c))
	}
	return out
}

// annotate sets each result's Change against the previous results.
func annotate(results []Result, prev []Result) {
	if prev == nil {
		return
	}
	was := make(map[string]Status, len(prev))
	for _, p := range prev {
		was[p.ID] = p.Status
	}
	for i := range results {
		r := &results[i]
		old, seen := was[r.ID]
		switch {
		case r.Status.Open() && (!seen || !old.Open()):
			r.Change = "new"
		case r.Status.Open() && r.Status.rank() > old.rank():
			r.Change = "worse"
		case seen && old.Open() && r.Status == Pass:
			r.Change = "resolved"
		}
	}
}

// Counts totals a run's results.
type Counts struct {
	Pass     int `json:"pass"`
	Warn     int `json:"warn"`
	Fail     int `json:"fail"`
	Skip     int `json:"skip"`
	Accepted int `json:"accepted"` // warnings and failures whose risk is accepted (not counted in Warn or Fail)
}

func count(results []Result) Counts {
	var c Counts
	for _, r := range results {
		switch {
		case r.Status == Pass:
			c.Pass++
		case r.Status == Skip:
			c.Skip++
		case r.Accepted != nil:
			c.Accepted++
		case r.Status == Warn:
			c.Warn++
		case r.Status == Fail:
			c.Fail++
		}
	}
	return c
}

// sortResults puts results in category order, keeping check order within one.
func sortResults(results []Result) {
	slices.SortStableFunc(results, func(a, b Result) int {
		return slices.Index(Categories, a.Category) - slices.Index(Categories, b.Category)
	})
}
