package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// SettingKey holds the auto-update schedule; lastKey the result of the latest run.
const (
	SettingKey = "autoupdate"
	lastKey    = "autoupdate_last"
	// MaxTimes is how many times of day one schedule can have.
	MaxTimes = 4
)

// AutoSettings is when SIEMLite installs a new release by itself.
type AutoSettings struct {
	Enabled bool `json:"enabled"`
	// Days are the days it may update, 0 (Sunday) to 6 (Saturday). Empty means every day.
	Days []int `json:"days"`
	// Times are the times of day (server time, "15:04") at which it looks for a release.
	Times []string `json:"times"`
	// BackupFirst makes a backup before installing; if the backup fails nothing is installed.
	BackupFirst bool `json:"backup_first"`
}

// AutoLast is what the latest scheduled check did.
type AutoLast struct {
	At     int64  `json:"at"` // unix ms
	Result string `json:"result"`
	OK     bool   `json:"ok"`
}

// AutoState is the schedule with what the page shows beside it.
type AutoState struct {
	AutoSettings
	Next     int64     `json:"next,omitempty"` // unix ms of the next check, 0 when off
	Last     *AutoLast `json:"last,omitempty"`
	Timezone string    `json:"timezone"`
	// CanApply is false when this install can't update itself (its WhyNot says why).
	CanApply bool   `json:"can_apply"`
	WhyNot   string `json:"why_not,omitempty"`
}

// DefaultAuto is the schedule before anyone sets one: off, a quiet time at night, with a backup.
func DefaultAuto() AutoSettings {
	return AutoSettings{Times: []string{"03:00"}, BackupFirst: true}
}

// ValidateAuto checks a schedule and returns it tidied (times sorted and in HH:MM form, days sorted).
// A schedule that is turned on needs at least one time.
func ValidateAuto(in AutoSettings) (AutoSettings, error) {
	out := AutoSettings{Enabled: in.Enabled, BackupFirst: in.BackupFirst, Days: []int{}, Times: []string{}}
	seen := map[int]bool{}
	for _, d := range in.Days {
		if d < 0 || d > 6 {
			return out, errors.New("Days must be Sunday to Saturday.")
		}
		if !seen[d] {
			seen[d] = true
			out.Days = append(out.Days, d)
		}
	}
	sort.Ints(out.Days)
	if len(out.Days) == 7 {
		out.Days = []int{} // every day
	}
	if len(in.Times) > MaxTimes {
		return out, fmt.Errorf("Use at most %d times a day.", MaxTimes)
	}
	have := map[string]bool{}
	for _, raw := range in.Times {
		t, err := time.Parse("15:04", strings.TrimSpace(raw))
		if err != nil {
			return out, fmt.Errorf("%q isn't a time. Use hours and minutes, like 03:30.", raw)
		}
		s := t.Format("15:04")
		if !have[s] {
			have[s] = true
			out.Times = append(out.Times, s)
		}
	}
	sort.Strings(out.Times)
	if out.Enabled && len(out.Times) == 0 {
		return out, errors.New("Add at least one time to update at.")
	}
	return out, nil
}

// NextAuto is the first scheduled time after t, in loc; the zero time if the schedule has no times.
func NextAuto(set AutoSettings, t time.Time, loc *time.Location) time.Time {
	if len(set.Times) == 0 {
		return time.Time{}
	}
	if loc == nil {
		loc = time.Local
	}
	t = t.In(loc)
	allowed := func(d time.Weekday) bool {
		if len(set.Days) == 0 {
			return true
		}
		for _, x := range set.Days {
			if x == int(d) {
				return true
			}
		}
		return false
	}
	times := append([]string(nil), set.Times...)
	sort.Strings(times)
	for off := 0; off <= 8; off++ {
		day := time.Date(t.Year(), t.Month(), t.Day()+off, 12, 0, 0, 0, loc) // noon: safely inside the day
		if !allowed(day.Weekday()) {
			continue
		}
		for _, s := range times {
			p, err := time.Parse("15:04", s)
			if err != nil {
				continue
			}
			c := time.Date(day.Year(), day.Month(), day.Day(), p.Hour(), p.Minute(), 0, 0, loc)
			if c.After(t) {
				return c
			}
		}
	}
	return time.Time{}
}

// AutoStore is what the scheduler needs from the database.
type AutoStore interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Auto installs new releases on the schedule in its settings.
type Auto struct {
	Checker *Checker
	Store   AutoStore
	// Backup makes a backup and waits for it (nil: BackupFirst is ignored).
	Backup func(ctx context.Context) error
	// Restart restarts SIEMLite on the new version.
	Restart func()
	// Done is told about an installed update (for the audit log).
	Done func(from, to string)
	Log  *slog.Logger

	Now func() time.Time
	Loc *time.Location

	mu    sync.Mutex
	armed time.Time // the next scheduled check, kept between ticks
	armBy string    // the settings it was worked out from
}

// Settings returns the saved schedule (the default when none is saved).
func (a *Auto) Settings(ctx context.Context) AutoSettings {
	raw, err := a.Store.Setting(ctx, SettingKey, "")
	if err != nil || raw == "" {
		return DefaultAuto()
	}
	var s AutoSettings
	if json.Unmarshal([]byte(raw), &s) != nil {
		return DefaultAuto()
	}
	if v, err := ValidateAuto(s); err == nil {
		return v
	}
	s.Enabled = false // a saved schedule that no longer validates is not run
	return s
}

// Save stores a schedule; the checks are the ones in ValidateAuto.
func (a *Auto) Save(ctx context.Context, in AutoSettings) (AutoSettings, error) {
	v, err := ValidateAuto(in)
	if err != nil {
		return v, err
	}
	b, _ := json.Marshal(v)
	if err := a.Store.SetSetting(ctx, SettingKey, string(b)); err != nil {
		return v, err
	}
	return v, nil
}

func (a *Auto) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Auto) loc() *time.Location {
	if a.Loc != nil {
		return a.Loc
	}
	return time.Local
}

// State is the schedule, the next check and the last result.
func (a *Auto) State(ctx context.Context) AutoState {
	set := a.Settings(ctx)
	st := AutoState{AutoSettings: set, Timezone: a.now().In(a.loc()).Format("MST, UTC-07:00")}
	if set.Enabled {
		st.Next = NextAuto(set, a.now(), a.loc()).UnixMilli()
	}
	if raw, _ := a.Store.Setting(ctx, lastKey, ""); raw != "" {
		var l AutoLast
		if json.Unmarshal([]byte(raw), &l) == nil {
			st.Last = &l
		}
	}
	st.CanApply, st.WhyNot = a.Checker.canApply()
	return st
}

func (a *Auto) record(ctx context.Context, ok bool, result string) {
	b, _ := json.Marshal(AutoLast{At: a.now().UnixMilli(), Result: result, OK: ok})
	_ = a.Store.SetSetting(ctx, lastKey, string(b))
}

// Tick runs one step of the schedule at the current time: when a scheduled time has come
// it looks for a release and installs it. It reports whether it installed one (and asked for a restart).
func (a *Auto) Tick(ctx context.Context) bool {
	set := a.Settings(ctx)
	a.mu.Lock()
	if !set.Enabled {
		a.armed, a.armBy = time.Time{}, ""
		a.mu.Unlock()
		return false
	}
	now := a.now()
	key, _ := json.Marshal(set)
	if a.armed.IsZero() || a.armBy != string(key) {
		// First look, or the schedule was changed: count from now, so a time already past isn't run late.
		a.armed, a.armBy = NextAuto(set, now, a.loc()), string(key)
		a.mu.Unlock()
		return false
	}
	if now.Before(a.armed) {
		a.mu.Unlock()
		return false
	}
	a.armed = NextAuto(set, now, a.loc())
	a.mu.Unlock()
	return a.runOnce(ctx, set)
}

func (a *Auto) runOnce(ctx context.Context, set AutoSettings) bool {
	log := a.Log
	if log == nil {
		log = slog.Default()
	}
	st := a.Checker.Check(ctx, true)
	switch {
	case st.Error != "":
		a.record(ctx, false, st.Error)
		return false
	case !st.Available:
		a.record(ctx, true, "Checked: "+a.Checker.Current+" is the latest release.")
		return false
	}
	if ok, why := a.Checker.canApply(); !ok {
		a.record(ctx, false, st.Latest+" is available but can't be installed here: "+why)
		return false
	}
	if set.BackupFirst && a.Backup != nil {
		if err := a.Backup(ctx); err != nil {
			log.Warn("automatic update skipped: the backup before it failed", "err", err)
			a.record(ctx, false, "Not updated to "+st.Latest+": the backup made first failed ("+err.Error()+"). Will try again at the next time.")
			return false
		}
	}
	from := a.Checker.Current
	to, err := a.Checker.Apply(ctx)
	if err != nil {
		if errors.Is(err, ErrNotAvailable) {
			a.record(ctx, true, "Checked: "+from+" is the latest release.")
			return false
		}
		log.Warn("automatic update failed", "err", err)
		a.record(ctx, false, "Not updated to "+st.Latest+": "+err.Error())
		return false
	}
	log.Warn("automatic update installed", "from", from, "to", to)
	a.record(ctx, true, "Updated from "+from+" to "+to+"; restarting.")
	if a.Done != nil {
		a.Done(from, to)
	}
	if a.Restart != nil {
		go func() { time.Sleep(300 * time.Millisecond); a.Restart() }()
	}
	return true
}

// Run checks the schedule every 20 seconds until ctx is done.
func (a *Auto) Run(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		if a.Tick(ctx) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
