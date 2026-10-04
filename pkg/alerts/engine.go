// Package alerts evaluates alert rules against newly stored events.
//
// Each check looks only at events stored since the last one (tracked by
// event id, so backfilled events with old timestamps still count). For each
// enabled rule it finds the groups (an IP, user or host) with new matching
// events; a group that already has an open or acknowledged alert gets it
// updated, otherwise the group's matches within the rule's window are
// counted and an alert opens when they reach the threshold.
package alerts

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"siemlite/pkg/storage"
)

const checkpointKey = "alert_checkpoint"

// Store is the storage the engine needs.
type Store interface {
	ListRules(ctx context.Context) ([]storage.Rule, error)
	MaxEventID(ctx context.Context) (int64, error)
	NewMatches(ctx context.Context, ru storage.Rule, afterID, maxID int64) ([]storage.RuleGroup, error)
	WindowCounts(ctx context.Context, ru storage.Rule, groups []storage.RuleGroup, window, maxID int64) (map[string]storage.WindowStat, error)
	ActiveAlertGroups(ctx context.Context, ruleID int64) (map[string]bool, error)
	RaiseAlert(ctx context.Context, ru storage.Rule, value string, newCount, windowCount, first, last int64, sample bool, nowMs int64) (bool, error)
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Engine checks rules. Check is safe to call concurrently; runs serialize.
type Engine struct {
	store Store
	log   *slog.Logger
	now   func() time.Time
	mu    sync.Mutex
}

// New returns an engine.
func New(store Store, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{store: store, log: log, now: time.Now}
}

// Result summarizes one check.
type Result struct {
	Opened  int
	Updated int
}

// Check evaluates every enabled rule against events stored since the last
// check.
func (e *Engine) Check(ctx context.Context) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var res Result
	cpStr, err := e.store.Setting(ctx, checkpointKey, "0")
	if err != nil {
		return res, err
	}
	cp, _ := strconv.ParseInt(cpStr, 10, 64)
	maxID, err := e.store.MaxEventID(ctx)
	if err != nil {
		return res, err
	}
	cp = min(cp, maxID) // events were deleted (retention, a restore)
	rules, err := e.store.ListRules(ctx)
	if err != nil {
		return res, err
	}
	now := e.now().UnixMilli()
	// Each rule keeps its own checkpoint, so a rule that fails (a broken
	// search, a database error) looks at the same events again next time
	// instead of skipping them, without holding the others back. A new rule
	// starts where the last check ended.
	for _, ru := range rules {
		key := checkpointKey + ":" + strconv.FormatInt(ru.ID, 10)
		from := cp
		if v, err := e.store.Setting(ctx, key, ""); err != nil {
			return res, err
		} else if v != "" {
			from, _ = strconv.ParseInt(v, 10, 64)
		}
		from = min(from, maxID)
		if ru.Enabled && from < maxID {
			if err := e.checkRule(ctx, ru, from, maxID, now, &res); err != nil {
				e.log.Warn("alert rule failed; it will look at these events again", "rule", ru.Name, "err", err)
				// Pin where it must start again (a new rule would otherwise
				// start from the overall checkpoint, which moves on).
				if err := e.store.SetSetting(ctx, key, strconv.FormatInt(from, 10)); err != nil {
					return res, err
				}
				continue
			}
		}
		// A switched-off rule moves along too, so switching it back on
		// doesn't raise alerts for everything that happened meanwhile.
		if err := e.store.SetSetting(ctx, key, strconv.FormatInt(maxID, 10)); err != nil {
			return res, err
		}
	}
	return res, e.store.SetSetting(ctx, checkpointKey, strconv.FormatInt(maxID, 10))
}

// checkRule runs one rule over the events with ids in (from, maxID].
func (e *Engine) checkRule(ctx context.Context, ru storage.Rule, from, maxID, now int64, res *Result) error {
	groups, err := e.store.NewMatches(ctx, ru, from, maxID)
	if err != nil {
		return err
	}
	window := int64(ru.WindowMinutes) * 60_000
	stats, err := e.store.WindowCounts(ctx, ru, groups, window, maxID)
	if err != nil {
		return err
	}
	active, err := e.store.ActiveAlertGroups(ctx, ru.ID)
	if err != nil {
		return err
	}
	for _, g := range groups {
		st := stats[g.Value]
		if st.Count == 0 || (!active[g.Value] && st.Count < int64(ru.Threshold)) {
			continue
		}
		opened, err := e.store.RaiseAlert(ctx, ru, g.Value, g.New, st.Count, st.First, st.Last, st.Sample, now)
		if err != nil {
			return err
		}
		if opened {
			res.Opened++
			e.log.Info("alert opened", "rule", ru.Name, "group", g.Value, "events", st.Count)
		} else {
			res.Updated++
		}
	}
	return nil
}

// Run checks every interval until ctx is done.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := e.Check(ctx); err != nil && ctx.Err() == nil {
			e.log.Error("alert check failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
