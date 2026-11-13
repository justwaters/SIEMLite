// Package alerts evaluates alert rules against newly stored events.
//
// Each check looks only at events stored since the last one (tracked by
// arrival number, so backfilled events with old timestamps still count). For each
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

	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

const checkpointKey = "alert_checkpoint"

// Store is the storage the engine needs.
type Store interface {
	ListRules(ctx context.Context) ([]storage.Rule, error)
	MaxEventSeq(ctx context.Context) (int64, error)
	NewMatches(ctx context.Context, ru storage.Rule, afterSeq, maxSeq int64) ([]storage.RuleGroup, error)
	WindowCounts(ctx context.Context, ru storage.Rule, groups []storage.RuleGroup, afterSeq, window, maxSeq int64) (map[string]storage.WindowStat, error)
	ActiveAlertGroups(ctx context.Context, ruleID int64) (map[string]bool, error)
	RaiseAlerts(ctx context.Context, ru storage.Rule, raises []storage.AlertRaise, nowMs int64) ([]bool, error)
	CountSourceEvents(ctx context.Context, sourceID, from, to int64) (int64, error)
	ListSources(ctx context.Context) ([]storage.Source, error)
	CountRuleEvents(ctx context.Context, ru storage.Rule, groupValue string, startMs, endMs int64) (int64, error)
	AlertsOfRule(ctx context.Context, ruleID int64) ([]storage.Alert, error)
	SetAlertCount(ctx context.Context, id, count, nowMs int64) error
	SetAlertStatus(ctx context.Context, id int64, status, by string, nowMs int64) (*storage.Alert, error)
	RaiseVolumeAlert(ctx context.Context, ru storage.Rule, count, first, last, nowMs int64) (bool, error)
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Engine checks rules. Check is safe to call concurrently; runs serialize.
type Engine struct {
	store Store
	log   *slog.Logger
	now   func() time.Time
	mu    sync.Mutex
	// started is when this engine began: a "fewer than" rule can't tell a
	// quiet source from SIEMLite having been off, so it waits a whole window.
	started time.Time
}

// New returns an engine.
func New(store Store, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{store: store, log: log, now: time.Now, started: time.Now()}
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
	maxID, err := e.store.MaxEventSeq(ctx)
	if err != nil {
		return res, err
	}
	cp = min(cp, maxID) // a restore went back in time
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
		if ru.IsVolume() { // judged by the clock, not by new events: see checkVolume
			continue
		}
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
	e.checkVolume(ctx, rules, now, &res)
	return res, e.store.SetSetting(ctx, checkpointKey, strconv.FormatInt(maxID, 10))
}

// checkVolume runs the rules that watch how much a source sends: it counts the
// source's events in the last window and raises an alert when there are more
// than (or fewer than) the rule's number. It runs on every check, since
// silence is the absence of new events. A rule that fails is logged and tried
// again at the next check.
func (e *Engine) checkVolume(ctx context.Context, rules []storage.Rule, now int64, res *Result) {
	for _, ru := range rules {
		if !ru.IsVolume() || !ru.Enabled || ru.SourceID == nil { // a deleted source leaves nothing to watch
			continue
		}
		window := int64(ru.WindowMinutes) * 60_000
		under := ru.Kind == storage.RuleVolumeUnder
		// Judge "fewer than" only once the rule and SIEMLite have both been
		// there for a whole window, or a new rule (or a restart) would say the
		// source went quiet.
		if under && now-max(ru.UpdatedAt, e.started.UnixMilli()) < window {
			continue
		}
		n, err := e.store.CountSourceEvents(ctx, *ru.SourceID, now-window, now)
		if err != nil {
			e.log.Warn("alert rule failed", "rule", ru.Name, "err", err)
			continue
		}
		if (under && n >= int64(ru.Threshold)) || (!under && n <= int64(ru.Threshold)) {
			continue
		}
		opened, err := e.store.RaiseVolumeAlert(ctx, ru, n, now-window, now, now)
		if err != nil {
			e.log.Warn("alert rule failed", "rule", ru.Name, "err", err)
			continue
		}
		if opened {
			res.Opened++
			e.log.Info("alert opened", "rule", ru.Name, "events", n)
		} else {
			res.Updated++
		}
	}
}

// checkRule runs one rule over the events with arrival numbers in (from, maxID].
func (e *Engine) checkRule(ctx context.Context, ru storage.Rule, from, maxID, now int64, res *Result) error {
	ru, err := e.prepare(ctx, ru)
	if err != nil {
		return err
	}
	groups, err := e.store.NewMatches(ctx, ru, from, maxID)
	if err != nil {
		return err
	}
	window := int64(ru.WindowMinutes) * 60_000
	stats, err := e.store.WindowCounts(ctx, ru, groups, from, window, maxID)
	if err != nil {
		return err
	}
	active, err := e.store.ActiveAlertGroups(ctx, ru.ID)
	if err != nil {
		return err
	}
	// All of a rule's alerts for this range are raised in one step: if it fails,
	// none were counted and the same range can be checked again.
	var raises []storage.AlertRaise
	for _, g := range groups {
		st := stats[g.Value]
		if st.Count == 0 || (!active[g.Value] && st.Count < int64(ru.Threshold)) {
			continue
		}
		raises = append(raises, storage.AlertRaise{Value: g.Value, NewCount: g.New, WindowCount: st.Count,
			First: st.First, Last: max(st.Last, g.NewMax)})
	}
	if len(raises) == 0 {
		return nil
	}
	opened, err := e.store.RaiseAlerts(ctx, ru, raises, now)
	if err != nil {
		return err
	}
	for i, a := range raises {
		if opened[i] {
			res.Opened++
			e.log.Info("alert opened", "rule", ru.Name, "group", a.Value, "events", a.WindowCount)
		} else {
			res.Updated++
		}
	}
	return nil
}

// prepare reads the field terms out of a rule's search, as the search box does:
// "action=ingest.late" matches what the event is, not words in its text. The
// words left over are the full-text search.
func (e *Engine) prepare(ctx context.Context, ru storage.Rule) (storage.Rule, error) {
	words, conds, threat, err := search.ParseTerms(ctx, e.store, ru.Query, false, nil)
	if err != nil {
		return ru, err
	}
	ru.Query, ru.Conds, ru.ThreatOnly = words, conds, ru.ThreatOnly || threat
	return ru, nil
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
