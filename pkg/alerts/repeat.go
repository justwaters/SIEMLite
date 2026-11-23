package alerts

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"siemlite/pkg/storage"
)

var severityName = map[int]string{0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal", 99: "Other"}

// repeatPart is one thing a repeat rule counts per user: the events with one keyword (or any, for
// repeat_severity), split by severity when the rule asks for it.
type repeatPart struct {
	keyword string
	sub     storage.Rule
}

// repeatParts expands a repeat rule into the rules the engine counts with: a match rule per keyword
// (the keyword as a phrase search) that groups by user, ignoring events with no user, and splits by
// exact severity for repeat_severity and repeat_both. A repeat_severity rule is one part with the
// rule's own search (field terms read out, as for any rule).
func (e *Engine) repeatParts(ctx context.Context, ru storage.Rule) ([]repeatPart, error) {
	base := ru
	base.Kind, base.GroupBy, base.NeedGroup = storage.RuleMatch, "user", true
	base.BySeverity = ru.Kind != storage.RuleRepeatKeyword
	if ru.Kind == storage.RuleRepeatSeverity {
		p, err := e.prepare(ctx, base)
		if err != nil {
			return nil, err
		}
		return []repeatPart{{sub: p}}, nil
	}
	var parts []repeatPart
	for _, k := range storage.RepeatKeywords(ru.Query) {
		sub := base
		sub.Query, sub.Conds = storage.KeywordPhrase(k), nil
		parts = append(parts, repeatPart{keyword: k, sub: sub})
	}
	return parts, nil
}

// repeatHit is a user's biggest pile of same-keyword or same-severity events in a window.
type repeatHit struct {
	user, keyword string
	level         int
	hasLevel      bool
	stat          storage.WindowStat
	newCount      int64
}

// checkRepeat runs a repeat rule over the events with arrival numbers in (from, maxID]. For each
// keyword (and severity) it counts the user's events in the window the way a match rule does, through
// NewMatches and WindowCounts, and a user whose count for any one of them reaches the threshold has
// one alert for the rule, which says which keyword or level it was.
func (e *Engine) checkRepeat(ctx context.Context, ru storage.Rule, from, maxID, now int64, res *Result) error {
	parts, err := e.repeatParts(ctx, ru)
	if err != nil {
		return err
	}
	window := int64(ru.WindowMinutes) * 60_000
	best := map[string]repeatHit{}
	for _, p := range parts {
		groups, err := e.store.NewMatches(ctx, p.sub, from, maxID)
		if err != nil {
			return err
		}
		stats, err := e.store.WindowCounts(ctx, p.sub, groups, from, window, maxID)
		if err != nil {
			return err
		}
		for _, g := range groups {
			st := stats[g.Value]
			if st.Count < int64(ru.Threshold) {
				continue
			}
			h := repeatHit{user: g.Value, keyword: p.keyword, stat: st, newCount: g.New}
			if p.sub.BySeverity {
				i := strings.LastIndex(g.Value, storage.GroupSep)
				if i < 0 {
					continue
				}
				lvl, err := strconv.Atoi(g.Value[i+len(storage.GroupSep):])
				if err != nil {
					continue
				}
				h.user, h.level, h.hasLevel = g.Value[:i], lvl, true
			}
			if h.user == "" {
				continue
			}
			if cur, ok := best[h.user]; !ok || st.Count > cur.stat.Count {
				best[h.user] = h
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	users := make([]string, 0, len(best))
	for u := range best {
		users = append(users, u)
	}
	// A stable order, so the alerts open in the same order every time.
	slices.Sort(users)
	ru.GroupBy = "user"
	raises := make([]storage.AlertRaise, len(users))
	for i, u := range users {
		h := best[u]
		raises[i] = storage.AlertRaise{Value: u, NewCount: h.newCount, WindowCount: h.stat.Count, First: h.stat.First, Last: h.stat.Last}
	}
	opened, err := e.store.RaiseAlerts(ctx, ru, raises, now)
	if err != nil {
		return err
	}
	for i, u := range users {
		if opened[i] {
			h := best[u]
			res.Opened++
			e.log.Info("alert opened", "rule", ru.Name, "group", u, "events", h.stat.Count)
			e.opened(ctx, Opened{Rule: ru, Group: u, Count: h.stat.Count, Detail: repeatDetail(h)})
		} else {
			res.Updated++
		}
	}
	return nil
}

// repeatDetail describes a user's pile of repeated events for an alert's announcement.
func repeatDetail(h repeatHit) string {
	var what []string
	if h.keyword != "" {
		what = append(what, fmt.Sprintf("the keyword %q", h.keyword))
	}
	if h.hasLevel {
		name, ok := severityName[h.level]
		if !ok {
			name = "level " + strconv.Itoa(h.level)
		}
		what = append(what, "severity "+name)
	}
	span := elapsed(float64(max(h.stat.Last-h.stat.First, 60_000)) / 3_600_000)
	return fmt.Sprintf("%d events with %s in %s", h.stat.Count, strings.Join(what, " and "), span)
}
