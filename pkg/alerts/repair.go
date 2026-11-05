package alerts

import (
	"context"
	"fmt"

	"siemlite/pkg/storage"
)

const repairKey = "alerts_self_trigger_repaired"

// selfTriggered are the built-in rules that watch SIEMLite's own audit log, and so could be
// raised by the audit events about managing their own alerts.
var selfTriggered = []string{"Mass ingestion of late logs"}

// Repair is one alert whose count was corrected.
type Repair struct {
	AlertID  int64
	Rule     string
	From, To int64
	Closed   bool // it had no real event behind it, so it was closed
}

// RepairSelfTriggered corrects the alerts that SIEMLite's own audit events raised or inflated
// (managing an alert named it in an audit message that the rule's phrase matched, so a new alert
// opened each time). It runs once per database; a restart does nothing more.
//
// For each alert of the rule it counts the events the rule matches now, without those audit events:
//   - in the alert's time span, which is what its count meant. A count above that was inflated, and is lowered.
//   - after the previous alert of the same group ended. An alert's span reaches back over the rule's whole
//     window, so a spurious alert's span still holds the real event that an earlier alert already covered.
//     An alert with no event of its own was raised by the audit events alone: it is closed (by "SIEMLite")
//     if it is still open, and its count is 0.
//
// A genuine later alert, with events of its own, keeps its count (never raised, only lowered).
func (e *Engine) RepairSelfTriggered(ctx context.Context) ([]Repair, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if done, err := e.store.Setting(ctx, repairKey, ""); err != nil || done == "1" {
		return nil, err
	}
	rules, err := e.store.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	var out []Repair
	now := e.now().UnixMilli()
	for _, ru := range rules {
		if !ru.Builtin || !contains(selfTriggered, ru.Name) {
			continue
		}
		pr, err := e.prepare(ctx, ru)
		if err != nil {
			return out, err
		}
		alerts, err := e.store.AlertsOfRule(ctx, ru.ID) // oldest first
		if err != nil {
			return out, err
		}
		prevEnd := map[string]int64{} // per group: when the earlier alerts' events ended
		for _, a := range alerts {
			group := a.GroupValue
			span, err := e.store.CountRuleEvents(ctx, pr, group, a.FirstSeen, a.LastSeen)
			if err != nil {
				return out, fmt.Errorf("alert %d: %w", a.ID, err)
			}
			own := span
			if end, ok := prevEnd[group]; ok {
				own, err = e.store.CountRuleEvents(ctx, pr, group, max(a.FirstSeen, end+1), a.LastSeen)
				if err != nil {
					return out, fmt.Errorf("alert %d: %w", a.ID, err)
				}
			}
			prevEnd[group] = max(prevEnd[group], a.LastSeen)
			want := min(a.Count, span)
			if own == 0 {
				want = 0
			}
			if want == a.Count && !(own == 0 && a.Status != storage.AlertClosed) {
				continue
			}
			r := Repair{AlertID: a.ID, Rule: ru.Name, From: a.Count, To: want}
			if want != a.Count {
				if err := e.store.SetAlertCount(ctx, a.ID, want, now); err != nil {
					return out, err
				}
			}
			if own == 0 && a.Status != storage.AlertClosed {
				if _, err := e.store.SetAlertStatus(ctx, a.ID, storage.AlertClosed, "SIEMLite", now); err != nil {
					return out, err
				}
				r.Closed = true
			}
			out = append(out, r)
			e.log.Info("corrected an alert counted from SIEMLite's own audit events", "alert", a.ID, "rule", ru.Name, "was", a.Count, "now", want, "closed", r.Closed)
		}
	}
	return out, e.store.SetSetting(ctx, repairKey, "1")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
