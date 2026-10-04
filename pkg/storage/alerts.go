package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrRuleNotFound  = errors.New("rule not found")
	ErrRuleExists    = errors.New("a rule with that name already exists")
	ErrAlertNotFound = errors.New("alert not found")
)

// Alert statuses.
const (
	AlertOpen         = "open"
	AlertAcknowledged = "acknowledged"
	AlertClosed       = "closed"
)

// Rule raises an alert when at least Threshold matching events, grouped by
// GroupBy, arrive within WindowMinutes.
type Rule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Enabled       bool   `json:"enabled"`
	Severity      int    `json:"severity"` // the alert's severity
	Query         string `json:"query"`    // FTS5 expression; empty matches everything
	MinSeverity   *int   `json:"min_severity,omitempty"`
	ThreatOnly    bool   `json:"threat_only"`
	SourceID      *int64 `json:"source_id,omitempty"`
	GroupBy       string `json:"group_by"` // "", src_ip, dst_ip, user or host
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Builtin       bool   `json:"builtin"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// Alert is a rule that fired, for one group value.
type Alert struct {
	ID         int64  `json:"id"`
	RuleID     *int64 `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name"`
	Severity   int    `json:"severity"`
	GroupBy    string `json:"group_by"`
	GroupValue string `json:"group_value"`
	Status     string `json:"status"`
	Count      int64  `json:"count"`
	FirstSeen  int64  `json:"first_seen"`
	LastSeen   int64  `json:"last_seen"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	UpdatedBy  string `json:"updated_by,omitempty"`
}

const ruleCols = `id, name, description, enabled, severity, query, min_severity, threat_only, source_id, group_by,
	threshold, window_minutes, builtin, created_at, updated_at`

func scanRule(row interface{ Scan(...any) error }) (*Rule, error) {
	var r Rule
	var minSev, src sql.NullInt64
	if err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.Severity, &r.Query, &minSev, &r.ThreatOnly, &src,
		&r.GroupBy, &r.Threshold, &r.WindowMinutes, &r.Builtin, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if minSev.Valid {
		v := int(minSev.Int64)
		r.MinSeverity = &v
	}
	if src.Valid {
		r.SourceID = &src.Int64
	}
	return &r, nil
}

// ListRules returns every rule by name.
func (r *Repository) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+ruleCols+` FROM alert_rules ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		ru, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ru)
	}
	return out, rows.Err()
}

// GetRule returns one rule.
func (r *Repository) GetRule(ctx context.Context, id int64) (*Rule, error) {
	ru, err := scanRule(r.db.Read.QueryRowContext(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRuleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get rule: %w", err)
	}
	return ru, nil
}

// SaveRule creates (ID 0) or updates a rule and returns its id.
func (r *Repository) SaveRule(ctx context.Context, ru Rule, nowMs int64) (int64, error) {
	var res sql.Result
	var err error
	if ru.ID == 0 {
		res, err = r.db.Write.ExecContext(ctx, `INSERT INTO alert_rules (name, description, enabled, severity, query, min_severity,
			threat_only, source_id, group_by, threshold, window_minutes, builtin, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
			ru.Name, ru.Description, ru.Enabled, ru.Severity, ru.Query, ru.MinSeverity, ru.ThreatOnly, ru.SourceID, ru.GroupBy,
			ru.Threshold, ru.WindowMinutes, nowMs, nowMs)
	} else {
		res, err = r.db.Write.ExecContext(ctx, `UPDATE alert_rules SET name = ?, description = ?, enabled = ?, severity = ?,
			query = ?, min_severity = ?, threat_only = ?, source_id = ?, group_by = ?, threshold = ?, window_minutes = ?,
			updated_at = ? WHERE id = ?`,
			ru.Name, ru.Description, ru.Enabled, ru.Severity, ru.Query, ru.MinSeverity, ru.ThreatOnly, ru.SourceID, ru.GroupBy,
			ru.Threshold, ru.WindowMinutes, nowMs, ru.ID)
	}
	if uniqueErr(err) {
		return 0, ErrRuleExists
	}
	if err != nil {
		return 0, fmt.Errorf("save rule: %w", err)
	}
	if ru.ID == 0 {
		return res.LastInsertId()
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrRuleNotFound
	}
	return ru.ID, nil
}

// DeleteRule removes a rule; its alerts are kept.
func (r *Repository) DeleteRule(ctx context.Context, id int64) error {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// groupExpr is the SQL for a rule's grouping column.
func groupExpr(groupBy string) string {
	switch groupBy {
	case "src_ip":
		return "COALESCE(e.src_ip, '')"
	case "dst_ip":
		return "COALESCE(e.dst_ip, '')"
	case "user":
		return "COALESCE(e.user_name, '')"
	case "host":
		return "COALESCE(e.host, '')"
	}
	return "''"
}

// ruleFrom builds the FROM clause and conditions selecting a rule's events.
func ruleFrom(ru Rule) (string, []string, []any) {
	from := "events e"
	var where []string
	var args []any
	if q := strings.TrimSpace(ru.Query); q != "" {
		from = "events_fts JOIN events e ON e.id = events_fts.rowid"
		where = append(where, "events_fts MATCH ?")
		args = append(args, q)
	}
	if ru.MinSeverity != nil {
		where = append(where, "e.severity_id >= ? AND e.severity_id <= 6")
		args = append(args, *ru.MinSeverity)
	}
	if ru.ThreatOnly {
		where = append(where, "e.threat = 1")
	}
	if ru.SourceID != nil {
		where = append(where, "e.source_id = ?")
		args = append(args, *ru.SourceID)
	}
	return from, where, args
}

// RuleGroup is a group with new events matching a rule.
type RuleGroup struct {
	Value  string
	NewMax int64 // newest new event time
	New    int64 // new matching events
}

// NewMatches returns the groups with events that arrived after afterSeq (up
// to maxSeq) and match the rule. Late events land in older days' files, so
// every day is checked; the arrival index makes that cheap for days with
// nothing new.
func (r *Repository) NewMatches(ctx context.Context, ru Rule, afterSeq, maxSeq int64) ([]RuleGroup, error) {
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	merged := map[string]*RuleGroup{}
	for _, s := range d.span(0, 0) {
		db, err := s.reader()
		if err != nil {
			return nil, err
		}
		// With few new rows, walk them and test each against the search rather
		// than reading every match of the search in every day; with many (a
		// backlog), let the search drive.
		from, where, args := ruleFrom(ru)
		if s.day != 0 {
			var fresh int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM events INDEXED BY idx_events_seq
				WHERE seq > ? AND seq <= ? LIMIT ?)`, afterSeq, maxSeq, fewNew).Scan(&fresh); err != nil {
				return nil, fmt.Errorf("rule %q: %w", ru.Name, err)
			}
			if fresh == 0 {
				continue
			}
			if fresh < fewNew {
				from = "events e INDEXED BY idx_events_seq"
				where, args = ruleWhere(ru)
			}
		}
		where = append(where, s.seqCol()+" > ?", s.seqCol()+" <= ?")
		args = append(args, afterSeq, maxSeq)
		if lw, la := d.legacyWhere(s); lw != "" {
			where, args = append(where, lw), append(args, la...)
		}
		rows, err := db.QueryContext(ctx, `SELECT `+groupExpr(ru.GroupBy)+`, MAX(e.timestamp), COUNT(*) FROM `+from+
			whereSQL(where)+` GROUP BY 1`, args...)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", ru.Name, err)
		}
		for rows.Next() {
			var rg RuleGroup
			if err := rows.Scan(&rg.Value, &rg.NewMax, &rg.New); err != nil {
				rows.Close()
				return nil, err
			}
			if cur, ok := merged[rg.Value]; ok {
				cur.New += rg.New
				cur.NewMax = max(cur.NewMax, rg.NewMax)
			} else {
				merged[rg.Value] = &rg
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	out := make([]RuleGroup, 0, len(merged))
	for _, g := range merged {
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b RuleGroup) int { return strings.Compare(a.Value, b.Value) })
	return out, nil
}

// fewNew is how many new rows in a day are tested one by one against a
// rule's search; beyond it the search index finds the matches.
const fewNew = 2000

// ruleWhere is a rule's conditions, with its search as a test of each row.
func ruleWhere(ru Rule) ([]string, []any) {
	_, where, args := ruleFrom(ru)
	if q := strings.TrimSpace(ru.Query); q != "" {
		where[0] = "EXISTS (SELECT 1 FROM events_fts WHERE events_fts MATCH ? AND events_fts.rowid = e.id)"
	}
	return where, args
}

// WindowStat is a group's matching events within a rule's window.
type WindowStat struct {
	Count, First, Last int64
}

// WindowCounts counts, for each group, the rule's matching events in the
// window ending at the group's newest new event (and arrived up to maxSeq).
// It reads each day in the windows once for all groups: a query per group
// would rescan the search index for each address.
func (r *Repository) WindowCounts(ctx context.Context, ru Rule, groups []RuleGroup, window, maxSeq int64) (map[string]WindowStat, error) {
	out := make(map[string]WindowStat, len(groups))
	if len(groups) == 0 {
		return out, nil
	}
	newMax := make(map[string]int64, len(groups))
	lo, hi := groups[0].NewMax, groups[0].NewMax
	for _, g := range groups {
		newMax[g.Value] = g.NewMax
		lo, hi = min(lo, g.NewMax), max(hi, g.NewMax)
	}
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	for _, s := range d.span(lo-window, hi) {
		db, err := s.reader()
		if err != nil {
			return nil, err
		}
		from, where, args := ruleFrom(ru)
		where = append(where, "e.timestamp >= ?", "e.timestamp <= ?", s.seqCol()+" <= ?")
		args = append(args, lo-window, hi, maxSeq)
		if lw, la := d.legacyWhere(s); lw != "" {
			where, args = append(where, lw), append(args, la...)
		}
		rows, err := db.QueryContext(ctx, `SELECT `+groupExpr(ru.GroupBy)+`, e.timestamp FROM `+from+whereSQL(where), args...)
		if err != nil {
			return nil, fmt.Errorf("rule %q window: %w", ru.Name, err)
		}
		for rows.Next() {
			var v string
			var ts int64
			if err := rows.Scan(&v, &ts); err != nil {
				rows.Close()
				return nil, err
			}
			end, ok := newMax[v]
			if !ok || ts < end-window || ts > end {
				continue
			}
			st, seen := out[v]
			if !seen {
				st = WindowStat{First: ts, Last: ts}
			}
			st.Count++
			st.First, st.Last = min(st.First, ts), max(st.Last, ts)
			out[v] = st
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MaxEventSeq is the arrival number of the newest event this process has
// stored (or the newest when it started). Every event up to it is visible.
func (r *Repository) MaxEventSeq(ctx context.Context) (int64, error) {
	return r.db.days.seq.Load(), nil
}

// RaiseAlert records that a rule fired for a group: it updates the group's
// open or acknowledged alert, or opens a new one.
func (r *Repository) RaiseAlert(ctx context.Context, ru Rule, value string, newCount, windowCount, first, last int64, nowMs int64) (opened bool, err error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM alerts WHERE rule_id = ? AND group_value = ? AND status <> 'closed'
		ORDER BY id DESC LIMIT 1`, ru.ID, value).Scan(&id)
	switch {
	case err == nil:
		_, err = tx.ExecContext(ctx, `UPDATE alerts SET count = count + ?, last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?),
			severity = ?, updated_at = ? WHERE id = ?`, newCount, last, first, ru.Severity, nowMs, id)
	case errors.Is(err, sql.ErrNoRows):
		opened = true
		_, err = tx.ExecContext(ctx, `INSERT INTO alerts (rule_id, rule_name, severity, group_by, group_value, status, count,
			first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)`,
			ru.ID, ru.Name, ru.Severity, ru.GroupBy, value, windowCount, first, last, nowMs, nowMs)
	}
	if err != nil {
		return false, fmt.Errorf("raise alert: %w", err)
	}
	return opened, tx.Commit()
}

// ActiveAlertGroups returns the groups for which a rule has an open or
// acknowledged alert.
func (r *Repository) ActiveAlertGroups(ctx context.Context, ruleID int64) (map[string]bool, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT group_value FROM alerts WHERE rule_id = ? AND status <> 'closed'`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// ListAlerts returns alerts with a status ("" for all), newest activity
// first, and the number in each status.
func (r *Repository) ListAlerts(ctx context.Context, status string, limit int) ([]Alert, map[string]int64, error) {
	q := `SELECT id, rule_id, rule_name, severity, group_by, group_value, status, count, first_seen, last_seen,
		created_at, updated_at, updated_by FROM alerts`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY last_seen DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var rid sql.NullInt64
		if err := rows.Scan(&a.ID, &rid, &a.RuleName, &a.Severity, &a.GroupBy, &a.GroupValue, &a.Status, &a.Count,
			&a.FirstSeen, &a.LastSeen, &a.CreatedAt, &a.UpdatedAt, &a.UpdatedBy); err != nil {
			return nil, nil, err
		}
		if rid.Valid {
			a.RuleID = &rid.Int64
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	counts := map[string]int64{AlertOpen: 0, AlertAcknowledged: 0, AlertClosed: 0}
	crow, err := r.db.Read.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts GROUP BY status`)
	if err != nil {
		return nil, nil, err
	}
	defer crow.Close()
	for crow.Next() {
		var s string
		var n int64
		if err := crow.Scan(&s, &n); err != nil {
			return nil, nil, err
		}
		counts[s] = n
	}
	return out, counts, crow.Err()
}

// SetAlertStatus changes an alert's status.
func (r *Repository) SetAlertStatus(ctx context.Context, id int64, status, by string, nowMs int64) (*Alert, error) {
	res, err := r.db.Write.ExecContext(ctx, `UPDATE alerts SET status = ?, updated_by = ?, updated_at = ? WHERE id = ?`, status, by, nowMs, id)
	if err != nil {
		return nil, fmt.Errorf("set alert status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrAlertNotFound
	}
	var a Alert
	var rid sql.NullInt64
	err = r.db.Write.QueryRowContext(ctx, `SELECT id, rule_id, rule_name, severity, group_by, group_value, status, count, first_seen,
		last_seen, created_at, updated_at, updated_by FROM alerts WHERE id = ?`, id).Scan(&a.ID, &rid, &a.RuleName,
		&a.Severity, &a.GroupBy, &a.GroupValue, &a.Status, &a.Count, &a.FirstSeen, &a.LastSeen, &a.CreatedAt, &a.UpdatedAt, &a.UpdatedBy)
	if rid.Valid {
		a.RuleID = &rid.Int64
	}
	return &a, err
}

// CountOpenAlerts returns the number of open alerts.
func (r *Repository) CountOpenAlerts(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE status = 'open'`).Scan(&n)
	return n, err
}
