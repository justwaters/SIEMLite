package storage

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// TravelRuleName is the name of the built-in rule that finds improbable travel: the same
// user signing in from places too far apart for the time between the sign-ins. The alert
// engine recognises the rule by this name (case-insensitively) and runs it through
// TravelLogins and PreviousLogin instead of counting events.
const TravelRuleName = "Improbable travel"

// TravelRuleQuery is what counts as a successful sign-in by default: SSH logins and VPN logins
// of the log generator, and SIEMLite's own sign-ins (password and Microsoft). Field terms
// can't be joined to words with OR, so this is the one list of actions; an administrator
// edits it to fit their own logs.
const TravelRuleQuery = "action=auth.success,vpn.login,signin,signin.sso"

// TravelMaxKmh is the default fastest speed, in km/h, that counts as believable.
const TravelMaxKmh = 900

// MaxTravelLogins bounds how many sign-ins TravelLogins returns for one check.
const MaxTravelLogins = 5000

// Login is a successful sign-in with the place its source address geolocates to.
type Login struct {
	User, IP, Country, City string
	Lon, Lat                float64
	TimeMs, Seq             int64
}

// EnsureTravelRule adds the built-in "Improbable travel" rule when it isn't there yet. It
// never changes an existing rule, so an administrator's edits (query, severity, whether it
// is on, the speed) survive restarts. (A migration would do the same, but this is
// idempotent on its own.)
func (r *Repository) EnsureTravelRule(ctx context.Context) error {
	now := time.Now().UnixMilli()
	_, err := r.db.Write.ExecContext(ctx, `INSERT OR IGNORE INTO alert_rules (name, description, enabled, severity, query,
		threat_only, group_by, threshold, window_minutes, builtin, created_at, updated_at, kind)
		VALUES (?, ?, 1, 4, ?, 0, 'user', ?, 1440, 1, ?, ?, 'match')`,
		TravelRuleName,
		"The same user signed in from two places too far apart to travel between in the time that passed. Needs a GeoIP City database.",
		TravelRuleQuery, TravelMaxKmh, now, now)
	if err != nil {
		return fmt.Errorf("add the %s rule: %w", TravelRuleName, err)
	}
	return nil
}

// coordsOK is the condition that an event has a location with coordinates in its enrichment.
const coordsOK = `CASE WHEN json_valid(e.enrichment) THEN
		json_type(e.enrichment, '$.src_endpoint.location.coordinates[0]') IN ('integer', 'real')
		AND json_type(e.enrichment, '$.src_endpoint.location.coordinates[1]') IN ('integer', 'real')
	ELSE 0 END`

func loginCols(seqCol string) string {
	return `COALESCE(e.user_name, ''), COALESCE(e.src_ip, ''),
		COALESCE(json_extract(e.enrichment, '$.src_endpoint.location.country'), e.src_country, ''),
		COALESCE(json_extract(e.enrichment, '$.src_endpoint.location.city'), ''),
		json_extract(e.enrichment, '$.src_endpoint.location.coordinates[0]'),
		json_extract(e.enrichment, '$.src_endpoint.location.coordinates[1]'),
		e.timestamp, COALESCE(` + seqCol + `, 0)`
}

func scanLogin(row interface{ Scan(...any) error }) (Login, error) {
	var l Login
	err := row.Scan(&l.User, &l.IP, &l.Country, &l.City, &l.Lon, &l.Lat, &l.TimeMs, &l.Seq)
	return l, err
}

// TravelLogins returns the rule's matching events with arrival numbers in (afterSeq, maxSeq]
// that name a user and have coordinates, oldest first (by time, then arrival). At most
// MaxTravelLogins come back, and they are always the ones that arrived first: when the
// result is that long the caller must go on from the highest Seq in it (not from maxSeq),
// since every matching event up to that number is in the result.
func (r *Repository) TravelLogins(ctx context.Context, ru Rule, afterSeq, maxSeq int64) ([]Login, error) {
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	var out []Login
	for _, s := range d.span(0, 0) {
		db, err := s.reader()
		if err != nil {
			return nil, err
		}
		if s.day != 0 {
			var fresh int
			if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM events INDEXED BY idx_events_seq
				WHERE seq > ? AND seq <= ?)`, afterSeq, maxSeq).Scan(&fresh); err != nil {
				return nil, fmt.Errorf("rule %q: %w", ru.Name, err)
			}
			if fresh == 0 {
				continue
			}
		}
		from, where, args, err := r.ruleFrom(ctx, ru)
		if err != nil {
			return nil, err
		}
		where = append(where, s.seqCol()+" > ?", s.seqCol()+" <= ?", "COALESCE(e.user_name, '') <> ''", coordsOK)
		args = append(args, afterSeq, maxSeq)
		if lw, la := d.legacyWhere(s); lw != "" {
			where, args = append(where, lw), append(args, la...)
		}
		rows, err := db.QueryContext(ctx, `SELECT `+loginCols(s.seqCol())+` FROM `+from+whereSQL(where)+
			` ORDER BY `+s.seqCol()+` LIMIT ?`, append(args, MaxTravelLogins)...)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", ru.Name, err)
		}
		for rows.Next() {
			l, err := scanLogin(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, l)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	// Keep the first MaxTravelLogins to arrive, then put them in the order they happened.
	slices.SortFunc(out, func(a, b Login) int { return cmp.Compare(a.Seq, b.Seq) })
	if len(out) > MaxTravelLogins {
		out = out[:MaxTravelLogins]
	}
	slices.SortFunc(out, func(a, b Login) int {
		if c := cmp.Compare(a.TimeMs, b.TimeMs); c != 0 {
			return c
		}
		return cmp.Compare(a.Seq, b.Seq)
	})
	return out, nil
}

// PreviousLogin returns the same user's latest matching sign-in (with coordinates) before the
// given one, within lookbackMs of it, or nil. User names compare without regard to case. Of
// sign-ins at the same millisecond the one that arrived first (lower seq) is earlier, and an
// event is never its own predecessor.
func (r *Repository) PreviousLogin(ctx context.Context, ru Rule, user string, beforeMs, beforeSeq, lookbackMs int64) (*Login, error) {
	if lookbackMs <= 0 {
		lookbackMs = 24 * 60 * 60 * 1000
	}
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	var best *Login
	for _, s := range d.span(beforeMs-lookbackMs, beforeMs) {
		db, err := s.reader()
		if err != nil {
			return nil, err
		}
		from, where, args, err := r.ruleFrom(ctx, ru)
		if err != nil {
			return nil, err
		}
		where = append(where, "e.user_name = ? COLLATE NOCASE", "e.timestamp >= ?", "e.timestamp <= ?",
			"(e.timestamp < ? OR COALESCE("+s.seqCol()+", 0) < ?)", coordsOK)
		args = append(args, user, beforeMs-lookbackMs, beforeMs, beforeMs, beforeSeq)
		if lw, la := d.legacyWhere(s); lw != "" {
			where, args = append(where, lw), append(args, la...)
		}
		l, err := scanLogin(db.QueryRowContext(ctx, `SELECT `+loginCols(s.seqCol())+` FROM `+from+whereSQL(where)+
			` ORDER BY e.timestamp DESC, `+s.seqCol()+` DESC LIMIT 1`, args...))
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", ru.Name, err)
		}
		if best == nil || l.TimeMs > best.TimeMs || (l.TimeMs == best.TimeMs && l.Seq > best.Seq) {
			best = &l
		}
	}
	return best, nil
}
