package storage

import (
	"context"
	"fmt"
	"strings"
)

// Overview summarizes events in a time window for the dashboard.
type Overview struct {
	Total      int64           `json:"total"`
	Threats    int64           `json:"threats"`
	BySeverity map[int]int64   `json:"by_severity"`
	Buckets    []Bucket        `json:"buckets"` // oldest first, every bucket present
	TopSources []NamedCount    `json:"top_sources"`
	TopCountry []NamedCount    `json:"top_countries"`
	TopThreats []ThreatSummary `json:"top_threat_ips"`
}

// Bucket counts events in [Start, Start+width).
type Bucket struct {
	Start   int64 `json:"start"`
	Count   int64 `json:"count"`
	Threats int64 `json:"threats"`
}

// NamedCount is a label with a count.
type NamedCount struct {
	ID    int64  `json:"id,omitempty"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// ThreatSummary is a source IP that matched threat intel.
type ThreatSummary struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Count   int64  `json:"count"`
}

// Overview counts events between startMs and endMs in buckets of bucketMs,
// honouring f's source filters (other filters are ignored).
func (r *Repository) Overview(ctx context.Context, startMs, endMs, bucketMs int64, f Filter) (*Overview, error) {
	where, args := sourceWhere(f, []string{"e.timestamp >= ?", "e.timestamp < ?"}, nil)
	args = append([]any{startMs, endMs}, args...)
	cond := " WHERE " + strings.Join(where, " AND ")
	ov := &Overview{BySeverity: map[int]int64{}, TopSources: []NamedCount{}, TopCountry: []NamedCount{}, TopThreats: []ThreatSummary{}}

	q := func(query string, scan func() []any, each func()) error {
		rows, err := r.db.Read.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("overview: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := rows.Scan(scan()...); err != nil {
				return err
			}
			each()
		}
		return rows.Err()
	}

	var sev int
	var n int64
	if err := q(`SELECT e.severity_id, COUNT(*) FROM events e`+cond+` GROUP BY e.severity_id`,
		func() []any { return []any{&sev, &n} }, func() { ov.BySeverity[sev] = n; ov.Total += n }); err != nil {
		return nil, err
	}

	counts := map[int64][2]int64{}
	var b, c, t int64
	if err := q(fmt.Sprintf(`SELECT (e.timestamp - %d) / %d, COUNT(*), SUM(e.threat) FROM events e%s GROUP BY 1`, startMs, bucketMs, cond),
		func() []any { return []any{&b, &c, &t} }, func() { counts[b] = [2]int64{c, t}; ov.Threats += t }); err != nil {
		return nil, err
	}
	for i := int64(0); startMs+i*bucketMs < endMs; i++ {
		ov.Buckets = append(ov.Buckets, Bucket{Start: startMs + i*bucketMs, Count: counts[i][0], Threats: counts[i][1]})
	}

	var nc NamedCount
	if err := q(`SELECT COALESCE(e.source_id, 0), COALESCE(so.name, 'Unknown'), COUNT(*) FROM events e
		LEFT JOIN sources so ON so.id = e.source_id`+cond+` GROUP BY 1 ORDER BY 3 DESC LIMIT 6`,
		func() []any { return []any{&nc.ID, &nc.Name, &nc.Count} }, func() { ov.TopSources = append(ov.TopSources, nc) }); err != nil {
		return nil, err
	}
	var cc NamedCount
	if err := q(`SELECT e.src_country, COUNT(*) FROM events e`+cond+` AND e.src_country IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 6`,
		func() []any { return []any{&cc.Name, &cc.Count} }, func() { ov.TopCountry = append(ov.TopCountry, cc) }); err != nil {
		return nil, err
	}
	// The IPs that actually matched an indicator (src or dst), read from
	// each event's threat intel matches, with that side's country.
	var ts ThreatSummary
	var country *string
	if err := q(`SELECT ip, MAX(cc), COUNT(*) FROM (
			SELECT COALESCE(json_extract(m.value, '$.matched'), json_extract(m.value, '$.value')) AS ip,
				CASE COALESCE(json_extract(m.value, '$.matched'), json_extract(m.value, '$.value'))
					WHEN e.src_ip THEN e.src_country WHEN e.dst_ip THEN e.dst_country END AS cc
			FROM events e, json_each(e.enrichment, '$.threat_intel') m`+cond+` AND e.threat = 1
				AND json_extract(m.value, '$.type') IN ('ip', 'cidr'))
		GROUP BY ip ORDER BY 3 DESC LIMIT 5`,
		func() []any { return []any{&ts.IP, &country, &ts.Count} },
		func() {
			ts.Country = ""
			if country != nil {
				ts.Country = *country
			}
			ov.TopThreats = append(ov.TopThreats, ts)
		}); err != nil {
		return nil, err
	}
	return ov, nil
}
