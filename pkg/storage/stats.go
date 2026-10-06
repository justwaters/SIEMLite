package storage

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
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
// honouring f's source filters (other filters are ignored). Each day in the
// window is counted separately, a few at a time, and the counts added up.
func (r *Repository) Overview(ctx context.Context, startMs, endMs, bucketMs int64, f Filter) (*Overview, error) {
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	shards := d.span(startMs, endMs-1)

	var (
		mu        sync.Mutex
		firstErr  error
		bySev     = map[int]int64{}
		buckets   = map[int64][2]int64{}
		bySource  = map[int64]int64{}
		byCountry = map[string]int64{}
		threats   = map[string]*ThreatSummary{}
	)
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, s := range shards {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			p, err := r.overviewShard(ctx, s, startMs, endMs, bucketMs, f)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for k, v := range p.bySev {
				bySev[k] += v
			}
			for k, v := range p.buckets {
				b := buckets[k]
				buckets[k] = [2]int64{b[0] + v[0], b[1] + v[1]}
			}
			for k, v := range p.bySource {
				bySource[k] += v
			}
			for k, v := range p.byCountry {
				byCountry[k] += v
			}
			for _, t := range p.threats {
				cur, ok := threats[t.IP]
				if !ok {
					cur = &ThreatSummary{IP: t.IP}
					threats[t.IP] = cur
				}
				cur.Count += t.Count
				if cur.Country == "" {
					cur.Country = t.Country
				}
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, fmt.Errorf("overview: %w", firstErr)
	}

	ov := &Overview{BySeverity: bySev, TopSources: []NamedCount{}, TopCountry: []NamedCount{}, TopThreats: []ThreatSummary{}}
	for _, n := range bySev {
		ov.Total += n
	}
	for i := int64(0); startMs+i*bucketMs < endMs; i++ {
		b := buckets[i]
		ov.Buckets = append(ov.Buckets, Bucket{Start: startMs + i*bucketMs, Count: b[0], Threats: b[1]})
		ov.Threats += b[1]
	}
	names, err := r.sourceNames(ctx)
	if err != nil {
		return nil, err
	}
	for id, n := range bySource {
		name := SourceLabel(names, id)
		ov.TopSources = append(ov.TopSources, NamedCount{ID: id, Name: name, Count: n})
	}
	for cc, n := range byCountry {
		ov.TopCountry = append(ov.TopCountry, NamedCount{Name: cc, Count: n})
	}
	for _, t := range threats {
		ov.TopThreats = append(ov.TopThreats, *t)
	}
	byCount := func(a, b NamedCount) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return strings.Compare(a.Name, b.Name)
	}
	slices.SortFunc(ov.TopSources, byCount)
	slices.SortFunc(ov.TopCountry, byCount)
	slices.SortFunc(ov.TopThreats, func(a, b ThreatSummary) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return strings.Compare(a.IP, b.IP)
	})
	ov.TopSources = ov.TopSources[:min(len(ov.TopSources), 6)]
	ov.TopCountry = ov.TopCountry[:min(len(ov.TopCountry), 6)]
	ov.TopThreats = ov.TopThreats[:min(len(ov.TopThreats), 5)]
	return ov, nil
}

// overviewPart is one shard's counts.
type overviewPart struct {
	bySev     map[int]int64
	buckets   map[int64][2]int64
	bySource  map[int64]int64
	byCountry map[string]int64
	threats   []ThreatSummary
}

func (r *Repository) overviewShard(ctx context.Context, s *shard, startMs, endMs, bucketMs int64, f Filter) (*overviewPart, error) {
	db, err := s.reader()
	if err != nil {
		return nil, err
	}
	where, args := sourceWhere(f, []string{"e.timestamp >= ?", "e.timestamp < ?"}, nil)
	args = append([]any{startMs, endMs}, args...)
	if lw, la := r.db.days.legacyWhere(s); lw != "" {
		where, args = append(where, lw), append(args, la...)
	}
	cond := whereSQL(where)
	p := &overviewPart{bySev: map[int]int64{}, buckets: map[int64][2]int64{}, bySource: map[int64]int64{}, byCountry: map[string]int64{}}

	q := func(query string, scan func() []any, each func()) error {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
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
	var n, b, c, t, id int64
	var name string
	if err := q(`SELECT e.severity_id, COUNT(*) FROM events e`+cond+` GROUP BY e.severity_id`,
		func() []any { return []any{&sev, &n} }, func() { p.bySev[sev] = n }); err != nil {
		return nil, err
	}
	if err := q(fmt.Sprintf(`SELECT (e.timestamp - %d) / %d, COUNT(*), SUM(e.threat) FROM events e%s GROUP BY 1`, startMs, bucketMs, cond),
		func() []any { return []any{&b, &c, &t} }, func() { p.buckets[b] = [2]int64{c, t} }); err != nil {
		return nil, err
	}
	if err := q(`SELECT COALESCE(e.source_id, 0), COUNT(*) FROM events e`+cond+` GROUP BY 1`,
		func() []any { return []any{&id, &n} }, func() { p.bySource[id] = n }); err != nil {
		return nil, err
	}
	if err := q(`SELECT e.src_country, COUNT(*) FROM events e`+cond+` AND e.src_country IS NOT NULL GROUP BY 1`,
		func() []any { return []any{&name, &n} }, func() { p.byCountry[name] = n }); err != nil {
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
		GROUP BY ip`,
		func() []any { return []any{&ts.IP, &country, &ts.Count} },
		func() {
			ts.Country = ""
			if country != nil {
				ts.Country = *country
			}
			p.threats = append(p.threats, ts)
		}); err != nil {
		return nil, err
	}
	return p, nil
}
