package storage

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
)

// Record is one row of the events table.
type Record struct {
	ID          int64  `json:"id"`
	Timestamp   int64  `json:"timestamp"`
	CategoryUID int    `json:"category_uid"`
	ClassUID    int    `json:"class_uid"`
	SeverityID  int    `json:"severity_id"`
	SrcIP       string `json:"src_ip,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	UserName    string `json:"user_name,omitempty"`
	RawData     string `json:"raw_data"`

	Source     string `json:"source,omitempty"` // producing product, e.g. "sshd"
	Host       string `json:"host,omitempty"`   // reporting device
	SrcCountry string `json:"src_country,omitempty"`
	DstCountry string `json:"dst_country,omitempty"`
	SrcASN     int    `json:"src_asn,omitempty"`
	DstASN     int    `json:"dst_asn,omitempty"`
	Threat     bool   `json:"threat,omitempty"` // matched a threat intel indicator
	Sample     bool   `json:"sample,omitempty"` // demo data from the Sample data switch
	SourceID   int64  `json:"source_id,omitempty"`
	SourceName string `json:"source_name,omitempty"` // read-only: the source's current name
	// Fields holds extra values a parser extracted, as a JSON object.
	Fields json.RawMessage `json:"fields,omitempty"`
	// Enrichment is the JSON document of GeoIP/ASN and threat intel context.
	Enrichment json.RawMessage `json:"enrichment,omitempty"`
}

// Filter describes a search. Zero values mean "no constraint" except where
// noted; Limit must be positive.
type Filter struct {
	StartMs     int64 // inclusive; 0 = unbounded
	EndMs       int64 // inclusive; 0 = unbounded
	CategoryUID *int
	ClassUID    *int
	SeverityID  *int
	SrcIP       string
	DstIP       string
	UserName    string
	Source      string
	Host        string
	Country     string // either endpoint's ISO country code
	ASN         int    // either endpoint's autonomous system number
	ThreatOnly  bool
	SourceID    int64 // one source; 0 = any
	// Restrict limits results to AllowedSources (a restricted user's view).
	// With Restrict set and no sources, nothing matches.
	Restrict       bool
	AllowedSources []int64
	Match          string // raw FTS5 MATCH expression
	Limit          int
	Offset         int
}

// Repository provides data access over a DB.
type Repository struct {
	db *DB
}

// DB returns the underlying database (for tests and maintenance).
func (r *Repository) DB() *DB { return r.db }

// NewRepository returns a Repository backed by db.
func NewRepository(db *DB) *Repository { return &Repository{db: db} }

const insertSQL = `INSERT INTO events
	(timestamp, category_uid, class_uid, severity_id, src_ip, dst_ip, user_name, raw_data,
	 source, host, src_country, dst_country, src_asn, dst_asn, threat, enrichment, sample, source_id, fields)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// InsertBatch writes all records in a single explicit transaction. The FTS
// index is maintained by the AFTER INSERT trigger.
func (r *Repository) InsertBatch(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for i := range recs {
		rec := &recs[i]
		if _, err := stmt.ExecContext(ctx,
			rec.Timestamp, rec.CategoryUID, rec.ClassUID, rec.SeverityID,
			nullable(rec.SrcIP), nullable(rec.DstIP), nullable(rec.UserName), rec.RawData,
			nullable(rec.Source), nullable(rec.Host), nullable(rec.SrcCountry), nullable(rec.DstCountry),
			nullableInt(rec.SrcASN), nullableInt(rec.DstASN), rec.Threat, nullable(string(rec.Enrichment)), rec.Sample,
			nullableInt64(rec.SourceID), nullable(string(rec.Fields)),
		); err != nil {
			return fmt.Errorf("insert record %d: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// Search runs the filter, newest events first.
func (r *Repository) Search(ctx context.Context, f Filter) ([]Record, error) {
	if f.Match != "" {
		// Sorting every match by time reads each matching event in full,
		// which is slow beyond a few hundred. denseSearch avoids that, but
		// walks the time index back as far as the page reaches, which is
		// short only when matches are common. Count enough to tell.
		need := max(denseMatches, denseFactor*(f.Offset+f.Limit))
		var n int
		if err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT rowid FROM events_fts WHERE events_fts MATCH ? LIMIT ?)`,
			f.Match, need).Scan(&n); err != nil {
			return nil, fmt.Errorf("search: %w", err)
		}
		if n >= need {
			ids, err := r.denseSearch(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("search: %w", err)
			}
			return r.records(ctx, ids)
		}
	}
	where, args := filterWhere(f)
	from := "events e"
	if f.Match != "" {
		from = "events_fts JOIN events e ON e.id = events_fts.rowid"
		where = append([]string{"events_fts MATCH ?"}, where...)
		args = append([]any{f.Match}, args...)
	}
	q := `SELECT ` + recordCols + ` FROM ` + from + ` LEFT JOIN sources so ON so.id = e.source_id` + whereSQL(where) +
		` ORDER BY e.timestamp DESC, e.id DESC LIMIT ? OFFSET ?`
	return r.scanRecords(ctx, q, append(args, f.Limit, f.Offset)...)
}

// A search uses denseSearch when it has at least denseMatches matches and
// denseFactor times the events up to the end of the page; then the walk back
// through time covers at most about 1/denseFactor of the events.
var (
	denseMatches = 2000 // variables so tests can change them
	denseFactor  = 20
)

// denseSearch returns the ids of a page of a search that matches many
// events, without reading every match. Ids grow as events are stored, so
// the newest ids are nearly the newest events:
//
//  1. Read matches newest id first (the search index can do this lazily)
//     until there are offset+limit that pass the filters: the candidates.
//  2. An event belongs on the page instead of a candidate only if it is at
//     least as new as the oldest candidate that would be on the page, yet has
//     a smaller id than every candidate (a late arrival with an old
//     timestamp, or a clock running ahead). Those are found by walking the
//     time index back to that time, which is short.
//
// The page is exactly what sorting every match would give.
func (r *Repository) denseSearch(ctx context.Context, f Filter) ([]int64, error) {
	k := f.Offset + f.Limit
	where, args := filterWhere(f)
	bound := int64(math.MaxInt64)
	if f.StartMs > 0 || f.EndMs > 0 {
		// No event in the time range has a larger id than this.
		end := f.EndMs
		if end <= 0 {
			end = math.MaxInt64
		}
		var maxID sql.NullInt64
		if err := r.db.Read.QueryRowContext(ctx, `SELECT MAX(id) FROM events INDEXED BY idx_events_ts WHERE timestamp >= ? AND timestamp <= ?`,
			f.StartMs, end).Scan(&maxID); err != nil {
			return nil, err
		}
		if !maxID.Valid {
			return nil, nil
		}
		bound = maxID.Int64
	}
	type hit struct{ id, ts int64 }
	read := func(q string, args ...any) ([]hit, error) {
		rows, err := r.db.Read.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []hit
		for rows.Next() {
			var h hit
			if err := rows.Scan(&h.id, &h.ts); err != nil {
				return nil, err
			}
			out = append(out, h)
		}
		return out, rows.Err()
	}
	// CROSS JOIN keeps the search index as the outer loop, read newest id first.
	cand, err := read(`SELECT e.id, e.timestamp FROM events_fts CROSS JOIN events e ON e.id = events_fts.rowid
		WHERE events_fts MATCH ? AND events_fts.rowid <= ?`+andSQL(where)+` ORDER BY events_fts.rowid DESC LIMIT ?`,
		append(append([]any{f.Match, bound}, args...), k)...)
	if err != nil {
		return nil, err
	}
	newest := func(a, b hit) int {
		if a.ts != b.ts {
			return cmp.Compare(b.ts, a.ts)
		}
		return cmp.Compare(b.id, a.id)
	}
	if len(cand) == k {
		slices.SortFunc(cand, newest)
		oldest, minID := cand[k-1].ts, cand[len(cand)-1].id
		for _, h := range cand {
			minID = min(minID, h.id)
		}
		late, err := read(`SELECT e.id, e.timestamp FROM events e INDEXED BY idx_events_ts
			WHERE e.timestamp >= ? AND e.id < ?`+andSQL(where)+`
			AND EXISTS (SELECT 1 FROM events_fts WHERE events_fts MATCH ? AND events_fts.rowid = e.id)`,
			append(append([]any{oldest, minID}, args...), f.Match)...)
		if err != nil {
			return nil, err
		}
		cand = append(cand, late...)
	}
	slices.SortFunc(cand, newest)
	if f.Offset >= len(cand) {
		return nil, nil
	}
	cand = cand[f.Offset:min(len(cand), k)]
	ids := make([]int64, len(cand))
	for i, h := range cand {
		ids[i] = h.id
	}
	return ids, nil
}

// records reads events by id, keeping the order of ids.
func (r *Repository) records(ctx context.Context, ids []int64) ([]Record, error) {
	if len(ids) == 0 {
		return []Record{}, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := `SELECT ` + recordCols + ` FROM events e LEFT JOIN sources so ON so.id = e.source_id WHERE e.id IN (` +
		strings.TrimSuffix(strings.Repeat("?, ", len(ids)), ", ") + `) ORDER BY e.timestamp DESC, e.id DESC`
	return r.scanRecords(ctx, q, args...)
}

const recordCols = `e.id, e.timestamp, e.category_uid, e.class_uid, e.severity_id,
		e.src_ip, e.dst_ip, e.user_name, e.raw_data,
		e.source, e.host, e.src_country, e.dst_country, e.src_asn, e.dst_asn, e.threat, e.enrichment, e.sample,
		e.source_id, COALESCE(so.name, ''), e.fields`

func (r *Repository) scanRecords(ctx context.Context, q string, args ...any) ([]Record, error) {
	rows, err := r.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var rec Record
		var src, dst, user, source, host, srcCC, dstCC, enrichment, fields sql.NullString
		var srcASN, dstASN, sourceID sql.NullInt64
		if err := rows.Scan(&rec.ID, &rec.Timestamp, &rec.CategoryUID, &rec.ClassUID,
			&rec.SeverityID, &src, &dst, &user, &rec.RawData,
			&source, &host, &srcCC, &dstCC, &srcASN, &dstASN, &rec.Threat, &enrichment, &rec.Sample,
			&sourceID, &rec.SourceName, &fields); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		rec.SrcIP, rec.DstIP, rec.UserName = src.String, dst.String, user.String
		rec.Source, rec.Host, rec.SrcCountry, rec.DstCountry = source.String, host.String, srcCC.String, dstCC.String
		rec.SrcASN, rec.DstASN = int(srcASN.Int64), int(dstASN.Int64)
		if enrichment.Valid {
			rec.Enrichment = json.RawMessage(enrichment.String)
		}
		if fields.Valid {
			rec.Fields = json.RawMessage(fields.String)
		}
		rec.SourceID = sourceID.Int64
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search rows: %w", err)
	}
	return out, nil
}

func whereSQL(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

func andSQL(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " AND " + strings.Join(where, " AND ")
}

// filterWhere is the conditions on events (e) for everything in f except
// the text search.
func filterWhere(f Filter) ([]string, []any) {
	where, args := sourceWhere(f, nil, nil)
	if f.StartMs > 0 {
		where = append(where, "e.timestamp >= ?")
		args = append(args, f.StartMs)
	}
	if f.EndMs > 0 {
		where = append(where, "e.timestamp <= ?")
		args = append(args, f.EndMs)
	}
	if f.CategoryUID != nil {
		where = append(where, "e.category_uid = ?")
		args = append(args, *f.CategoryUID)
	}
	if f.ClassUID != nil {
		where = append(where, "e.class_uid = ?")
		args = append(args, *f.ClassUID)
	}
	if f.SeverityID != nil {
		where = append(where, "e.severity_id = ?")
		args = append(args, *f.SeverityID)
	}
	if f.SrcIP != "" {
		where = append(where, "e.src_ip = ?")
		args = append(args, f.SrcIP)
	}
	if f.DstIP != "" {
		where = append(where, "e.dst_ip = ?")
		args = append(args, f.DstIP)
	}
	if f.UserName != "" {
		where = append(where, "e.user_name = ?")
		args = append(args, f.UserName)
	}
	if f.Source != "" {
		where = append(where, "e.source = ?")
		args = append(args, f.Source)
	}
	if f.Host != "" {
		where = append(where, "e.host = ?")
		args = append(args, f.Host)
	}
	if f.Country != "" {
		where = append(where, "(e.src_country = ? OR e.dst_country = ?)")
		args = append(args, f.Country, f.Country)
	}
	if f.ASN != 0 {
		where = append(where, "(e.src_asn = ? OR e.dst_asn = ?)")
		args = append(args, f.ASN, f.ASN)
	}
	if f.ThreatOnly {
		where = append(where, "e.threat = 1")
	}

	return where, args
}

// DeleteSample removes every sample event and returns how many there were.
func (r *Repository) DeleteSample(ctx context.Context) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM events WHERE sample = 1`)
	if err != nil {
		return 0, fmt.Errorf("delete sample events: %w", err)
	}
	return res.RowsAffected()
}

// CountSample returns the number of sample events.
func (r *Repository) CountSample(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sample = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sample events: %w", err)
	}
	return n, nil
}

// DeleteOlderThan deletes up to limit events with timestamp < cutoffMs and
// returns how many were removed. The AFTER DELETE trigger prunes the FTS
// index. Callers loop until the result is below limit.
func (r *Repository) DeleteOlderThan(ctx context.Context, cutoffMs int64, limit int) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`DELETE FROM events WHERE id IN
			(SELECT id FROM events WHERE timestamp < ? ORDER BY timestamp LIMIT ?)`,
		cutoffMs, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	return n, nil
}

// IncrementalVacuum returns up to pages free pages to the OS (0 = all). It
// has no effect unless the database uses auto_vacuum=INCREMENTAL.
func (r *Repository) IncrementalVacuum(ctx context.Context, pages int) error {
	// The pragma frees one page per step, so the result set must be drained
	// for it to run to completion.
	rows, err := r.db.Write.QueryContext(ctx, fmt.Sprintf("PRAGMA incremental_vacuum(%d)", max(pages, 0)))
	if err != nil {
		return fmt.Errorf("incremental vacuum: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("incremental vacuum: %w", err)
	}
	return nil
}

// Checkpoint truncates the WAL file after a large delete.
func (r *Repository) Checkpoint(ctx context.Context) error {
	rows, err := r.db.Write.QueryContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	if err != nil {
		return fmt.Errorf("wal checkpoint: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
	}
	return rows.Err()
}

// Stats summarizes database size for health reporting.
type Stats struct {
	Events     int64 `json:"events"`
	SizeBytes  int64 `json:"size_bytes"`
	FreePages  int64 `json:"free_pages"`
	PageSize   int64 `json:"page_size"`
	TotalPages int64 `json:"total_pages"`
}

// Stats reads row count and page statistics.
func (r *Repository) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	if err := r.db.Read.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&s.Events); err != nil {
		return s, fmt.Errorf("count events: %w", err)
	}
	pragmas := []struct {
		name string
		dst  *int64
	}{
		{"page_count", &s.TotalPages},
		{"page_size", &s.PageSize},
		{"freelist_count", &s.FreePages},
	}
	for _, p := range pragmas {
		if err := r.db.Read.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(p.dst); err != nil {
			return s, fmt.Errorf("pragma %s: %w", p.name, err)
		}
	}
	s.SizeBytes = s.TotalPages * s.PageSize
	return s, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// sourceWhere adds the single-source filter and a restricted user's limit.
func sourceWhere(f Filter, where []string, args []any) ([]string, []any) {
	if f.SourceID != 0 {
		where = append(where, "e.source_id = ?")
		args = append(args, f.SourceID)
	}
	if f.Restrict {
		if len(f.AllowedSources) == 0 {
			return append(where, "0"), args
		}
		// "+" keeps the limit from choosing the plan: the source index
		// covers a large share of events and would be sorted in full, where
		// the plan an admin gets (time, threat or search index) stops early.
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(f.AllowedSources)), ", ")
		where = append(where, "+e.source_id IN ("+marks+")")
		for _, id := range f.AllowedSources {
			args = append(args, id)
		}
	}
	return where, args
}

func nullableInt64(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullableInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
