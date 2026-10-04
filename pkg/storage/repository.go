package storage

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// InsertBatch stores records, each in its day's file.
func (r *Repository) InsertBatch(ctx context.Context, recs []Record) error {
	return r.db.days.insert(ctx, recs, false)
}

// hit is a matching event: its row in a shard and its time.
type hit struct {
	sh     *shard
	id, ts int64
}

// newestFirst orders hits by time, then id, newest first.
func newestFirst(a, b hit) int {
	if a.ts != b.ts {
		return cmp.Compare(b.ts, a.ts)
	}
	return cmp.Compare(b.sh.globalID(b.id), a.sh.globalID(a.id))
}

// Search runs the filter, newest events first. It reads the days newest
// first and stops as soon as the page is full of events newer than anything
// an older day can hold.
func (r *Repository) Search(ctx context.Context, f Filter) ([]Record, error) {
	d := r.db.days
	d.move.RLock()
	defer d.move.RUnlock()
	need := f.Offset + f.Limit
	if f.Limit <= 0 {
		return []Record{}, nil
	}
	if f.Match != "" {
		// Check the expression even when no day holds events yet, using the
		// main database's (normally empty) search index.
		if err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM events_fts WHERE events_fts MATCH ? LIMIT 1)`,
			f.Match).Scan(new(int)); err != nil {
			return nil, fmt.Errorf("search: %w", err)
		}
	}
	// Days are searched newest first in waves: the first alone (the newest
	// page is usually all in it), then several at a time, so a search for
	// something rare doesn't wait on each day in turn. Before each wave, stop
	// if the page is already full of events newer than that wave can hold.
	var hits []hit
	shards := d.span(f.StartMs, f.EndMs)
	for i, wave := 0, 1; i < len(shards); i, wave = i+wave, searchWave {
		if s := shards[i]; s.day != 0 && len(hits) >= need && hits[need-1].ts >= dayEnd(s.day) {
			break
		}
		group := shards[i:min(i+wave, len(shards))]
		found := make([][]hit, len(group))
		errs := make([]error, len(group))
		var wg sync.WaitGroup
		for j, s := range group {
			wg.Add(1)
			go func() {
				defer wg.Done()
				found[j], errs[j] = r.searchShard(ctx, s, f, need)
			}()
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			return nil, fmt.Errorf("search: %w", err)
		}
		for _, hs := range found {
			hits = append(hits, hs...)
		}
		slices.SortFunc(hits, newestFirst)
		hits = hits[:min(len(hits), need)]
	}
	if f.Offset >= len(hits) {
		return []Record{}, nil
	}
	return r.records(ctx, hits[f.Offset:])
}

// searchShard returns up to k of a shard's matching events, newest first.
func (r *Repository) searchShard(ctx context.Context, s *shard, f Filter, k int) ([]hit, error) {
	db, err := s.reader()
	if err != nil {
		return nil, err
	}
	where, args := filterWhere(f)
	if lw, la := r.db.days.legacyWhere(s); lw != "" {
		where, args = append(where, lw), append(args, la...)
	}
	from := "events e"
	if f.Match != "" {
		// Sorting every match by time reads each matching event, which is
		// slow for a common word. denseHits avoids that, but walks the time
		// index back as far as the page reaches, which is short only when
		// matches are common. Count enough to tell.
		need := max(denseMatches, denseFactor*k)
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT rowid FROM events_fts WHERE events_fts MATCH ? LIMIT ?)`,
			f.Match, need).Scan(&n); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil // nothing in this day matches the words
		}
		if n >= need {
			return denseHits(ctx, db, s, f, where, args, k)
		}
		from = "events_fts JOIN events e ON e.id = events_fts.rowid"
		where = append([]string{"events_fts MATCH ?"}, where...)
		args = append([]any{f.Match}, args...)
	}
	return readHits(ctx, db, s, `SELECT e.id, e.timestamp FROM `+from+whereSQL(where)+
		` ORDER BY e.timestamp DESC, e.id DESC LIMIT ?`, append(args, k)...)
}

func readHits(ctx context.Context, db *sql.DB, s *shard, q string, args ...any) ([]hit, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hit
	for rows.Next() {
		h := hit{sh: s}
		if err := rows.Scan(&h.id, &h.ts); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// A shard search uses denseHits when it has at least denseMatches matches and
// denseFactor times the events up to the end of the page; then the walk back
// through time covers at most about 1/denseFactor of the events.
var (
	denseMatches = 2000 // variables so tests can change them
	denseFactor  = 20
)

// denseHits returns the newest k matches of a search that matches many
// events in a shard, without reading every match. Row ids grow as events are
// stored, so the newest ids are nearly the newest events:
//
//  1. Read matches newest id first (the search index can do this lazily)
//     until there are k that pass the filters: the candidates.
//  2. An event belongs among them instead of a candidate only if it is at
//     least as new as the k-th newest candidate, yet has a smaller id than
//     every candidate (a late arrival with an old timestamp, or a clock
//     running ahead). Those are found by walking the time index back to that
//     time, which is short.
//
// The result is exactly what sorting every match would give.
func denseHits(ctx context.Context, db *sql.DB, s *shard, f Filter, where []string, args []any, k int) ([]hit, error) {
	bound := int64(math.MaxInt64)
	if f.StartMs > 0 || f.EndMs > 0 {
		// No event in the time range has a larger id than this.
		end := f.EndMs
		if end <= 0 {
			end = math.MaxInt64
		}
		var maxID sql.NullInt64
		if err := db.QueryRowContext(ctx, `SELECT MAX(id) FROM events INDEXED BY idx_events_ts WHERE timestamp >= ? AND timestamp <= ?`,
			f.StartMs, end).Scan(&maxID); err != nil {
			return nil, err
		}
		if !maxID.Valid {
			return nil, nil
		}
		bound = maxID.Int64
	}
	// CROSS JOIN keeps the search index as the outer loop, read newest id first.
	cand, err := readHits(ctx, db, s, `SELECT e.id, e.timestamp FROM events_fts CROSS JOIN events e ON e.id = events_fts.rowid
		WHERE events_fts MATCH ? AND events_fts.rowid <= ?`+andSQL(where)+` ORDER BY events_fts.rowid DESC LIMIT ?`,
		append(append([]any{f.Match, bound}, args...), k)...)
	if err != nil {
		return nil, err
	}
	if len(cand) == k {
		slices.SortFunc(cand, newestFirst)
		oldest, minID := cand[k-1].ts, cand[0].id
		for _, h := range cand {
			minID = min(minID, h.id)
		}
		late, err := readHits(ctx, db, s, `SELECT e.id, e.timestamp FROM events e INDEXED BY idx_events_ts
			WHERE e.timestamp >= ? AND e.id < ?`+andSQL(where)+`
			AND EXISTS (SELECT 1 FROM events_fts WHERE events_fts MATCH ? AND events_fts.rowid = e.id)`,
			append(append([]any{oldest, minID}, args...), f.Match)...)
		if err != nil {
			return nil, err
		}
		cand = append(cand, late...)
	}
	slices.SortFunc(cand, newestFirst)
	return cand[:min(len(cand), k)], nil
}

// records reads the events for hits, in the hits' order.
func (r *Repository) records(ctx context.Context, hits []hit) ([]Record, error) {
	names, err := r.sourceNames(ctx)
	if err != nil {
		return nil, err
	}
	byShard := map[*shard][]int64{}
	for _, h := range hits {
		byShard[h.sh] = append(byShard[h.sh], h.id)
	}
	found := map[int64]Record{}
	for s, ids := range byShard {
		db, err := s.reader()
		if err != nil {
			return nil, err
		}
		args := make([]any, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		recs, err := scanRecords(ctx, db, `SELECT `+recordCols+` FROM events e WHERE e.id IN (`+
			strings.TrimSuffix(strings.Repeat("?, ", len(ids)), ", ")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			rec.ID = s.globalID(rec.ID)
			rec.SourceName = names[rec.SourceID]
			found[rec.ID] = rec
		}
	}
	out := make([]Record, 0, len(hits))
	for _, h := range hits {
		if rec, ok := found[h.sh.globalID(h.id)]; ok { // gone if deleted meanwhile
			out = append(out, rec)
		}
	}
	return out, nil
}

// sourceNames maps source ids to names.
func (r *Repository) sourceNames(ctx context.Context) (map[int64]string, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, name FROM sources`)
	if err != nil {
		return nil, fmt.Errorf("source names: %w", err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// searchWave is how many days a search reads at once after the newest.
const searchWave = 4

// recordCols are an event's columns, minus the source name (sources live in
// the main database).
const recordCols = `e.id, e.timestamp, e.category_uid, e.class_uid, e.severity_id,
		e.src_ip, e.dst_ip, e.user_name, e.raw_data,
		e.source, e.host, e.src_country, e.dst_country, e.src_asn, e.dst_asn, e.threat, e.enrichment,
		e.source_id, e.fields`

func scanRecords(ctx context.Context, db *sql.DB, q string, args ...any) ([]Record, error) {
	rows, err := db.QueryContext(ctx, q, args...)
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
			&source, &host, &srcCC, &dstCC, &srcASN, &dstASN, &rec.Threat, &enrichment,
			&sourceID, &fields); err != nil {
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

// DeleteOlderThan deletes events with timestamp < cutoffMs and returns how
// many were removed: whole days by deleting their files, then up to limit
// from the day the cutoff falls in. Callers loop until the result is below
// limit.
func (r *Repository) DeleteOlderThan(ctx context.Context, cutoffMs int64, limit int) (int64, error) {
	d := r.db.days
	cutDay := dayOf(cutoffMs)
	var total int64
	d.move.RLock()
	all := d.span(0, 0)
	d.move.RUnlock()
	for _, s := range all {
		if s.day == 0 || s.day >= cutDay {
			continue
		}
		n, err := d.countShard(ctx, s)
		if err != nil {
			return total, err
		}
		// No search is reading the file and no batch is writing to it (the
		// same order as moving events takes these locks).
		d.move.Lock()
		d.writeMu.Lock()
		err = d.remove(s.day)
		d.writeMu.Unlock()
		d.move.Unlock()
		if err != nil {
			return total, fmt.Errorf("delete %s: %w", filepath.Base(s.path), err)
		}
		total += n
	}
	if total > 0 {
		return total, nil
	}
	del := func(db *sql.DB) (int64, error) {
		res, err := db.ExecContext(ctx, `DELETE FROM events WHERE id IN
			(SELECT id FROM events WHERE timestamp < ? ORDER BY timestamp LIMIT ?)`, cutoffMs, limit)
		if err != nil {
			return 0, fmt.Errorf("delete expired: %w", err)
		}
		return res.RowsAffected()
	}
	if s := d.shard(cutDay, false); s != nil && dayStart(cutDay) < cutoffMs {
		w, err := s.writer(ctx)
		if err != nil {
			return 0, err
		}
		n, err := del(w)
		if err != nil {
			return 0, err
		}
		s.count.Store(-1)
		total += n
	}
	d.move.RLock()
	legacy := d.legacy != nil
	d.move.RUnlock()
	if legacy && total < int64(limit) {
		n, err := del(r.db.Write)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// IncrementalVacuum returns up to pages free pages of the main database to
// the OS (0 = all). Day files don't need it: they are deleted whole.
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

// Checkpoint truncates the main database's WAL file after a large delete.
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

// Stats summarizes storage for health reporting.
type Stats struct {
	Events     int64 `json:"events"`
	SizeBytes  int64 `json:"size_bytes"` // the main database and every day file
	Days       int   `json:"days"`       // day files
	FreePages  int64 `json:"free_pages"` // of the main database
	PageSize   int64 `json:"page_size"`
	TotalPages int64 `json:"total_pages"`
}

// Stats counts events and adds up file sizes.
func (r *Repository) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	d := r.db.days
	d.move.RLock()
	for _, s := range d.span(0, 0) {
		n, err := d.countShard(ctx, s)
		if err != nil {
			d.move.RUnlock()
			return st, fmt.Errorf("count events: %w", err)
		}
		st.Events += n
		if s.day != 0 {
			st.Days++
			st.SizeBytes += fileSize(s.path)
		}
	}
	d.move.RUnlock()
	pragmas := []struct {
		name string
		dst  *int64
	}{
		{"page_count", &st.TotalPages},
		{"page_size", &st.PageSize},
		{"freelist_count", &st.FreePages},
	}
	for _, p := range pragmas {
		if err := r.db.Read.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(p.dst); err != nil {
			return st, fmt.Errorf("pragma %s: %w", p.name, err)
		}
	}
	st.SizeBytes += st.TotalPages * st.PageSize
	return st, nil
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
