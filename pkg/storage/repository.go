package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	Match       string // raw FTS5 MATCH expression
	Limit       int
	Offset      int
}

// Repository provides data access over a DB.
type Repository struct {
	db *DB
}

// NewRepository returns a Repository backed by db.
func NewRepository(db *DB) *Repository { return &Repository{db: db} }

const insertSQL = `INSERT INTO events
	(timestamp, category_uid, class_uid, severity_id, src_ip, dst_ip, user_name, raw_data,
	 source, host, src_country, dst_country, src_asn, dst_asn, threat, enrichment)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
			nullableInt(rec.SrcASN), nullableInt(rec.DstASN), rec.Threat, nullable(string(rec.Enrichment)),
		); err != nil {
			return fmt.Errorf("insert record %d: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// Search runs the filter, newest events first. When f.Match is set the query
// joins events_fts to events on rowid.
func (r *Repository) Search(ctx context.Context, f Filter) ([]Record, error) {
	query, args := buildSearch(f)
	rows, err := r.db.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer rows.Close()

	out := make([]Record, 0, min(max(f.Limit, 0), 1000))
	for rows.Next() {
		var rec Record
		var src, dst, user, source, host, srcCC, dstCC, enrichment sql.NullString
		var srcASN, dstASN sql.NullInt64
		if err := rows.Scan(&rec.ID, &rec.Timestamp, &rec.CategoryUID, &rec.ClassUID,
			&rec.SeverityID, &src, &dst, &user, &rec.RawData,
			&source, &host, &srcCC, &dstCC, &srcASN, &dstASN, &rec.Threat, &enrichment); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		rec.SrcIP, rec.DstIP, rec.UserName = src.String, dst.String, user.String
		rec.Source, rec.Host, rec.SrcCountry, rec.DstCountry = source.String, host.String, srcCC.String, dstCC.String
		rec.SrcASN, rec.DstASN = int(srcASN.Int64), int(dstASN.Int64)
		if enrichment.Valid {
			rec.Enrichment = json.RawMessage(enrichment.String)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search rows: %w", err)
	}
	return out, nil
}

func buildSearch(f Filter) (string, []any) {
	var (
		sb    strings.Builder
		where []string
		args  []any
	)
	sb.WriteString(`SELECT e.id, e.timestamp, e.category_uid, e.class_uid, e.severity_id,
		e.src_ip, e.dst_ip, e.user_name, e.raw_data,
		e.source, e.host, e.src_country, e.dst_country, e.src_asn, e.dst_asn, e.threat, e.enrichment FROM `)

	if f.Match != "" {
		sb.WriteString("events_fts JOIN events e ON e.id = events_fts.rowid")
		where = append(where, "events_fts MATCH ?")
		args = append(args, f.Match)
	} else {
		sb.WriteString("events e")
	}

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

	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(where, " AND "))
	}
	sb.WriteString(" ORDER BY e.timestamp DESC, e.id DESC LIMIT ? OFFSET ?")
	args = append(args, f.Limit, f.Offset)
	return sb.String(), args
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

func nullableInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
