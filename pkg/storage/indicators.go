package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// Indicator is one threat intel indicator of compromise.
type Indicator struct {
	Type        string `json:"type"` // ip, cidr, domain or hash
	Value       string `json:"value"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
}

// IntelSource summarizes the indicators loaded from one source.
type IntelSource struct {
	Source    string `json:"source"`
	Count     int    `json:"count"`
	UpdatedAt int64  `json:"updated_at"`
}

// ReplaceIndicators atomically swaps every indicator of source for inds, so
// a refreshed feed also drops entries that left it. inds must all carry
// source. It returns how many distinct indicators are stored.
func (r *Repository) ReplaceIndicators(ctx context.Context, source string, inds []Indicator, nowMs int64) (int, error) {
	return r.writeIndicators(ctx, source, inds, nowMs)
}

// AddIndicators inserts inds, keeping existing ones (duplicates are updated).
func (r *Repository) AddIndicators(ctx context.Context, inds []Indicator, nowMs int64) (int, error) {
	return r.writeIndicators(ctx, "", inds, nowMs)
}

func (r *Repository) writeIndicators(ctx context.Context, replace string, inds []Indicator, nowMs int64) (int, error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin indicators: %w", err)
	}
	defer tx.Rollback()

	if replace != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM indicators WHERE source = ?`, replace); err != nil {
			return 0, fmt.Errorf("clear source: %w", err)
		}
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO indicators (type, value, source, description, added_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (source, type, value) DO UPDATE SET description = excluded.description, added_at = excluded.added_at`)
	if err != nil {
		return 0, fmt.Errorf("prepare indicator: %w", err)
	}
	defer stmt.Close()
	for _, in := range inds {
		if _, err := stmt.ExecContext(ctx, in.Type, in.Value, in.Source, in.Description, nowMs); err != nil {
			return 0, fmt.Errorf("insert indicator %q: %w", in.Value, err)
		}
	}
	if err := bumpIntelVersion(ctx, tx); err != nil {
		return 0, err
	}
	var n int
	if replace != "" {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM indicators WHERE source = ?`, replace).Scan(&n); err != nil {
			return 0, fmt.Errorf("count indicators: %w", err)
		}
	} else {
		n = len(inds)
	}
	return n, tx.Commit()
}

// DeleteIndicatorSource removes every indicator of source.
func (r *Repository) DeleteIndicatorSource(ctx context.Context, source string) (int64, error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin delete indicators: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM indicators WHERE source = ?`, source)
	if err != nil {
		return 0, fmt.Errorf("delete indicators: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := bumpIntelVersion(ctx, tx); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func bumpIntelVersion(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE intel_state SET version = version + 1 WHERE id = 1`); err != nil {
		return fmt.Errorf("bump intel version: %w", err)
	}
	return nil
}

// IntelVersion returns a counter that changes whenever indicators change.
func (r *Repository) IntelVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := r.db.Read.QueryRowContext(ctx, `SELECT version FROM intel_state WHERE id = 1`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read intel version: %w", err)
	}
	return v, nil
}

// AllIndicators returns every stored indicator.
func (r *Repository) AllIndicators(ctx context.Context) ([]Indicator, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT type, value, source, description FROM indicators`)
	if err != nil {
		return nil, fmt.Errorf("list indicators: %w", err)
	}
	defer rows.Close()
	var out []Indicator
	for rows.Next() {
		var in Indicator
		if err := rows.Scan(&in.Type, &in.Value, &in.Source, &in.Description); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// ListIntelSources returns one summary row per indicator source.
func (r *Repository) ListIntelSources(ctx context.Context) ([]IntelSource, error) {
	rows, err := r.db.Read.QueryContext(ctx,
		`SELECT source, COUNT(*), MAX(added_at) FROM indicators GROUP BY source ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("list intel sources: %w", err)
	}
	defer rows.Close()
	var out []IntelSource
	for rows.Next() {
		var s IntelSource
		if err := rows.Scan(&s.Source, &s.Count, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
