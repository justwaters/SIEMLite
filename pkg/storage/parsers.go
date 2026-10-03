package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrParserExists is returned when a parser name is taken.
var ErrParserExists = errors.New("a parser with that name already exists")

// StoredParser is a saved parser. Definition is the parser's JSON, which
// pkg/parser understands; storage treats it as opaque.
type StoredParser struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"-"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	UsedBy     int    `json:"used_by"` // number of sources using it
}

const parserCols = `p.id, p.name, p.definition, p.created_at, p.updated_at,
	(SELECT COUNT(*) FROM sources s WHERE s.parser_id = p.id AND s.revoked_at IS NULL) FROM parsers p`

func scanParser(row interface{ Scan(...any) error }) (*StoredParser, error) {
	var p StoredParser
	if err := row.Scan(&p.ID, &p.Name, &p.Definition, &p.CreatedAt, &p.UpdatedAt, &p.UsedBy); err != nil {
		return nil, err
	}
	return &p, nil
}

func uniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateParser stores a parser and returns its id.
func (r *Repository) CreateParser(ctx context.Context, name, definition string, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO parsers (name, definition, created_at, updated_at) VALUES (?, ?, ?, ?)`, name, definition, nowMs, nowMs)
	if uniqueErr(err) {
		return 0, ErrParserExists
	}
	if err != nil {
		return 0, fmt.Errorf("create parser: %w", err)
	}
	return res.LastInsertId()
}

// UpdateParser replaces a parser's name and definition.
func (r *Repository) UpdateParser(ctx context.Context, id int64, name, definition string, nowMs int64) error {
	res, err := r.db.Write.ExecContext(ctx,
		`UPDATE parsers SET name = ?, definition = ?, updated_at = ? WHERE id = ?`, name, definition, nowMs, id)
	if uniqueErr(err) {
		return ErrParserExists
	}
	if err != nil {
		return fmt.Errorf("update parser: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrParserNotFound
	}
	return nil
}

// GetParser returns one parser.
func (r *Repository) GetParser(ctx context.Context, id int64) (*StoredParser, error) {
	p, err := scanParser(r.db.Read.QueryRowContext(ctx, `SELECT `+parserCols+` WHERE p.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrParserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get parser: %w", err)
	}
	return p, nil
}

// ListParsers returns every parser by name.
func (r *Repository) ListParsers(ctx context.Context) ([]StoredParser, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+parserCols+` ORDER BY p.name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("list parsers: %w", err)
	}
	defer rows.Close()
	var out []StoredParser
	for rows.Next() {
		p, err := scanParser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// DeleteParser removes a parser; sources using it fall back to automatic
// parsing.
func (r *Repository) DeleteParser(ctx context.Context, id int64) error {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM parsers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete parser: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrParserNotFound
	}
	return nil
}
