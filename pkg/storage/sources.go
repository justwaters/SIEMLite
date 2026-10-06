package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Source kinds. Tokens are created by admins; the others exist once each.
const (
	SourceToken    = "token"    // an access token an application sends logs with
	SourceSyslog   = "syslog"   // the syslog listeners
	SourceUpload   = "upload"   // logs pasted or uploaded in the web UI
	SourceInternal = "internal" // SIEMLite's own audit log
)

var (
	ErrSourceNotFound = errors.New("source not found")
	ErrParserNotFound = errors.New("parser not found")
	ErrBuiltinSource  = errors.New("built-in sources can't be disabled, enabled or deleted")
)

// SourceInUseError says alert rules are scoped to a source, so it can't be deleted.
type SourceInUseError struct{ Rules []string }

func (e *SourceInUseError) Error() string {
	return "Alert rules use this source: " + strings.Join(e.Rules, ", ") + ". Change those rules first."
}

// Source is somewhere events come from. Only a SHA-256 of a token is stored.
type Source struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	ParserID   *int64 `json:"parser_id,omitempty"`
	ParserName string `json:"parser_name,omitempty"`
	ParserNone bool   `json:"parser_none"` // lines are stored as they arrive, with no detection
	CreatedAt  int64  `json:"created_at"`
	RevokedAt  *int64 `json:"revoked_at,omitempty"` // set while the token is disabled
	Enabled    bool   `json:"enabled"`              // false while a token is disabled
	LastUsedAt *int64 `json:"last_used_at,omitempty"`
}

const sourceCols = `s.id, s.name, s.kind, s.parser_id, COALESCE(p.name, ''), s.parser_none, s.created_at, s.revoked_at, s.last_used_at
	FROM sources s LEFT JOIN parsers p ON p.id = s.parser_id`

func scanSource(row interface{ Scan(...any) error }) (*Source, error) {
	var s Source
	var parser, revoked, used sql.NullInt64
	if err := row.Scan(&s.ID, &s.Name, &s.Kind, &parser, &s.ParserName, &s.ParserNone, &s.CreatedAt, &revoked, &used); err != nil {
		return nil, err
	}
	if parser.Valid {
		s.ParserID = &parser.Int64
	}
	if revoked.Valid {
		s.RevokedAt = &revoked.Int64
	}
	s.Enabled = !revoked.Valid
	if used.Valid {
		s.LastUsedAt = &used.Int64
	}
	return &s, nil
}

// CreateTokenSource stores a new access token source and returns its id.
// parserNone keeps its lines as they arrive; it can't be combined with a parser.
func (r *Repository) CreateTokenSource(ctx context.Context, name, keyHash string, parserID *int64, parserNone bool, nowMs int64) (int64, error) {
	if parserNone && parserID != nil {
		return 0, errors.New("a source can't have a parser and parser_none together")
	}
	res, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO sources (name, kind, key_hash, parser_id, parser_none, created_at) VALUES (?, 'token', ?, ?, ?, ?)`,
		name, keyHash, parserID, parserNone, nowMs)
	if err != nil {
		return 0, fmt.Errorf("create source: %w", err)
	}
	return res.LastInsertId()
}

// FindActiveToken returns the unrevoked token source with this key hash.
func (r *Repository) FindActiveToken(ctx context.Context, keyHash string) (*Source, error) {
	s, err := scanSource(r.db.Read.QueryRowContext(ctx,
		`SELECT `+sourceCols+` WHERE s.key_hash = ? AND s.kind = 'token' AND s.revoked_at IS NULL`, keyHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find token: %w", err)
	}
	return s, nil
}

// GetSource returns one source.
func (r *Repository) GetSource(ctx context.Context, id int64) (*Source, error) {
	s, err := scanSource(r.db.Read.QueryRowContext(ctx, `SELECT `+sourceCols+` WHERE s.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get source: %w", err)
	}
	return s, nil
}

// BuiltinSource returns the syslog, upload or INTERNAL source.
func (r *Repository) BuiltinSource(ctx context.Context, kind string) (*Source, error) {
	s, err := scanSource(r.db.Read.QueryRowContext(ctx, `SELECT `+sourceCols+` WHERE s.kind = ?`, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get %s source: %w", kind, err)
	}
	return s, nil
}

// ListSources returns every source, built-in ones first, then tokens by id.
func (r *Repository) ListSources(ctx context.Context) ([]Source, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+sourceCols+`
		ORDER BY CASE s.kind WHEN 'token' THEN 1 ELSE 0 END, s.id`)
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		s, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// UpdateSource renames a token source and/or sets any source's parser.
// clearParser removes the parser (the source then uses automatic parsing).
// parserNone true keeps lines as they arrive (and drops any parser); choosing
// a parser or clearParser turns it off again, as does parserNone false.
func (r *Repository) UpdateSource(ctx context.Context, id int64, name *string, parserID *int64, clearParser bool, parserNone *bool) error {
	s, err := r.GetSource(ctx, id)
	if err != nil {
		return err
	}
	none := parserNone != nil && *parserNone
	if none && parserID != nil {
		return errors.New("a source can't have a parser and parser_none together")
	}
	if none && s.Kind == SourceInternal {
		return errors.New("the built-in INTERNAL source doesn't use a parser")
	}
	if name != nil {
		if s.Kind != SourceToken {
			return errors.New("built-in sources can't be renamed")
		}
		if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET name = ? WHERE id = ?`, *name, id); err != nil {
			return fmt.Errorf("rename source: %w", err)
		}
	}
	switch {
	case none:
		if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET parser_id = NULL, parser_none = 1 WHERE id = ?`, id); err != nil {
			return fmt.Errorf("set parser: %w", err)
		}
	case parserID != nil || clearParser:
		if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET parser_id = ?, parser_none = 0 WHERE id = ?`, parserID, id); err != nil {
			return fmt.Errorf("set parser: %w", err)
		}
	case parserNone != nil:
		if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET parser_none = 0 WHERE id = ?`, id); err != nil {
			return fmt.Errorf("set parser: %w", err)
		}
	}
	return nil
}

// tokenSource returns the source with this id, or an error if it is missing
// or isn't an access token.
func (r *Repository) tokenSource(ctx context.Context, id int64) (*Source, error) {
	s, err := r.GetSource(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.Kind != SourceToken {
		return nil, ErrBuiltinSource
	}
	return s, nil
}

// SetSourceEnabled enables or disables an access token. A disabled token is
// rejected but the source, its token and its events are kept; enabling it
// makes the same token work again.
func (r *Repository) SetSourceEnabled(ctx context.Context, id int64, enabled bool, nowMs int64) error {
	s, err := r.tokenSource(ctx, id)
	if err != nil {
		return err
	}
	if enabled == s.Enabled {
		return nil
	}
	var revoked any
	if !enabled {
		revoked = nowMs
	}
	if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET revoked_at = ? WHERE id = ?`, revoked, id); err != nil {
		return fmt.Errorf("set source enabled: %w", err)
	}
	return nil
}

// DeleteSource removes an access token source and its token for good. Its
// events stay in the day files. It refuses (with a *SourceInUseError) while
// an alert rule is scoped to the source, as the rule would then match every
// source.
func (r *Repository) DeleteSource(ctx context.Context, id int64) error {
	if _, err := r.tokenSource(ctx, id); err != nil {
		return err
	}
	rows, err := r.db.Read.QueryContext(ctx, `SELECT name FROM alert_rules WHERE source_id = ? ORDER BY name COLLATE NOCASE`, id)
	if err != nil {
		return fmt.Errorf("check alert rules: %w", err)
	}
	var rules []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		rules = append(rules, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(rules) > 0 {
		return &SourceInUseError{Rules: rules}
	}
	// A rule added between the check and here would lose its source (SET
	// NULL); the guard in the statement keeps that from happening.
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM sources WHERE id = ? AND kind = 'token'
		AND NOT EXISTS (SELECT 1 FROM alert_rules WHERE source_id = ?)`, id, id)
	if err != nil {
		return fmt.Errorf("delete source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return &SourceInUseError{Rules: []string{"a rule that was just added"}}
	}
	return nil
}

// TouchSource records that a source was just used.
func (r *Repository) TouchSource(ctx context.Context, id, nowMs int64) error {
	if _, err := r.db.Write.ExecContext(ctx, `UPDATE sources SET last_used_at = ? WHERE id = ?`, nowMs, id); err != nil {
		return fmt.Errorf("touch source: %w", err)
	}
	return nil
}
