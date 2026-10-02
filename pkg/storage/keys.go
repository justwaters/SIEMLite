package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrKeyNotFound is returned when no active key matches.
var ErrKeyNotFound = errors.New("api key not found")

// APIKey is the stored metadata of a key; the secret itself is never stored.
type APIKey struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
	RevokedAt *int64 `json:"revoked_at,omitempty"`
}

// CreateKey stores a new key by its hash and returns its id.
func (r *Repository) CreateKey(ctx context.Context, name, role, hash string, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO api_keys (name, role, key_hash, created_at) VALUES (?, ?, ?, ?)`,
		name, role, hash, nowMs)
	if err != nil {
		return 0, fmt.Errorf("create api key: %w", err)
	}
	return res.LastInsertId()
}

// FindActiveKey looks up a non-revoked key by hash.
func (r *Repository) FindActiveKey(ctx context.Context, hash string) (*APIKey, error) {
	var k APIKey
	err := r.db.Read.QueryRowContext(ctx,
		`SELECT id, name, role, created_at FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`,
		hash).Scan(&k.ID, &k.Name, &k.Role, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find api key: %w", err)
	}
	return &k, nil
}

// ListKeys returns all keys, including revoked ones.
func (r *Repository) ListKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := r.db.Read.QueryContext(ctx,
		`SELECT id, name, role, created_at, revoked_at FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var revoked sql.NullInt64
		if err := rows.Scan(&k.ID, &k.Name, &k.Role, &k.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			k.RevokedAt = &revoked.Int64
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeKey marks a key revoked; it reports whether an active key was found.
func (r *Repository) RevokeKey(ctx context.Context, id, nowMs int64) (bool, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, nowMs, id)
	if err != nil {
		return false, fmt.Errorf("revoke api key: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CountActiveKeys returns the number of non-revoked keys.
func (r *Repository) CountActiveKeys(ctx context.Context) (int, error) {
	var n int
	if err := r.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count api keys: %w", err)
	}
	return n, nil
}
