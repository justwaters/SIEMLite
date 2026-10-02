package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("user already exists")
)

// User is an account that can sign in to the web UI.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}

// CreateUser stores a new user with an already-hashed password.
func (r *Repository) CreateUser(ctx context.Context, username, passwordHash, role string, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, passwordHash, role, nowMs)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrUserExists
		}
		return 0, fmt.Errorf("create user: %w", err)
	}
	return res.LastInsertId()
}

// GetUserForLogin returns the user and their password hash.
func (r *Repository) GetUserForLogin(ctx context.Context, username string) (*User, string, error) {
	var u User
	var hash string
	err := r.db.Read.QueryRowContext(ctx,
		`SELECT id, username, role, created_at, password_hash FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrUserNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("get user: %w", err)
	}
	return &u, hash, nil
}

// ListUsers returns all users.
func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, username, role, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (r *Repository) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := r.db.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// SetPassword replaces a user's password hash and signs them out everywhere.
func (r *Repository) SetPassword(ctx context.Context, username, passwordHash string) (bool, error) {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE username = ?`, passwordHash, username)
	if err != nil {
		return false, fmt.Errorf("set password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)`, username); err != nil {
		return false, fmt.Errorf("clear sessions: %w", err)
	}
	return true, tx.Commit()
}

// DeleteUser removes a user and, via cascade, their sessions.
func (r *Repository) DeleteUser(ctx context.Context, username string) (bool, error) {
	res, err := r.db.Write.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return false, fmt.Errorf("delete user: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CreateSession stores a session by token hash.
func (r *Repository) CreateSession(ctx context.Context, tokenHash string, userID, nowMs, expiresMs int64) error {
	if _, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, nowMs, expiresMs); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// FindSession returns the user owning an unexpired session.
func (r *Repository) FindSession(ctx context.Context, tokenHash string, nowMs int64) (*User, error) {
	var u User
	err := r.db.Read.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.role, u.created_at FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > ?`,
		tokenHash, nowMs).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	return &u, nil
}

// DeleteSession removes one session.
func (r *Repository) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := r.db.Write.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// PurgeExpiredSessions removes sessions past their expiry.
func (r *Repository) PurgeExpiredSessions(ctx context.Context, nowMs int64) error {
	if _, err := r.db.Write.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowMs); err != nil {
		return fmt.Errorf("purge sessions: %w", err)
	}
	return nil
}
