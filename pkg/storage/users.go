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
	// ErrExternalUser is returned when a password is set for an account that
	// signs in elsewhere.
	ErrExternalUser = errors.New("this account signs in with another service and has no password")
)

// User is an account that can sign in to the web UI.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
	// Limited users see only events from Sources (possibly none). Admins and
	// unlimited standard users see everything.
	Limited bool    `json:"limited"`
	Sources []int64 `json:"sources"`
	// AuthProvider is "local" (a password) or the integration that signs the
	// person in. ExternalID identifies them there. A Disabled account can't
	// sign in.
	AuthProvider string `json:"auth_provider"`
	ExternalID   string `json:"-"`
	Disabled     bool   `json:"disabled"`
}

// Sign-in providers.
const ProviderLocal = "local"

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
		`SELECT id, username, role, created_at, password_hash, auth_provider, disabled FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &hash, &u.AuthProvider, &u.Disabled)
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
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, username, role, limited, created_at, auth_provider, external_id, disabled FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Limited, &u.CreatedAt, &u.AuthProvider, &u.ExternalID, &u.Disabled); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Sources, err = r.userSources(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *Repository) userSources(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT source_id FROM user_sources WHERE user_id = ? ORDER BY source_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("user sources: %w", err)
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GetUser returns a user by id.
func (r *Repository) GetUser(ctx context.Context, id int64) (*User, error) {
	var u User
	err := r.db.Read.QueryRowContext(ctx, `SELECT id, username, role, limited, created_at, auth_provider, external_id, disabled FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.Limited, &u.CreatedAt, &u.AuthProvider, &u.ExternalID, &u.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if u.Sources, err = r.userSources(ctx, id); err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUserAccess sets a user's role, whether they are limited to some
// sources, and which. Admins always see everything, so their limit and
// source list are cleared. It refuses to demote the last admin.
func (r *Repository) UpdateUserAccess(ctx context.Context, id int64, role string, limited bool, sources []int64) error {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if current == "admin" && role != "admin" {
		if err := lastAdminCheck(ctx, tx); err != nil {
			return err
		}
	}
	limited = limited && role != "admin"
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, limited = ? WHERE id = ?`, role, limited, id); err != nil {
		return fmt.Errorf("set role: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_sources WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("clear sources: %w", err)
	}
	if limited {
		for _, sid := range sources {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO user_sources (user_id, source_id) VALUES (?, ?)`, id, sid); err != nil {
				return fmt.Errorf("add source %d: %w", sid, err)
			}
		}
	}
	return tx.Commit()
}

// ErrLastAdmin protects against locking everyone out.
var ErrLastAdmin = errors.New("there must always be at least one admin")

func lastAdminCheck(ctx context.Context, tx *sql.Tx) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n); err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if n <= 1 {
		return ErrLastAdmin
	}
	return nil
}

// DeleteUserByID removes a user (sessions and source limits cascade). It
// refuses to delete the last admin.
func (r *Repository) DeleteUserByID(ctx context.Context, id int64) error {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, id).Scan(&role); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if role == "admin" {
		if err := lastAdminCheck(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return tx.Commit()
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
	var provider string
	if err := tx.QueryRowContext(ctx, `SELECT auth_provider FROM users WHERE username = ?`, username).Scan(&provider); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("get user: %w", err)
	}
	if provider != ProviderLocal {
		return false, ErrExternalUser
	}
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

// DeleteUser removes a user by name; see DeleteUserByID.
func (r *Repository) DeleteUser(ctx context.Context, username string) (bool, error) {
	var id int64
	err := r.db.Read.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find user: %w", err)
	}
	if err := r.DeleteUserByID(ctx, id); err != nil {
		return false, err
	}
	return true, nil
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
		`SELECT u.id, u.username, u.role, u.limited, u.created_at, u.auth_provider FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`,
		tokenHash, nowMs).Scan(&u.ID, &u.Username, &u.Role, &u.Limited, &u.CreatedAt, &u.AuthProvider)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}
	if u.Sources, err = r.userSources(ctx, u.ID); err != nil {
		return nil, err
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

// FindExternalUser returns the account for a person at a sign-in provider.
func (r *Repository) FindExternalUser(ctx context.Context, provider, externalID string) (*User, error) {
	var id int64
	err := r.db.Read.QueryRowContext(ctx, `SELECT id FROM users WHERE auth_provider = ? AND external_id = ?`, provider, externalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	return r.GetUser(ctx, id)
}

// CreateExternalUser adds an account that signs in through a provider. It has
// no usable password. ErrUserExists means the name is taken (by a local
// account or another person); the caller must not take it over.
func (r *Repository) CreateExternalUser(ctx context.Context, provider, externalID, username, role string, nowMs int64) (int64, error) {
	if provider == ProviderLocal || externalID == "" {
		return 0, errors.New("an external account needs a provider and an external id")
	}
	res, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, created_at, auth_provider, external_id) VALUES (?, '!', ?, ?, ?, ?)`,
		username, role, nowMs, provider, externalID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrUserExists
		}
		return 0, fmt.Errorf("create user: %w", err)
	}
	return res.LastInsertId()
}

// ListExternalUsers returns the accounts that sign in through a provider.
func (r *Repository) ListExternalUsers(ctx context.Context, provider string) ([]User, error) {
	all, err := r.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	var out []User
	for _, u := range all {
		if u.AuthProvider == provider {
			out = append(out, u)
		}
	}
	return out, nil
}

// SetUserDisabled disables or re-enables an account. Disabling ends its
// sessions, and is refused for the last enabled admin.
func (r *Repository) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	var was bool
	if err := tx.QueryRowContext(ctx, `SELECT role, disabled FROM users WHERE id = ?`, id).Scan(&role, &was); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if was == disabled {
		return nil
	}
	if disabled && role == "admin" {
		if err := lastAdminCheck(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id); err != nil {
		return fmt.Errorf("set disabled: %w", err)
	}
	if disabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return fmt.Errorf("clear sessions: %w", err)
		}
	}
	return tx.Commit()
}

// DeleteSessionsByProvider ends every session of the accounts that sign in
// through a provider, and returns how many there were.
func (r *Repository) DeleteSessionsByProvider(ctx context.Context, provider string) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE auth_provider = ?)`, provider)
	if err != nil {
		return 0, fmt.Errorf("clear sessions: %w", err)
	}
	return res.RowsAffected()
}

// CountEnabledAdmins returns how many enabled admins sign in through a provider.
func (r *Repository) CountEnabledAdmins(ctx context.Context, provider string) (int, error) {
	var n int
	if err := r.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND auth_provider = ?`, provider).Scan(&n); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return n, nil
}
