package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaVersion is stored in PRAGMA user_version.
const schemaVersion = 6

// schemaStatements is the idempotent DDL applied on startup.
//
// events_fts is an external-content FTS5 table: it stores only the inverted
// index and reads text back from events, so raw_data is never duplicated. The
// triggers keep the index in sync; the 'delete' command needs the old column
// values, which is why the AFTER DELETE trigger passes old.raw_data.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp   INTEGER NOT NULL,
		category_uid INTEGER NOT NULL,
		class_uid   INTEGER NOT NULL,
		severity_id INTEGER NOT NULL,
		src_ip      TEXT,
		dst_ip      TEXT,
		user_name   TEXT,
		raw_data    TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_events_lookup ON events(timestamp DESC, category_uid, severity_id)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
		raw_data,
		content='events',
		content_rowid='id'
	)`,
	`CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
		INSERT INTO events_fts(rowid, raw_data) VALUES (new.id, new.raw_data);
	END`,
	`CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
		INSERT INTO events_fts(events_fts, rowid, raw_data) VALUES ('delete', old.id, old.raw_data);
	END`,
	// Users sign in to the web UI. Only a bcrypt hash of the password is stored.
	`CREATE TABLE IF NOT EXISTS users (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
		created_at    INTEGER NOT NULL
	)`,
	// Browser sessions; the cookie holds a random token, only its hash is stored.
	`CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,
	// Threat intel indicators. version in intel_state is bumped on every
	// change so a running server notices imports made by the CLI.
	`CREATE TABLE IF NOT EXISTS indicators (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		type        TEXT NOT NULL CHECK (type IN ('ip', 'cidr', 'domain', 'hash')),
		value       TEXT NOT NULL,
		source      TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		added_at    INTEGER NOT NULL,
		UNIQUE (source, type, value)
	)`,
	`CREATE TABLE IF NOT EXISTS intel_state (
		id      INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL
	)`,
	`INSERT OR IGNORE INTO intel_state (id, version) VALUES (1, 0)`,
}

// upgrades[v] moves a database from user_version v to v+1. ALTER TABLE is
// not idempotent, so these run once, keyed off PRAGMA user_version.
var upgrades = map[int][]string{
	// v4: reporting source/host, GeoIP/ASN and threat intel enrichment.
	3: {
		`ALTER TABLE events ADD COLUMN source TEXT`,
		`ALTER TABLE events ADD COLUMN host TEXT`,
		`ALTER TABLE events ADD COLUMN src_country TEXT`,
		`ALTER TABLE events ADD COLUMN dst_country TEXT`,
		`ALTER TABLE events ADD COLUMN src_asn INTEGER`,
		`ALTER TABLE events ADD COLUMN dst_asn INTEGER`,
		`ALTER TABLE events ADD COLUMN threat INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE events ADD COLUMN enrichment TEXT`,
		`CREATE INDEX IF NOT EXISTS idx_events_threat ON events(timestamp DESC) WHERE threat = 1`,
	},
	// v5: sample data, which the UI can load and remove without touching real events.
	4: {
		`ALTER TABLE events ADD COLUMN sample INTEGER NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_events_sample ON events(id) WHERE sample = 1`,
	},
	// v6: sources (access tokens plus built-in syslog, upload and sample
	// sources), parsers, Admin/Standard roles and per-user source limits.
	5: {
		`CREATE TABLE parsers (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
			definition TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		// Only a SHA-256 of each token is stored; the plaintext is shown once.
		`CREATE TABLE sources (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL,
			kind         TEXT NOT NULL CHECK (kind IN ('token', 'syslog', 'upload', 'sample')),
			key_hash     TEXT UNIQUE,
			parser_id    INTEGER REFERENCES parsers(id) ON DELETE SET NULL,
			created_at   INTEGER NOT NULL,
			revoked_at   INTEGER,
			last_used_at INTEGER
		)`,
		`CREATE UNIQUE INDEX idx_sources_builtin ON sources(kind) WHERE kind <> 'token'`,
		// Earlier versions' API keys become token sources with the same ids.
		// api_keys only exists in databases created before v6; v0.1 read and
		// admin keys are carried over revoked.
		`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER)`,
		`INSERT INTO sources (id, name, kind, key_hash, created_at, revoked_at)
			SELECT id, name, 'token', key_hash, created_at,
				CASE WHEN role <> 'write' AND revoked_at IS NULL THEN CAST(strftime('%s','now') AS INTEGER) * 1000 ELSE revoked_at END
			FROM api_keys`,
		`DROP TABLE api_keys`,
		`INSERT INTO sources (name, kind, created_at) VALUES
			('Syslog', 'syslog', CAST(strftime('%s','now') AS INTEGER) * 1000),
			('Added in the UI', 'upload', CAST(strftime('%s','now') AS INTEGER) * 1000),
			('Sample data', 'sample', CAST(strftime('%s','now') AS INTEGER) * 1000)`,
		// Roles become admin and standard. SQLite cannot change a CHECK
		// constraint in place, so the table is rebuilt; dropping it ends all
		// sessions (they cascade), so everyone signs in again once.
		`CREATE TABLE users_new (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL,
			role          TEXT NOT NULL CHECK (role IN ('admin', 'standard')),
			created_at    INTEGER NOT NULL
		)`,
		`INSERT INTO users_new (id, username, password_hash, role, created_at)
			SELECT id, username, password_hash, CASE role WHEN 'analyst' THEN 'standard' ELSE role END, created_at FROM users`,
		`DROP TABLE users`,
		`ALTER TABLE users_new RENAME TO users`,
		// A Standard user with rows here only sees events from those sources.
		`CREATE TABLE user_sources (
			user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, source_id)
		)`,
		`ALTER TABLE events ADD COLUMN source_id INTEGER`,
		`ALTER TABLE events ADD COLUMN fields TEXT`,
		`CREATE INDEX idx_events_source ON events(source_id, timestamp DESC)`,
		`UPDATE events SET source_id = (SELECT id FROM sources WHERE kind = 'sample') WHERE sample = 1`,
	},
}

// migrate applies the schema inside one transaction.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema tx: %w", err)
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
	}
	// A new database starts at 0 and gets the base tables above, which match
	// version 3, then every upgrade.
	for v := max(version, 3); v < schemaVersion; v++ {
		for _, stmt := range upgrades[v] {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("upgrade schema to v%d: %w", v+1, err)
			}
		}
	}
	// PRAGMA does not accept bound parameters.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}
