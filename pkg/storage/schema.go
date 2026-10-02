package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaVersion is stored in PRAGMA user_version.
const schemaVersion = 2

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
	// Only a SHA-256 of each key is stored; the plaintext is shown once at creation.
	`CREATE TABLE IF NOT EXISTS api_keys (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT NOT NULL,
		role       TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')),
		key_hash   TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		revoked_at INTEGER
	)`,
}

// migrate applies the schema inside one transaction.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema tx: %w", err)
	}
	defer tx.Rollback()

	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
	}
	// PRAGMA does not accept bound parameters.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}
