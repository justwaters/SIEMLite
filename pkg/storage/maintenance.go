package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SchemaVersion is the database format this build reads and writes.
const SchemaVersion = schemaVersion

// Path is the database file.
func (d *DB) Path() string { return d.path }

// A snapshot (and a backup) is a folder holding the main database as
// MainFile and each day as EventsFolder/YYYY-MM-DD.db.
const (
	MainFile     = "siemlite.db"
	EventsFolder = "events"
)

// SnapshotTo writes a compacted copy of the main database and every day file
// into dir with VACUUM INTO. Each copy uses its own read-only connection, so
// storing events carries on meanwhile. (A connection that sets auto_vacuum,
// as the writer's does, makes VACUUM INTO wait for the write lock, which a
// busy server never frees.) Days are copied before the main database, so its
// arrival counter covers every event in them, and no events are moved
// between files until it finishes.
func (d *DB) SnapshotTo(ctx context.Context, dir string) error {
	dd := d.days
	dd.move.RLock()
	defer dd.move.RUnlock()
	if err := os.MkdirAll(filepath.Join(dir, EventsFolder), 0o700); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	for _, s := range dd.span(0, 0) {
		if s.day == 0 {
			continue
		}
		if err := vacuumInto(ctx, s.path, filepath.Join(dir, EventsFolder, dayName(s.day)+".db")); err != nil {
			return fmt.Errorf("snapshot %s: %w", dayName(s.day), err)
		}
	}
	if err := vacuumInto(ctx, d.path, filepath.Join(dir, MainFile)); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	return nil
}

func vacuumInto(ctx context.Context, src, dest string) error {
	conn, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	_, err = conn.ExecContext(ctx, `VACUUM INTO ?`, dest)
	return err
}

// CheckDayFile checks that a file is a sound SIEMLite day file.
func CheckDayFile(ctx context.Context, path string) error {
	if _, ok := parseDayFile(filepath.Base(path)); !ok {
		return fmt.Errorf("%s isn't named like a day (YYYY-MM-DD.db)", filepath.Base(path))
	}
	conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer conn.Close()
	var check string
	if err := conn.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil {
		return fmt.Errorf("%s isn't a readable SQLite database: %w", filepath.Base(path), err)
	}
	if check != "ok" {
		return fmt.Errorf("%s is damaged: %s", filepath.Base(path), check)
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'seq'`).Scan(&n); err != nil || n == 0 {
		return fmt.Errorf("%s isn't a SIEMLite day file", filepath.Base(path))
	}
	var v int
	if err := conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > dayVersion {
		return fmt.Errorf("%s is from a newer SIEMLite", filepath.Base(path))
	}
	return nil
}

// CheckFile opens a database file read-only and reports its schema version.
// It fails unless the file is a sound SIEMLite database this build can use:
// it passes SQLite's quick_check, has an events table, and is not from a
// newer version.
func CheckFile(ctx context.Context, path string) (int, error) {
	conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var check string
	if err := conn.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil {
		return 0, fmt.Errorf("not a readable SQLite database: %w", err)
	}
	if check != "ok" {
		return 0, fmt.Errorf("the database is damaged: %s", check)
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'events'`).Scan(&n); err != nil || n == 0 {
		return 0, errors.New("not a SIEMLite database (it has no events table)")
	}
	var v int
	if err := conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, err
	}
	if v > schemaVersion {
		return v, fmt.Errorf("the backup is from a newer SIEMLite (database version %d; this one reads up to %d)", v, schemaVersion)
	}
	return v, nil
}

// Setting returns a stored setting, or def when it isn't set.
func (r *Repository) Setting(ctx context.Context, key, def string) (string, error) {
	var v string
	err := r.db.Read.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return def, fmt.Errorf("read setting %s: %w", key, err)
	}
	return v, nil
}

// SetSetting stores a setting.
func (r *Repository) SetSetting(ctx context.Context, key, value string) error {
	if _, err := r.db.Write.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("save setting %s: %w", key, err)
	}
	return nil
}
