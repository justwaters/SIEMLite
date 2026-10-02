// Package storage owns the SQLite database: connection setup, schema and
// queries.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"runtime"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Options configures Open.
type Options struct {
	// Path is the database file path.
	Path string
	// ReadConns is the size of the read-only pool (default: NumCPU, min 2).
	ReadConns int
}

// DB holds two pools over the same WAL database: a single-connection writer
// (SQLite allows one writer, so this avoids SQLITE_BUSY between our own
// goroutines) and a read-only pool that scales with concurrent searches.
type DB struct {
	Write *sql.DB
	Read  *sql.DB
	path  string
}

// Open opens (creating if needed) the database and applies the schema.
func Open(ctx context.Context, opts Options) (*DB, error) {
	if opts.Path == "" {
		return nil, errors.New("storage: empty database path")
	}
	if opts.ReadConns <= 0 {
		opts.ReadConns = max(runtime.NumCPU(), 2)
	}

	write, err := openPool(dsn(opts.Path, false), 1)
	if err != nil {
		return nil, err
	}
	if err := prepareWriter(ctx, write); err != nil {
		write.Close()
		return nil, err
	}

	read, err := openPool(dsn(opts.Path, true), opts.ReadConns)
	if err != nil {
		write.Close()
		return nil, err
	}
	if err := read.PingContext(ctx); err != nil {
		write.Close()
		read.Close()
		return nil, fmt.Errorf("storage: ping reader: %w", err)
	}
	return &DB{Write: write, Read: read, path: opts.Path}, nil
}

// dsn builds a modernc.org/sqlite DSN. _pragma values run on every new
// connection. auto_vacuum comes first: it only takes effect on a database
// that has no tables yet, and incremental_vacuum needs it set to 2.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "auto_vacuum(2)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	}
	// url.Values.Encode sorts keys but preserves per-key order.
	return "file:" + path + "?" + q.Encode()
}

func openPool(dsn string, conns int) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	db.SetMaxOpenConns(conns)
	db.SetMaxIdleConns(conns)
	return db, nil
}

// prepareWriter makes sure auto_vacuum is INCREMENTAL, then migrates.
func prepareWriter(ctx context.Context, db *sql.DB) error {
	var mode int
	if err := db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return fmt.Errorf("storage: read auto_vacuum: %w", err)
	}
	if mode != 2 {
		// Pre-existing database created without incremental auto_vacuum: the
		// mode only changes after a full VACUUM (one-time cost).
		if _, err := db.ExecContext(ctx, "PRAGMA auto_vacuum = 2"); err != nil {
			return fmt.Errorf("storage: set auto_vacuum: %w", err)
		}
		if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
			return fmt.Errorf("storage: convert auto_vacuum: %w", err)
		}
	}
	return migrate(ctx, db)
}

// Ping verifies both pools can reach the database.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.Write.PingContext(ctx); err != nil {
		return fmt.Errorf("writer: %w", err)
	}
	if err := d.Read.PingContext(ctx); err != nil {
		return fmt.Errorf("reader: %w", err)
	}
	return nil
}

// Close checkpoints the WAL and closes both pools.
func (d *DB) Close() error {
	var errs []error
	if err := d.Read.Close(); err != nil {
		errs = append(errs, err)
	}
	// Closing the last connection normally checkpoints; be explicit anyway.
	_, _ = d.Write.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err := d.Write.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
