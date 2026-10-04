package storage

import (
	"context"
	"fmt"
)

// moveBatch is how many events are moved at a time. Searches wait while a
// batch is copied, so it is kept small enough to take a fraction of a second.
var moveBatch = 5000 // a variable so tests can make batches small

// MovingEvents reports whether the main database still holds events that
// MoveLegacyEvents hasn't moved into day files.
func (d *DB) MovingEvents() bool {
	d.days.move.RLock()
	defer d.days.move.RUnlock()
	return d.days.legacy != nil
}

// MoveLegacyEvents moves events kept in the main database (by versions
// before day files) into day files, a batch at a time, then empties the
// table and gives its space back. Search and the alert engine work
// throughout: each batch is copied and the main table's starting point moved
// on together, so no event is seen twice or missed. It resumes where it left
// off after a restart, and copying an event twice is a no-op. Only one
// process (the server) should run it. progress, if set, is called after each
// batch.
func (d *DB) MoveLegacyEvents(ctx context.Context, progress func(moved, left int64)) error {
	dd := d.days
	if !d.MovingEvents() {
		return nil
	}
	var left int64
	if err := d.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE id > ?`, dd.movedThrough).Scan(&left); err != nil {
		return fmt.Errorf("count events to move: %w", err)
	}
	var moved int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		dd.move.RLock()
		from := dd.movedThrough
		dd.move.RUnlock()
		recs, err := scanRecords(ctx, d.Read, `SELECT `+legacyRecordCols+` FROM events e WHERE e.id > ? ORDER BY e.id LIMIT ?`, from, moveBatch)
		if err != nil {
			return fmt.Errorf("read events to move: %w", err)
		}
		if len(recs) == 0 {
			break
		}
		last := recs[len(recs)-1].ID
		dd.move.Lock()
		err = dd.insert(ctx, recs, true)
		if err == nil {
			_, err = d.Write.ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = 'legacy_moved_through'`, last)
		}
		if err == nil {
			dd.movedThrough = last
		}
		dd.move.Unlock()
		if err != nil {
			return fmt.Errorf("move events: %w", err)
		}
		moved += int64(len(recs))
		if progress != nil {
			progress(moved, max(left-moved, 0))
		}
	}

	// Every event is in a day file: empty the table in one step. Without its
	// triggers SQLite can clear it at once instead of row by row, and the
	// search index is cleared with one command.
	dd.move.Lock()
	err := d.emptyLegacy(ctx)
	if err == nil {
		dd.legacy = nil
	}
	dd.move.Unlock()
	if err != nil {
		return fmt.Errorf("empty the old events table: %w", err)
	}
	return NewRepository(d).IncrementalVacuum(ctx, 0)
}

func (d *DB) emptyLegacy(ctx context.Context) error {
	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`DROP TRIGGER IF EXISTS events_ai`,
		`DROP TRIGGER IF EXISTS events_ad`,
		`DELETE FROM events`,
		`INSERT INTO events_fts(events_fts) VALUES ('delete-all')`,
		schemaStatements[4], // the triggers, as created by the schema
		schemaStatements[5],
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%.40s: %w", stmt, err)
		}
	}
	return tx.Commit()
}
