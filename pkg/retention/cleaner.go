// Package retention deletes expired events and reclaims disk space.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Store is the storage surface the cleaner needs.
type Store interface {
	DeleteOlderThan(ctx context.Context, cutoffMs int64, limit int) (int64, error)
	IncrementalVacuum(ctx context.Context, pages int) error
	Checkpoint(ctx context.Context) error
	PurgeRawLines(ctx context.Context, now time.Time) (int64, error)
}

// Config tunes the cleaner. Zero values select defaults.
type Config struct {
	RetentionDays int           // default 30
	Interval      time.Duration // default 24h
	RawInterval   time.Duration // how often original lines are removed (default 1h)
	BatchSize     int           // rows deleted per transaction (default 5000)
	VacuumPages   int           // pages reclaimed after each batch (default 2000)
	Logger        *slog.Logger
	Now           func() time.Time // for tests; default time.Now
}

// Cleaner periodically enforces the retention window.
type Cleaner struct {
	cfg   Config
	store Store
}

// New returns a Cleaner.
func New(store Store, cfg Config) *Cleaner {
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.RawInterval <= 0 {
		cfg.RawInterval = time.Hour
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 5000
	}
	if cfg.VacuumPages <= 0 {
		cfg.VacuumPages = 2000
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cleaner{cfg: cfg, store: store}
}

// Run cleans immediately, then every Interval, until ctx is cancelled.
func (c *Cleaner) Run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		if n, err := c.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.cfg.Logger.Error("retention run failed", "err", err)
		} else if n > 0 {
			c.cfg.Logger.Info("retention run complete", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce deletes every event older than the retention window, in batches
// small enough not to starve the ingest writer, running an incremental
// vacuum after each batch. It returns the number of events deleted.
func (c *Cleaner) RunOnce(ctx context.Context) (int64, error) {
	cutoff := c.cfg.Now().AddDate(0, 0, -c.cfg.RetentionDays).UnixMilli()

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := c.store.DeleteOlderThan(ctx, cutoff, c.cfg.BatchSize)
		if err != nil {
			return total, err
		}
		total += n
		if n > 0 {
			if err := c.store.IncrementalVacuum(ctx, c.cfg.VacuumPages); err != nil {
				return total, err
			}
		}
		if n < int64(c.cfg.BatchSize) {
			break
		}
	}
	if total > 0 {
		if err := c.store.Checkpoint(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.cfg.Logger.Warn("wal checkpoint failed", "err", err)
		}
	}
	return total, nil
}

// RunRaw removes expired original lines (see storage.RawKeep) now, then
// every RawInterval, until ctx is cancelled. The events themselves are kept
// for the retention window; only the line as it arrived goes.
func (c *Cleaner) RunRaw(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.RawInterval)
	defer ticker.Stop()
	for {
		if n, err := c.store.PurgeRawLines(ctx, c.cfg.Now()); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.cfg.Logger.Error("removing original lines failed", "err", err)
		} else if n > 0 {
			c.cfg.Logger.Info("removed original lines", "events", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
