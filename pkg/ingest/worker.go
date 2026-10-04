// Package ingest batches events from many producers into SQLite transactions.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// ErrClosed is returned by Submit after Close.
var ErrClosed = errors.New("ingest: worker closed")

// Sink persists a batch of records atomically.
type Sink interface {
	InsertBatch(ctx context.Context, recs []storage.Record) error
}

// Config tunes the pipeline. Zero values select defaults.
type Config struct {
	QueueSize     int             // channel buffer (default 10000)
	BatchSize     int             // flush at this many records (default 500)
	FlushInterval time.Duration   // flush partial batches this often (default 500ms)
	FlushTimeout  time.Duration   // per-flush deadline (default 30s)
	Workers       int             // consumer goroutines (default 2)
	Enricher      enrich.Enricher // optional GeoIP/ASN/threat intel enrichment
	Logger        *slog.Logger
}

func (c *Config) applyDefaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 10000
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 500 * time.Millisecond
	}
	if c.FlushTimeout <= 0 {
		c.FlushTimeout = 30 * time.Second
	}
	if c.Workers <= 0 {
		c.Workers = 2
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Stats is a snapshot of pipeline counters.
type Stats struct {
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
	Accepted      uint64 `json:"accepted"`
	Written       uint64 `json:"written"`
	Dropped       uint64 `json:"dropped"`
	Batches       uint64 `json:"batches"`
}

// Worker is a pool of consumers draining a shared buffered channel. It is
// safe for concurrent use.
type Worker struct {
	cfg  Config
	sink Sink
	ch   chan storage.Record

	mu     sync.RWMutex // guards closed and sends vs. close(ch)
	closed bool
	wg     sync.WaitGroup

	accepted, written, dropped, batches atomic.Uint64
}

// New starts the worker pool.
func New(sink Sink, cfg Config) *Worker {
	cfg.applyDefaults()
	w := &Worker{cfg: cfg, sink: sink, ch: make(chan storage.Record, cfg.QueueSize)}
	w.wg.Add(cfg.Workers)
	for range cfg.Workers {
		go w.run()
	}
	return w
}

// SubmitOptions adjust how one event is stored.
type SubmitOptions struct {
	Enricher enrich.Enricher // runs after the configured enricher
	SourceID int64           // the source the event arrived through
	// Fields are extra values a parser extracted; stored as a JSON object.
	Fields map[string]string
}

// Submit validates ev and queues it, blocking while the queue is full until
// ctx is done. A *ocsf.ValidationError means the event was rejected.
func (w *Worker) Submit(ctx context.Context, ev *ocsf.Event) error {
	return w.SubmitWith(ctx, ev, SubmitOptions{})
}

// SubmitWith is Submit with options.
func (w *Worker) SubmitWith(ctx context.Context, ev *ocsf.Event, opts SubmitOptions) error {
	if err := ev.Prepare(); err != nil {
		return err
	}
	rec := storage.Record{
		Timestamp:   ev.Time,
		CategoryUID: ev.CategoryUID,
		ClassUID:    ev.ClassUID,
		SeverityID:  ev.SeverityID,
		SrcIP:       ev.SrcIP(),
		DstIP:       ev.DstIP(),
		UserName:    ev.UserName(),
		RawData:     ev.RawData,
		Source:      ev.ProductName(),
		Host:        ev.DeviceName(),
		SourceID:    opts.SourceID,
	}
	if len(opts.Fields) > 0 {
		if b, err := json.Marshal(opts.Fields); err == nil {
			rec.Fields = b
		}
	}
	if w.cfg.Enricher != nil || opts.Enricher != nil {
		var d enrich.Data
		if w.cfg.Enricher != nil {
			w.cfg.Enricher.Enrich(ev, &d)
		}
		if opts.Enricher != nil {
			opts.Enricher.Enrich(ev, &d)
		}
		if !d.Empty() {
			rec.SrcCountry, rec.DstCountry = d.Src.Country(), d.Dst.Country()
			rec.SrcASN, rec.DstASN = d.Src.ASN(), d.Dst.ASN()
			rec.Threat = len(d.ThreatIntel) > 0
			if b, err := json.Marshal(&d); err == nil {
				rec.Enrichment = b
			}
		}
	}

	// Holding the read lock across the send keeps Close from closing the
	// channel under us. Consumers keep draining, so Close is never starved.
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return ErrClosed
	}
	select {
	case w.ch <- rec:
		w.accepted.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting events, flushes everything queued and waits for the
// consumers to finish.
func (w *Worker) Close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	w.wg.Wait()
}

// Drain blocks until every accepted event has been written or dropped, or
// ctx is done. Partial batches are flushed by the interval timer.
func (w *Worker) Drain(ctx context.Context) error {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		if w.written.Load()+w.dropped.Load() >= w.accepted.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Stats returns current counters.
func (w *Worker) Stats() Stats {
	return Stats{
		QueueDepth:    len(w.ch),
		QueueCapacity: cap(w.ch),
		Accepted:      w.accepted.Load(),
		Written:       w.written.Load(),
		Dropped:       w.dropped.Load(),
		Batches:       w.batches.Load(),
	}
}

func (w *Worker) run() {
	defer w.wg.Done()
	batch := make([]storage.Record, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.flush(batch)
		batch = batch[:0]
	}

	for {
		select {
		case rec, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= w.cfg.BatchSize {
				flush()
				ticker.Reset(w.cfg.FlushInterval)
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flush writes one batch, retrying transient failures (e.g. SQLITE_BUSY).
// It deliberately uses its own context: shutdown must not abort a final flush.
func (w *Worker) flush(batch []storage.Record) {
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.FlushTimeout)
	defer cancel()

	const attempts = 3
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = w.sink.InsertBatch(ctx, batch); err == nil {
			w.written.Add(uint64(len(batch)))
			w.batches.Add(1)
			return
		}
		w.cfg.Logger.Warn("batch insert failed", "attempt", attempt, "size", len(batch), "err", err)
		select {
		case <-ctx.Done():
			attempt = attempts
		case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
		}
	}
	w.dropped.Add(uint64(len(batch)))
	w.cfg.Logger.Error("dropping batch", "size", len(batch), "err", err)
}
