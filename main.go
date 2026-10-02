// SIEMLite: an embedded, OCSF-normalized SIEM backed by SQLite + FTS5.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"siemlite/api"
	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/retention"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

func main() {
	if err := run(); err != nil {
		slog.Error("siemlite failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	dbPath := flag.String("db", "siemlite.db", "SQLite database path")
	addr := flag.String("addr", "localhost:8080", "HTTP listen address")
	retentionDays := flag.Int("retention-days", 30, "delete events older than this many days")
	sample := flag.Bool("sample", true, "insert sample telemetry and run a demo search at startup")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := storage.Open(ctx, storage.Options{Path: *dbPath})
	if err != nil {
		return err
	}
	defer db.Close()

	repo := storage.NewRepository(db)
	worker := ingest.New(repo, ingest.Config{BatchSize: 500, FlushInterval: 500 * time.Millisecond})
	engine := search.NewEngine(repo)

	cleaner := retention.New(repo, retention.Config{RetentionDays: *retentionDays, Interval: 24 * time.Hour})
	var wg sync.WaitGroup
	cleanerCtx, cancelCleaner := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cleaner.Run(cleanerCtx)
	}()

	if *sample {
		if err := loadSampleAndSearch(ctx, worker, engine); err != nil {
			slog.Warn("sample run failed", "err", err)
		}
	}

	srv := api.NewServer(*addr, api.Deps{DB: db, Repo: repo, Ingest: worker, Search: engine})
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start() }()
	slog.Info("SIEMLite listening", "addr", *addr, "db", *dbPath, "retention_days", *retentionDays)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case runErr = <-serveErr:
	}

	// Stop intake first, then flush the queue, then close the database.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	worker.Close()
	cancelCleaner()
	wg.Wait()
	return runErr
}

// loadSampleAndSearch ingests demo events through the batching pipeline and
// then runs an FTS5 search over them.
func loadSampleAndSearch(ctx context.Context, worker *ingest.Worker, engine *search.Engine) error {
	now := time.Now()
	ev := func(ago time.Duration, cat, class, sev int, msg, src, dst, user string) *ocsf.Event {
		e := &ocsf.Event{
			Time: now.Add(-ago).UnixMilli(), CategoryUID: cat, ClassUID: class, ActivityID: 1,
			SeverityID: sev, Message: msg,
			Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "siemlite-sample"}},
		}
		if src != "" {
			e.SrcEndpoint = &ocsf.Endpoint{IP: src}
		}
		if dst != "" {
			e.DstEndpoint = &ocsf.Endpoint{IP: dst}
		}
		if user != "" {
			e.Actor = &ocsf.Actor{User: &ocsf.User{Name: user}}
		}
		return e
	}

	samples := []*ocsf.Event{
		ev(50*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityMedium, "Failed password for root from 203.0.113.7 via ssh", "203.0.113.7", "10.0.0.5", "root"),
		ev(48*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityMedium, "Failed password for invalid user admin via ssh", "203.0.113.7", "10.0.0.5", "admin"),
		ev(45*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityHigh, "Multiple failed ssh logins, possible brute force", "203.0.113.7", "10.0.0.5", ""),
		ev(40*time.Minute, ocsf.CategoryIAM, 3002, ocsf.SeverityInformational, "Accepted publickey for deploy via ssh", "198.51.100.20", "10.0.0.5", "deploy"),
		ev(30*time.Minute, ocsf.CategoryNetworkActivity, 4001, ocsf.SeverityLow, "Firewall allowed outbound HTTPS connection", "10.0.0.12", "93.184.216.34", ""),
		ev(20*time.Minute, ocsf.CategoryNetworkActivity, 4001, ocsf.SeverityHigh, "Firewall blocked connection to known C2 address", "10.0.0.31", "192.0.2.66", ""),
		ev(10*time.Minute, ocsf.CategorySystemActivity, 1007, ocsf.SeverityCritical, "Process injection detected in lsass.exe", "", "", "svc-backup"),
		ev(5*time.Minute, ocsf.CategoryApplicationActivity, 6003, ocsf.SeverityInformational, "GET /api/orders 200 12ms", "10.0.0.40", "10.0.0.8", "alice"),
	}
	for _, e := range samples {
		if err := worker.Submit(ctx, e); err != nil {
			return fmt.Errorf("submit sample: %w", err)
		}
	}

	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := worker.Drain(drainCtx); err != nil {
		return fmt.Errorf("drain: %w", err)
	}

	res, err := engine.Search(ctx, search.Query{
		Start: now.Add(-2 * time.Hour),
		End:   now,
		Text:  `failed AND ssh`,
		Limit: 10,
	})
	if err != nil {
		return err
	}
	fmt.Printf("FTS5 demo: %q matched %d events in %.2fms\n", "failed AND ssh", res.Count, res.TookMs)
	for _, r := range res.Events {
		out, _ := json.Marshal(map[string]any{
			"id": r.ID, "time": time.UnixMilli(r.Timestamp).Format(time.RFC3339),
			"severity": r.SeverityID, "src_ip": r.SrcIP, "user": r.UserName,
		})
		fmt.Println(" ", string(out))
	}
	return nil
}
