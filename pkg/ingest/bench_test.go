package ingest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"siemlite/pkg/loggen"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

// Ingest throughput through ingest.Worker into a temporary SQLite database,
// using realistic lines from pkg/loggen read by the built-in Log generator
// parser. Run:
//
//	go test ./pkg/ingest -run xxx -bench Ingest -benchtime 3x
//
// Each iteration stores benchEvents events into a fresh database. The
// "events/s" metric is events divided by the time from the first Submit to
// the last event being committed (Drain returning).

const benchEvents = 200_000

type parsedLine struct {
	ev    *ocsf.Event
	extra map[string]string
}

// benchLines makes n parsed events dated within the last hour.
func benchLines(b *testing.B, n int) []parsedLine {
	b.Helper()
	p, err := parser.Compile(parser.LogGenerator)
	if err != nil {
		b.Fatal(err)
	}
	g := loggen.New(11)
	now := time.Now()
	out := make([]parsedLine, n)
	for i := range out {
		at := now.Add(-time.Duration(i%3600) * time.Second)
		res, err := p.Parse(string(g.Next(at)), parser.Defaults{Now: at})
		if err != nil {
			b.Fatal(err)
		}
		out[i] = parsedLine{res.Event, res.Extra}
	}
	return out
}

func benchIngest(b *testing.B, cfg Config) {
	ctx := context.Background()
	var total time.Duration
	for range b.N {
		b.StopTimer()
		lines := benchLines(b, benchEvents)
		db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(b.TempDir(), "bench.db")})
		if err != nil {
			b.Fatal(err)
		}
		cfg.FlushInterval = 50 * time.Millisecond
		w := New(storage.NewRepository(db), cfg)
		b.StartTimer()
		began := time.Now()
		for _, l := range lines {
			if err := w.SubmitWith(ctx, l.ev, SubmitOptions{SourceID: 3, Fields: l.extra}); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.Drain(ctx); err != nil {
			b.Fatal(err)
		}
		total += time.Since(began)
		b.StopTimer()
		if st := w.Stats(); st.Written != benchEvents || st.Dropped != 0 {
			b.Fatalf("stats = %+v", st)
		}
		w.Close()
		db.Close()
		b.StartTimer()
	}
	b.ReportMetric(float64(benchEvents*b.N)/total.Seconds(), "events/s")
}

// BenchmarkIngestWorker uses the default configuration (2 consumers, batches
// of 5000).
func BenchmarkIngestWorker(b *testing.B) { benchIngest(b, Config{}) }

// BenchmarkIngestWorkerOneConsumer is the same with a single consumer
// goroutine, to show whether the second one helps.
func BenchmarkIngestWorkerOneConsumer(b *testing.B) { benchIngest(b, Config{Workers: 1}) }

// BenchmarkParseAndIngest includes reading each line with the parser, as the
// HTTP and syslog paths do, in the measured time.
func BenchmarkParseAndIngest(b *testing.B) {
	ctx := context.Background()
	p, err := parser.Compile(parser.LogGenerator)
	if err != nil {
		b.Fatal(err)
	}
	var total time.Duration
	for range b.N {
		b.StopTimer()
		g := loggen.New(11)
		now := time.Now()
		lines := make([]string, benchEvents)
		ats := make([]time.Time, benchEvents)
		for i := range lines {
			ats[i] = now.Add(-time.Duration(i%3600) * time.Second)
			lines[i] = string(g.Next(ats[i]))
		}
		db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(b.TempDir(), "bench.db")})
		if err != nil {
			b.Fatal(err)
		}
		w := New(storage.NewRepository(db), Config{FlushInterval: 50 * time.Millisecond})
		b.StartTimer()
		began := time.Now()
		for i, line := range lines {
			res, err := p.Parse(line, parser.Defaults{Now: ats[i]})
			if err != nil {
				b.Fatal(err)
			}
			if err := w.SubmitWith(ctx, res.Event, SubmitOptions{SourceID: 3, Fields: res.Extra}); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.Drain(ctx); err != nil {
			b.Fatal(err)
		}
		total += time.Since(began)
		b.StopTimer()
		w.Close()
		db.Close()
		b.StartTimer()
	}
	b.ReportMetric(float64(benchEvents*b.N)/total.Seconds(), "events/s")
}
