package storage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/loggen"
)

// Benchmarks for search latency and memory over stored events.
//
//	go test ./pkg/storage -run xxx -bench 'Search|Load' -benchtime 50x
//	SIEMLITE_BENCH_LARGE=1 go test ./pkg/storage -run xxx -bench 'Search|Load' -benchtime 50x -timeout 60m
//
// The 100k set always runs (with -bench). The 1M set runs only when
// SIEMLITE_BENCH_LARGE=1 and not in -short mode, so nothing here slows a
// normal "go test" (benchmarks do not run then anyway).

// benchSizes returns the data set sizes to build.
func benchSizes() []int {
	sizes := []int{100_000}
	if os.Getenv("SIEMLITE_BENCH_LARGE") == "1" && !testing.Short() {
		sizes = append(sizes, 1_000_000)
	}
	return sizes
}

// loggenRecords makes n events from pkg/loggen's lines, spread evenly over
// the given number of days ending on 2026-11-10 UTC, in time order. About 1%
// carry a threat intel match, as an installation with a modest feed would see.
func loggenRecords(n, days int) []Record {
	return loggenRange(loggen.New(7), n, days, 0, n)
}

// loggenRange makes events number from..to-1 of the n; the generator g must be
// the same one for successive ranges (it is stateful), so a large set can be
// built and stored in chunks without holding it all in memory.
func loggenRange(g *loggen.Generator, n, days, from, to int) []Record {
	start := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -days)
	span := int64(days) * 86_400_000
	out := make([]Record, to-from)
	sev := map[string]int{"info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5}
	for k := range out {
		i := from + k
		at := start.Add(time.Duration(int64(i)*span/int64(n)) * time.Millisecond)
		line := string(g.Next(at))
		// time|host|app|level|action|src_ip|src_port|dst_ip|dst_port|user|message
		f := strings.SplitN(line, "|", 11)
		dash := func(s string) string {
			if s == "-" {
				return ""
			}
			return s
		}
		out[k] = Record{
			Timestamp: at.UnixMilli(), CategoryUID: 4, ClassUID: 4001, SeverityID: sev[f[3]],
			SrcIP: dash(f[5]), DstIP: dash(f[7]), UserName: dash(f[9]),
			Message: f[10] + " evt" + strconv.Itoa(i), RawData: line, Source: f[2], Host: f[1],
			SourceID: 3, Fields: []byte(`{"action":"` + f[4] + `"}`), Threat: i%100 == 7,
		}
	}
	return out
}

// loadBench opens a database in dir and stores n events in batches of 5000,
// returning how long it took.
func loadBench(b *testing.B, dir string, n, days int) (*DB, *Repository, time.Duration) {
	b.Helper()
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: dir + "/bench.db"})
	if err != nil {
		b.Fatal(err)
	}
	repo := NewRepository(db)
	g := loggen.New(7)
	var took time.Duration
	for i := 0; i < n; i += 5000 {
		recs := loggenRange(g, n, days, i, min(i+5000, n)) // generated untimed, so only storing is measured
		began := time.Now()
		if err := repo.InsertBatch(ctx, recs); err != nil {
			b.Fatal(err)
		}
		took += time.Since(began)
	}
	return db, repo, took
}

// BenchmarkSearch measures one page (100 events) of results for each kind
// of query over 100k (and, if enabled, 1M) stored events across 7 days.
// ns/op is the latency of one search; "matched" is how many events the
// query found in the page.
func BenchmarkSearch(b *testing.B) {
	for _, n := range benchSizes() {
		b.Run(fmt.Sprintf("events=%d", n), func(b *testing.B) {
			db, repo, took := loadBench(b, b.TempDir(), n, 7)
			defer db.Close()
			b.Logf("loaded %d events in %s (%.0f events/s straight into storage)", n, took.Round(time.Millisecond), float64(n)/took.Seconds())
			ctx := context.Background()
			sevHigh := []string{"4"}
			// An address that really occurs in the data (the newest event that has one).
			var addr string
			recent, err := repo.Search(ctx, Filter{Limit: 50})
			if err != nil {
				b.Fatal(err)
			}
			for _, r := range recent {
				if r.SrcIP != "" {
					addr = r.SrcIP
					break
				}
			}
			if addr == "" {
				b.Fatal("no source address found")
			}
			cases := []struct {
				name string
				f    Filter
			}{
				{"freetext_common", Filter{Match: `"failed"`}},
				{"freetext_rare", Filter{Match: fmt.Sprintf("evt%d", n/3)}},
				{"field_src_ip", Filter{Conds: []Cond{{Field: "src_ip", Values: []string{addr}}}}},
				{"severity_high", Filter{Conds: []Cond{{Field: "severity", Values: sevHigh}}}},
				{"threat_true", Filter{ThreatOnly: true}},
				{"no_filter", Filter{}},
			}
			for _, c := range cases {
				b.Run(c.name, func(b *testing.B) {
					f := c.f
					f.Limit = 100
					var got int
					for range b.N {
						recs, err := repo.Search(ctx, f)
						if err != nil {
							b.Fatal(err)
						}
						got = len(recs)
					}
					b.ReportMetric(float64(got), "matched")
				})
			}
			b.Run("heap", func(b *testing.B) { reportHeap(b, db) })
		})
	}
}

// reportHeap records Go heap use and database size with the data loaded and
// the garbage collected. SQLite's page cache is allocated outside the Go heap
// by the pure-Go driver's C-to-Go translation, so rss_MB (the whole
// process's resident size from ps, which includes that cache and the memory
// mapped files) is the figure to size a machine by; heap_inuse_MB is Go's own.
func reportHeap(b *testing.B, db *DB) {
	debug.FreeOSMemory() // collects, and hands freed memory (the load's own copy of the events) back to the OS
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	size := dirSize(EventsDir(db.path)) + fileSize(db.path)
	if out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output(); err == nil {
		if kb, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil {
			b.ReportMetric(kb/1e3, "rss_MB")
		}
	}
	b.ReportMetric(float64(m.HeapInuse)/1e6, "heap_inuse_MB")
	b.ReportMetric(float64(m.HeapAlloc)/1e6, "heap_alloc_MB")
	b.ReportMetric(float64(m.Sys)/1e6, "go_sys_MB")
	b.ReportMetric(float64(size)/1e6, "db_files_MB")
}

func dirSize(dir string) int64 {
	var n int64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			n += info.Size()
		}
	}
	return n
}
