# Performance

Measured on 2026-11-18. These are single-machine laptop results from one
run each, not a guarantee, and not a capacity plan for any other machine.
Other work (editors, builds, other tools) was running on the laptop at the
same time, so expect noise of tens of percent.

## Machine

| | |
|---|---|
| CPU | Apple M2 Pro (`sysctl -n machdep.cpu.brand_string`) |
| Cores | 10 (`sysctl -n hw.ncpu`) |
| RAM | 16 GB (`sysctl -n hw.memsize` = 17179869184) |
| OS | macOS 27.0 (Darwin 27.0.0), local SSD |
| Go | go1.27.4 darwin/arm64 |
| SQLite | modernc.org/sqlite (pure Go), as the app uses it |

## Commands

The benchmarks are in `pkg/storage/bench_test.go` and `pkg/ingest/bench_test.go`.

```
# ingest throughput (3 benchmarks, 2 iterations of 200,000 events each)
go test ./pkg/ingest -run xxx -bench . -benchtime 2x

# search latency and memory, 100k and 1M events (1M only with the env var)
SIEMLITE_BENCH_LARGE=1 go test ./pkg/storage -run xxx -bench Search -benchtime 30x -timeout 60m

# 100k only (what you get without the env var, or with -short)
go test ./pkg/storage -run xxx -bench Search -benchtime 30x
```

The storage figures below came from the same code run as a compiled test
binary (`go test -c`, then the binary with `-test.bench Search
-test.benchtime 30x`), which is equivalent.

## Data

Events come from `pkg/loggen` (the fictional company's firewall, web, SSH,
VPN, DNS, database, mail and antivirus lines, with attacks mixed in). In the
search benchmarks they are spread evenly over 7 days (so 7 day files),
stored in batches of 5000 through `Repository.InsertBatch`, about 1% marked
as threat intel matches, severity from the line's level. In the ingest
benchmarks the lines are read by the built-in Log generator parser and
submitted to `ingest.Worker` with its default configuration (2 consumers,
batches of 5000, 50 ms flush), into a fresh temporary database each iteration;
no enrichment is configured.

## Ingest throughput

Time from the first `Submit` to the last event committed (`Drain` returning),
200,000 events per iteration, 2 iterations.

| Benchmark | events/second |
|---|---|
| `BenchmarkIngestWorker` (already parsed events, 2 consumers) | 22,450 |
| `BenchmarkIngestWorkerOneConsumer` | 22,985 |
| `BenchmarkParseAndIngest` (parser run inside the timed region) | 20,770 |

The second consumer made no difference here: SQLite allows one writer, so the
writer is the limit, not the goroutines. Storing straight through
`InsertBatch` (no worker, no `Submit` validation) measured 42,540 events/s for
the first 100k events and 28,534 events/s over the 1M run, in the same
runs as the search figures below (the 1M figure is an average over a bigger load; the cause of the difference was not investigated).

## Search latency

One search returning a page of 100 events, newest first, one client at a
time. `ns/op` is the average over 30 consecutive runs of the same query, straight
after the data was loaded (so mostly warm-cache). "matched" is how many events the first page held. All times are
milliseconds.

| Query (filter) | 100k events | 1M events |
|---|---|---|
| free text, common word (`"failed"`) | 1.21 ms | 1.31 ms |
| free text, rare token (one matching event) | 0.41 ms | 0.41 ms |
| field query (`src_ip=<an address that occurs>`) | 0.61 ms (20 matched) | 1.06 ms (100 matched) |
| severity filter (`severity=4`) | 1.24 ms | 1.15 ms |
| `threat=true` (about 1% of events) | 0.69 ms | 0.65 ms |
| no filter (newest 100) | 0.64 ms | 0.60 ms |

The numbers barely change from 100k to 1M events because a search reads days
newest first and stops as soon as the page is full, and the day files are
indexed by time. They say how fast a first page appears. They do not say how
long a query that has to look at everything would take (see below).

## Memory and disk after loading

Measured with the data loaded and idle, after a forced garbage collection
(`runtime.ReadMemStats`), with the benchmark's own event copies released
(they are generated and stored in chunks of 5000):

| | 100k events | 1M events |
|---|---|---|
| Go heap in use (`HeapInuse`) | 4.0 MB | 4.2 MB |
| Go heap allocated (`HeapAlloc`) | 2.2 MB | 2.4 MB |
| Memory the Go runtime has from the OS (`Sys`) | 28 MB | 33 MB |
| Process resident size (`ps -o rss`) | 189 MB | 301 MB |
| Database files on disk (main file, day files and their WAL) | 79 MB | 936 MB |

The Go heap is tiny because SQLite's page cache and the database files'
mapped pages are not part of it, which is why the whole-process resident
size is the number to plan with. Disk use was about 0.8 to 0.95 KB per event
for these lines (message, raw line, fields and the full-text index).

## What was not measured

- Concurrency: only one search at a time, and no search during ingest, or
  ingest during a backup. Mixed load is likely slower than these figures.
- Searches that cannot stop at the first page: counting all matches, deep
  paging (`Offset`), queries with no match at all, a time range over every
  day, exports, and alert rule evaluation. A query matching nothing has to
  look in every day file.
- Cold-cache first searches after a restart (every figure here is warm).
- Enrichment cost: GeoIP/ASN lookups and threat intel matching during ingest
  (no enricher was configured), and large indicator lists.
- The HTTP and syslog front ends, TLS, authentication, JSON encoding of
  results: only the storage and ingest packages were timed.
- Sizes above 1M events, many more days than 7, retention/purge, the move of
  old events into day files, backup and restore times, and the AI features.
- Other hardware, other operating systems, spinning disks, network
  filesystems. Peak memory while loading was not tracked separately from the
  idle figure above.
- Variation between runs: each figure is one run, so no spread is given.
