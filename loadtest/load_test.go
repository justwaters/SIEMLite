package loadtest

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/storage"
)

// scale holds the sizes and the floors each load test must reach. The
// floors are deliberately well below what a laptop or CI runner manages, so
// they catch regressions that cost several times the speed, not noise.
type scale struct {
	name            string
	ingestClients   int
	ingestFor       time.Duration
	ingestFloor     float64 // events per second, end to end
	udpMessages     int
	udpRate         int     // messages per second sent, kept under what storage sustains
	udpFloor        float64 // share that must arrive (UDP has no backpressure)
	tcpLines        int
	tcpFloor        float64 // lines per second
	bigEvents       int
	searchP95       time.Duration
	statsP95        time.Duration
	backupFloor     float64 // events per second backed up
	alertFloor      float64 // events per second checked by the alert engine
	searchClients   int
	searchesEachRun int
}

var scales = map[string]scale{
	// ci runs on every commit on a shared GitHub runner: small, with floors
	// that only catch large regressions.
	"ci": {name: "ci", ingestClients: 4, ingestFor: 5 * time.Second, ingestFloor: 1000,
		udpMessages: 20000, udpRate: 5000, udpFloor: 0.90, tcpLines: 50000, tcpFloor: 1500,
		bigEvents: 100_000, searchP95: time.Second, statsP95: 2 * time.Second, backupFloor: 20_000, alertFloor: 20_000,
		searchClients: 4, searchesEachRun: 6},
	"small": {name: "small", ingestClients: 8, ingestFor: 10 * time.Second, ingestFloor: 3000,
		udpMessages: 100_000, udpRate: 4000, udpFloor: 0.99, tcpLines: 200000, tcpFloor: 3000,
		bigEvents: 500_000, searchP95: time.Second, statsP95: 2 * time.Second, backupFloor: 50_000, alertFloor: 20_000,
		searchClients: 8, searchesEachRun: 10},
}

// hard is sized to run in about the time SIEMLITE_LOAD_FOR allows; most of
// it goes on filling and measuring the big database.
var hard = map[string]scale{
	"5m": {name: "hard 5m", ingestClients: 32, ingestFor: 30 * time.Second, ingestFloor: 3000,
		udpMessages: 120_000, udpRate: 4000, udpFloor: 0.99, tcpLines: 200_000, tcpFloor: 4000,
		bigEvents: 600_000, searchP95: time.Second, statsP95: 2 * time.Second, backupFloor: 50_000, alertFloor: 20_000,
		searchClients: 16, searchesEachRun: 10},
	"30m": {name: "hard 30m", ingestClients: 32, ingestFor: 60 * time.Second, ingestFloor: 3000,
		udpMessages: 300_000, udpRate: 4000, udpFloor: 0.99, tcpLines: 1_000_000, tcpFloor: 4000,
		bigEvents: 3_000_000, searchP95: 2 * time.Second, statsP95: 5 * time.Second, backupFloor: 50_000, alertFloor: 20_000,
		searchClients: 16, searchesEachRun: 20},
	"2h": {name: "hard 2h", ingestClients: 32, ingestFor: 5 * time.Minute, ingestFloor: 3000,
		udpMessages: 1_200_000, udpRate: 4000, udpFloor: 0.99, tcpLines: 3_000_000, tcpFloor: 4000,
		bigEvents: 20_000_000, searchP95: 3 * time.Second, statsP95: 10 * time.Second, backupFloor: 50_000, alertFloor: 20_000,
		searchClients: 16, searchesEachRun: 20},
}

func loadScale(t *testing.T) scale {
	v := os.Getenv("SIEMLITE_LOAD")
	if v == "" {
		t.Skip("set SIEMLITE_LOAD=ci, small or hard to run load tests")
	}
	sc, ok := scales[v]
	if v == "hard" {
		d := os.Getenv("SIEMLITE_LOAD_FOR")
		if sc, ok = hard[d]; !ok {
			t.Fatalf("with SIEMLITE_LOAD=hard, set SIEMLITE_LOAD_FOR to 5m, 30m or 2h (not %q)", d)
		}
	}
	if !ok {
		t.Fatalf("SIEMLITE_LOAD must be ci, small or hard, not %q", v)
	}
	if raceEnabled {
		t.Skip("load tests measure speed; run them without -race")
	}
	return sc
}

// report logs a result and fails if it misses the floor.
func report(t *testing.T, what string, got, floor float64, unit string, higherIsBetter bool) {
	t.Helper()
	ok := got >= floor
	if !higherIsBetter {
		ok = got <= floor
	}
	mark := "ok"
	if !ok {
		mark = "BELOW FLOOR"
		t.Errorf("%s: %.0f %s (floor %.0f)", what, got, unit, floor)
	}
	t.Logf("%-42s %12.0f %-8s floor %.0f  %s", what, got, unit, floor, mark)
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	slices.Sort(ds)
	return ds[min(len(ds)-1, int(float64(len(ds))*p))]
}

// TestLoadIngestHTTPS sends batches of 500 lines from many clients at once
// and measures events stored per second, from first request to searchable.
func TestLoadIngestHTTPS(t *testing.T) {
	sc := loadScale(t)
	s := newStack(t, false)
	ctx := context.Background()
	admin := s.user("root", auth.RoleAdmin, nil)

	var accepted, rejected, busy atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(sc.ingestFor)
	for n := 0; n < sc.ingestClients; n++ {
		_, tok := s.token(admin, fmt.Sprintf("app%d", n))
		hdr := map[string]string{"Authorization": "Bearer " + tok}
		c := s.client()
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(n), 2))
			var b strings.Builder
			for i := 0; time.Now().Before(deadline); i++ {
				b.Reset()
				for j := 0; j < 500; j++ {
					ip := fmt.Sprintf("10.%d.%d.%d", n, rng.IntN(256), rng.IntN(256))
					switch rng.IntN(4) {
					case 0:
						fmt.Fprintf(&b, "Oct  3 10:17:%02d web%d sshd[%d]: Failed password for user%d from %s port %d ssh2\n",
							j%60, n, rng.IntN(9999), rng.IntN(500), ip, 1024+rng.IntN(60000))
					case 1:
						fmt.Fprintf(&b, `{"level":"info","msg":"request served","user":"u%d","src_ip":"%s","path":"/api/%d","status":200,"ms":%d}`+"\n",
							rng.IntN(500), ip, rng.IntN(100), rng.IntN(900))
					case 2:
						fmt.Fprintf(&b, `%s - - [03/Oct/2026:10:17:12 +0000] "GET /p/%d HTTP/1.1" 200 %d "-" "curl/8"`+"\n", ip, rng.IntN(1000), rng.IntN(99999))
					default:
						fmt.Fprintf(&b, "action=allow src=%s dst=192.0.2.%d proto=tcp dport=%d user=svc%d\n", ip, rng.IntN(256), rng.IntN(65535), rng.IntN(50))
					}
				}
				// Behave like a good sender: on 503 (the queue stayed full)
				// wait as Retry-After says and send the rest again.
				lines := strings.SplitAfter(strings.TrimSuffix(b.String(), "\n"), "\n")
				for len(lines) > 0 {
					t0 := time.Now()
					var res struct {
						Accepted, Rejected int64
						StoppedAt          int `json:"stopped_at_index"`
					}
					code, err := s.call(c, "POST", "/api/v1/logs", strings.Join(lines, ""), &res, hdr)
					d := time.Since(t0)
					if err != nil || (code != 202 && code != 503) {
						t.Errorf("ingest = %d %v", code, err)
						return
					}
					accepted.Add(res.Accepted)
					rejected.Add(res.Rejected)
					mu.Lock()
					lat = append(lat, d)
					mu.Unlock()
					if code == 202 {
						break
					}
					busy.Add(1)
					lines = lines[res.StoppedAt:]
					time.Sleep(time.Second)
				}
			}
		}()
	}
	wg.Wait()
	sent := time.Since(start)
	s.worker.Drain(ctx)
	stored := s.count("1=1")
	total := time.Since(start)
	if rejected.Load() > 0 {
		t.Errorf("%d lines rejected", rejected.Load())
	}
	if stored < accepted.Load() {
		t.Errorf("stored %d of %d accepted events", stored, accepted.Load())
	}
	t.Logf("%d clients for %s: %d events accepted in %s, all stored after %s; %d requests told to retry (queue full)",
		sc.ingestClients, sc.ingestFor, accepted.Load(), sent.Round(time.Millisecond), total.Round(time.Millisecond), busy.Load())
	report(t, "HTTPS ingest, accepted", float64(accepted.Load())/sent.Seconds(), sc.ingestFloor, "events/s", true)
	report(t, "HTTPS ingest, stored and searchable", float64(accepted.Load())/total.Seconds(), sc.ingestFloor, "events/s", true)
	// Saturating senders queue behind each other, so the floor grows with them.
	report(t, "HTTPS ingest, p95 per 500-line request", float64(percentile(lat, 0.95).Milliseconds()),
		float64(max(5000, 300*sc.ingestClients)), "ms", false)
	s.healthy()
}

// TestLoadSyslog floods UDP at a fixed rate (some loss is normal for UDP;
// the floor is on what arrives) and sends as fast as possible over TCP,
// where nothing may be lost.
func TestLoadSyslog(t *testing.T) {
	sc := loadScale(t)
	s := newStack(t, true)
	ctx := context.Background()

	t.Run("udp", func(t *testing.T) {
		conn, err := net.Dial("udp", s.syslog.UDPAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		start := time.Now()
		interval := time.Second / time.Duration(sc.udpRate)
		for i := 0; i < sc.udpMessages; i++ {
			if want := start.Add(time.Duration(i) * interval); time.Until(want) > 0 {
				time.Sleep(time.Until(want))
			}
			fmt.Fprintf(conn, "<38>Oct  3 10:17:12 fw kernel: udp flood %d DROP IN=eth0 SRC=198.51.100.%d DST=192.0.2.1 PROTO=TCP DPT=22", i, i%256)
		}
		sendTime := time.Since(start)
		waitStable(s, "raw_data LIKE '%udp flood%'")
		got := s.count("raw_data LIKE '%udp flood%'")
		t.Logf("sent %d datagrams in %s (%.0f/s), %d stored; listener counters %+v", sc.udpMessages, sendTime.Round(time.Millisecond),
			float64(sc.udpMessages)/sendTime.Seconds(), got, s.syslog.Stats())
		report(t, fmt.Sprintf("syslog UDP at %d/s, delivered", sc.udpRate), 100*float64(got)/float64(sc.udpMessages), 100*sc.udpFloor, "%", true)
	})

	t.Run("tcp", func(t *testing.T) {
		const conns = 4
		start := time.Now()
		var wg sync.WaitGroup
		for c := 0; c < conns; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.Dial("tcp", s.syslog.StreamAddrs()[0].String())
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				w := make([]byte, 0, 1<<16)
				for i := c; i < sc.tcpLines; i += conns {
					w = fmt.Appendf(w, "<86>Oct  3 10:17:12 bastion sshd[4242]: tcp flood %d Accepted publickey for deploy from 10.9.%d.%d port 50022 ssh2\n", i, i%256, (i/256)%256)
					if len(w) > 60000 {
						if _, err := conn.Write(w); err != nil {
							t.Error(err)
							return
						}
						w = w[:0]
					}
				}
				conn.Write(w)
			}()
		}
		wg.Wait()
		deadline := time.Now().Add(5 * time.Minute)
		for s.count("raw_data LIKE '%tcp flood%'") < int64(sc.tcpLines) && time.Now().Before(deadline) {
			s.worker.Drain(ctx)
			time.Sleep(100 * time.Millisecond)
		}
		total := time.Since(start)
		got := s.count("raw_data LIKE '%tcp flood%'")
		if got != int64(sc.tcpLines) {
			t.Errorf("TCP syslog stored %d of %d lines (stats %+v)", got, sc.tcpLines, s.syslog.Stats())
		}
		report(t, "syslog TCP flood, stored and searchable", float64(got)/total.Seconds(), sc.tcpFloor, "lines/s", true)
	})
	s.healthy()
}

// waitStable waits until the count stops changing (UDP has no end marker).
func waitStable(s *stack, where string) {
	last := int64(-1)
	for i := 0; i < 600; i++ {
		s.worker.Drain(context.Background())
		n := s.count(where)
		if n == last {
			return
		}
		last = n
		time.Sleep(500 * time.Millisecond)
	}
}

// TestLoadBigDatabase fills a database with millions of events spread over
// 30 days and many sources, then measures searches, the dashboard, the alert
// engine and a backup and restore of the whole thing.
func TestLoadBigDatabase(t *testing.T) {
	sc := loadScale(t)
	s := newStack(t, false)
	ctx := context.Background()
	admin := s.user("root", auth.RoleAdmin, nil)
	var srcIDs []int64
	for i := 0; i < 8; i++ {
		id, _ := s.token(admin, fmt.Sprintf("app%d", i))
		srcIDs = append(srcIDs, id)
	}
	limited := s.user("lim", auth.RoleStandard, srcIDs[:2])

	// Fill: straight into storage in large batches (ingest speed is measured
	// separately); this is the database a busy month leaves behind.
	start := time.Now()
	now := time.Now().UnixMilli()
	span := int64(30 * 24 * time.Hour / time.Millisecond)
	rng := rand.New(rand.NewPCG(1, 1))
	words := []string{"failed", "password", "accepted", "connection", "refused", "timeout", "denied", "login", "session",
		"opened", "closed", "error", "warning", "request", "served", "upload", "download", "admin", "kernel", "firewall"}
	batch := make([]storage.Record, 0, 5000)
	for i := 0; i < sc.bigEvents; i++ {
		var msg strings.Builder
		for w := 0; w < 6+rng.IntN(6); w++ {
			msg.WriteString(words[rng.IntN(len(words))])
			msg.WriteByte(' ')
		}
		src := fmt.Sprintf("10.%d.%d.%d", rng.IntN(4), rng.IntN(256), rng.IntN(256))
		fmt.Fprintf(&msg, "from %s user%d id=%d", src, rng.IntN(2000), i)
		batch = append(batch, storage.Record{
			Timestamp: now - span + int64(i)*span/int64(sc.bigEvents), CategoryUID: 1 + rng.IntN(6), ClassUID: 3002,
			SeverityID: rng.IntN(7), SrcIP: src, DstIP: fmt.Sprintf("192.0.2.%d", rng.IntN(256)),
			UserName: fmt.Sprintf("user%d", rng.IntN(2000)), RawData: msg.String(), Source: []string{"sshd", "nginx", "kernel", "app"}[rng.IntN(4)],
			Host: fmt.Sprintf("host%d", rng.IntN(50)), Threat: rng.IntN(1000) == 0, SourceID: srcIDs[rng.IntN(len(srcIDs))],
		})
		if len(batch) == cap(batch) {
			if err := s.repo.InsertBatch(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := s.repo.InsertBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	fill := time.Since(start)
	st, _ := s.repo.Stats(ctx)
	t.Logf("filled %d events in %s (%.0f/s); %d MB on disk", sc.bigEvents, fill.Round(time.Millisecond),
		float64(sc.bigEvents)/fill.Seconds(), st.SizeBytes>>20)

	t.Run("search", func(t *testing.T) {
		queries := []struct{ name, q string }{
			{"newest page", ""},
			{"word", "q=refused"},
			{"phrase", "q=" + url.QueryEscape(`"failed password"`)},
			{"rare word AND", "q=" + url.QueryEscape("firewall AND admin AND upload")},
			{"source address", "src_ip=10.1.2.3"},
			{"user", "user=user42"},
			{"host and severity", "host=host7&severity=5"},
			{"threat only", "threat=true"},
			{"last hour", "start=" + url.QueryEscape(time.Now().Add(-time.Hour).Format(time.RFC3339))},
			{"one day, word", "q=denied&start=" + url.QueryEscape(time.Now().Add(-10*24*time.Hour).Format(time.RFC3339)) +
				"&end=" + url.QueryEscape(time.Now().Add(-9*24*time.Hour).Format(time.RFC3339))},
			{"deep page", "q=error&offset=5000&limit=100"},
			{"no match", "q=zzzznotthere"},
		}
		for _, who := range []struct {
			name string
			c    *http.Client
		}{{"admin", admin}, {"limited user", limited}} {
			for _, qq := range queries {
				var lat []time.Duration
				var mu sync.Mutex
				var wg sync.WaitGroup
				for c := 0; c < sc.searchClients; c++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := 0; i < sc.searchesEachRun/2+1; i++ {
							t0 := time.Now()
							code, err := s.call(who.c, "GET", "/api/v1/search?limit=100&"+qq.q, nil, nil, nil)
							d := time.Since(t0)
							if err != nil || code != 200 {
								t.Errorf("%s %s = %d %v", who.name, qq.name, code, err)
								return
							}
							mu.Lock()
							lat = append(lat, d)
							mu.Unlock()
						}
					}()
				}
				wg.Wait()
				p95 := percentile(lat, 0.95)
				report(t, fmt.Sprintf("search p95, %s, %s", who.name, qq.name), float64(p95.Milliseconds()),
					float64(sc.searchP95.Milliseconds()), "ms", false)
			}
		}
	})

	t.Run("dashboard", func(t *testing.T) {
		for _, who := range []struct {
			name string
			c    *http.Client
		}{{"admin", admin}, {"limited user", limited}} {
			var lat []time.Duration
			for i := 0; i < 5; i++ {
				t0 := time.Now()
				if code, err := s.call(who.c, "GET", "/api/v1/stats", nil, nil, nil); err != nil || code != 200 {
					t.Fatalf("stats = %d %v", code, err)
				}
				lat = append(lat, time.Since(t0))
			}
			report(t, "dashboard p95, "+who.name, float64(percentile(lat, 0.95).Milliseconds()),
				float64(sc.statsP95.Milliseconds()), "ms", false)
		}
	})

	t.Run("alerts", func(t *testing.T) {
		// The first check of a full database starts from the beginning.
		t0 := time.Now()
		res, err := s.alerts.Check(ctx)
		if err != nil {
			t.Fatal(err)
		}
		d := time.Since(t0)
		t.Logf("first alert check over %d events: %s, %d opened", sc.bigEvents, d.Round(time.Millisecond), res.Opened)
		report(t, "alert engine, events checked", float64(sc.bigEvents)/d.Seconds(), sc.alertFloor, "events/s", true)
		t0 = time.Now()
		if _, err := s.alerts.Check(ctx); err != nil {
			t.Fatal(err)
		}
		report(t, "alert engine, check with nothing new", float64(time.Since(t0).Milliseconds()), 1000, "ms", false)
	})

	t.Run("backup", func(t *testing.T) {
		t0 := time.Now()
		b, err := s.backups.Create(ctx, "manual")
		if err != nil {
			t.Fatal(err)
		}
		d := time.Since(t0)
		t.Logf("backup %s: %d MB compressed in %s", b.Name, b.Size>>20, d.Round(time.Millisecond))
		report(t, "backup", float64(sc.bigEvents)/d.Seconds(), sc.backupFloor, "events/s", true)

		// Restore it into a copy and check every event is there.
		dbPath := filepath.Join(t.TempDir(), "restored.db")
		if _, err := s.backups.StageRestore(ctx, b.Name); err != nil {
			t.Fatal(err)
		}
		os.Rename(backup.PendingPath(s.db.Path()), backup.PendingPath(dbPath))
		os.Rename(backup.PendingPath(s.db.Path())+".json", backup.PendingPath(dbPath)+".json")
		t0 = time.Now()
		if _, err := backup.ApplyPendingRestore(dbPath, quiet); err != nil {
			t.Fatal(err)
		}
		rdb, err := storage.Open(ctx, storage.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer rdb.Close()
		var n int64
		n, _ = rdb.CountEvents(ctx, "1")
		report(t, "restore and reopen", float64(sc.bigEvents)/time.Since(t0).Seconds(), sc.backupFloor, "events/s", true)
		if n != s.count("1=1") {
			t.Errorf("restored %d events, want %d", n, s.count("1=1"))
		}
	})
	s.healthy()
}
