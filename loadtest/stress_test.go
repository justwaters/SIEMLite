package loadtest

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/backup"
	"siemlite/pkg/loggen"
	"siemlite/pkg/parser"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

// TestStressEverythingAtOnce runs ingest over HTTPS and syslog, searches by
// admins and limited users, retention, backups, the alert engine, the log
// generator and user changes all at the same time, then checks nothing was lost,
// leaked or corrupted. SIEMLITE_STRESS sets how long it runs (default 4s).
func TestStressEverythingAtOnce(t *testing.T) {
	dur := 4 * time.Second
	if v := os.Getenv("SIEMLITE_STRESS"); v != "" {
		var err error
		if dur, err = time.ParseDuration(v); err != nil {
			t.Fatal(err)
		}
	}
	if testing.Short() || raceEnabled {
		dur = 1500 * time.Millisecond // the race detector slows everything ~10x
	}
	s := newStack(t, true)
	ctx := context.Background()
	admin := s.user("root", auth.RoleAdmin, nil)

	const senders = 6
	var ids []int64
	var tokens []string
	for i := 0; i < senders; i++ {
		id, tok := s.token(admin, fmt.Sprintf("app%d", i))
		ids, tokens = append(ids, id), append(tokens, tok)
	}
	limited := s.user("lim", auth.RoleStandard, ids[:2])

	// Old events for retention to remove while everything else runs.
	old := time.Now().Add(-100 * 24 * time.Hour).UnixMilli()
	var ancient []storage.Record
	for i := 0; i < 5000; i++ {
		ancient = append(ancient, storage.Record{Timestamp: old + int64(i), CategoryUID: 6, ClassUID: 6003, SeverityID: 1,
			RawData: fmt.Sprintf("ancient event %d", i)})
	}
	if err := s.repo.InsertBatch(ctx, ancient); err != nil {
		t.Fatal(err)
	}

	var (
		wg                         sync.WaitGroup
		accepted, sentTCP, failed  atomic.Int64
		expired                    atomic.Int64
		searches, leaks, backupsOK atomic.Int64
		checks, generated, churn   atomic.Int64
		mu                         sync.Mutex
		errs                       []string
	)
	fail := func(format string, args ...any) {
		failed.Add(1)
		mu.Lock()
		if len(errs) < 20 {
			errs = append(errs, fmt.Sprintf(format, args...))
		}
		mu.Unlock()
	}
	deadline := time.Now().Add(dur)
	loop := func(name string, f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				start := time.Now()
				f(i)
				if d := time.Since(start); d > 2*time.Second {
					t.Logf("one %s step took %s", name, d.Round(time.Millisecond))
				}
			}
		}()
	}

	// Ingest over HTTPS: batches of lines from many addresses, some of them
	// SSH brute force from a few.
	for n := 0; n < senders; n++ {
		c := s.client()
		hdr := map[string]string{"Authorization": "Bearer " + tokens[n]}
		loop("ingest", func(i int) {
			var b strings.Builder
			for j := 0; j < 50; j++ {
				if j%5 == 0 {
					fmt.Fprintf(&b, "sshd: Failed password for root from 198.18.0.%d port 22 stress s%d\n", n, n)
				} else {
					fmt.Fprintf(&b, "app: request ok user=u%d src=10.%d.%d.%d stress s%d\n", j, n, i%250, j, n)
				}
			}
			var res struct{ Accepted int64 }
			code, err := s.call(c, "POST", "/api/v1/logs", b.String(), &res, hdr)
			if err != nil || code != 202 {
				fail("ingest = %d %v", code, err)
				return
			}
			accepted.Add(res.Accepted)
		})
	}
	// Syslog over TCP.
	conn, err := net.Dial("tcp", s.syslog.StreamAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	loop("syslog", func(i int) {
		if _, err := fmt.Fprintf(conn, "<38>Oct  3 10:00:00 fw kernel: stress syslog %d DROP src=198.51.100.%d\n", i, i%200); err != nil {
			fail("syslog: %v", err)
			return
		}
		sentTCP.Add(1)
		if i%10 == 0 {
			time.Sleep(time.Millisecond) // a busy firewall, not a flood (the load tests flood)
		}
	})
	// Searches by an admin and a user limited to two sources.
	for n := 0; n < 4; n++ {
		c, mine := admin, false
		if n%2 == 1 {
			c, mine = limited, true
		}
		rng := rand.New(rand.NewPCG(uint64(n), 1))
		loop("search", func(i int) {
			v := url.Values{"limit": {fmt.Sprint(1 + rng.IntN(200))}}
			if q := []string{"", "stress", `"failed password"`, "s1 OR s3", "ancient", "syslog"}[rng.IntN(6)]; q != "" {
				v.Set("q", q)
			}
			if rng.IntN(3) == 0 {
				v.Set("offset", fmt.Sprint(rng.IntN(500)))
			}
			var res search.Result
			code, err := s.call(c, "GET", "/api/v1/search?"+v.Encode(), nil, &res, nil)
			if err != nil || code != 200 {
				fail("search %s = %d %v", v.Encode(), code, err)
				return
			}
			searches.Add(1)
			for _, ev := range res.Events {
				if mine && !slices.Contains(ids[:2], ev.SourceID) {
					leaks.Add(1)
				}
			}
			if i%10 == 0 {
				var stats map[string]any
				if code, err := s.call(c, "GET", "/api/v1/stats", nil, &stats, nil); err != nil || code != 200 {
					fail("stats = %d %v", code, err)
				}
			}
		})
	}
	// Retention, in small batches so it interleaves with everything else.
	cutoff := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	loop("retention", func(i int) {
		n, err := s.repo.DeleteOlderThan(ctx, cutoff, 250)
		if err != nil {
			fail("retention: %v", err)
		}
		expired.Add(n)
		if n == 0 {
			if err := s.repo.IncrementalVacuum(ctx, 200); err != nil {
				fail("vacuum: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	loop("backup", func(i int) {
		if _, err := s.backups.Create(ctx, "manual"); err != nil {
			fail("backup: %v", err)
			return
		}
		backupsOK.Add(1)
		time.Sleep(100 * time.Millisecond)
	})
	loop("alerts", func(i int) {
		if _, err := s.alerts.Check(ctx); err != nil {
			fail("alerts: %v", err)
		}
		checks.Add(1)
		time.Sleep(20 * time.Millisecond)
	})
	// The log generator, through its own parser and token, as on a new install.
	genParser, _ := json.Marshal(parser.LogGenerator)
	var p storage.StoredParser
	s.must(admin, "POST", "/api/v1/parsers", json.RawMessage(genParser), &p, 201)
	var gen struct {
		Source storage.Source `json:"source"`
		Token  string         `json:"token"`
	}
	s.must(admin, "POST", "/api/v1/sources", map[string]any{"name": "Log generator", "parser_id": p.ID}, &gen, 201)
	gc, g := s.client(), loggen.New(1)
	loop("loggen", func(i int) {
		var b []byte
		for j := 0; j < 100; j++ {
			b = append(append(b, g.Next(time.Now())...), '\n')
		}
		var res struct{ Accepted, Rejected int64 }
		code, err := s.call(gc, "POST", "/api/v1/logs", string(b), &res, map[string]string{"Authorization": "Bearer " + gen.Token})
		if err != nil || code != 202 || res.Rejected != 0 {
			fail("loggen = %d %v (%d rejected)", code, err, res.Rejected)
			return
		}
		generated.Add(res.Accepted)
		time.Sleep(10 * time.Millisecond)
	})
	loop("users", func(i int) {
		var u storage.User
		name := fmt.Sprintf("tmp%d", i)
		code, err := s.call(admin, "POST", "/api/v1/users", map[string]any{"username": name, "password": password,
			"role": "standard", "sources": ids[i%senders : i%senders+1]}, &u, nil)
		if err != nil || code != 201 {
			fail("create user = %d %v", code, err)
			return
		}
		c := s.client()
		if code, _ := s.call(c, "POST", "/api/v1/login", map[string]string{"username": name, "password": password}, nil, nil); code != 200 {
			fail("login %s = %d", name, code)
		}
		if code, _ := s.call(admin, "DELETE", fmt.Sprintf("/api/v1/users/%d", u.ID), nil, nil, nil); code != 200 {
			fail("delete user = %d", code)
		}
		// A deleted user's session is gone at once.
		if code, _ := s.call(c, "GET", "/api/v1/search", nil, nil, nil); code != 401 {
			fail("deleted user's session = %d", code)
		}
		churn.Add(1)
	})
	wg.Wait()
	conn.Close()
	t.Logf("workload stopped after %s", time.Since(deadline.Add(-dur)).Round(time.Millisecond))
	if expired.Load() == 0 {
		t.Error("retention removed nothing while under load")
	}
	for { // finish retention (a slow machine may not get through it in time)
		n, err := s.repo.DeleteOlderThan(ctx, cutoff, 5000)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}

	// Everything sent arrives once all queues empty.
	waitFor(t, 30*time.Second, func() bool {
		s.worker.Drain(ctx)
		return s.count("raw_data LIKE '%stress syslog%'") == sentTCP.Load()
	})
	t.Logf("queues drained after %s", time.Since(deadline.Add(-dur)).Round(time.Millisecond))
	s.worker.Drain(ctx)
	if got := s.count("raw_data LIKE '%stress s_'"); got != accepted.Load() {
		t.Errorf("HTTPS events stored = %d, accepted = %d", got, accepted.Load())
	}
	if got := s.count("raw_data LIKE '%stress syslog%'"); got != sentTCP.Load() {
		t.Errorf("syslog events stored = %d, sent = %d", got, sentTCP.Load())
	}
	if got := s.count("raw_data LIKE 'ancient%'"); got != 0 {
		t.Errorf("%d events older than the retention window remain", got)
	}
	if leaks.Load() > 0 {
		t.Errorf("a limited user saw %d events from other sources", leaks.Load())
	}
	var brute int
	s.db.Write.QueryRow(`SELECT COUNT(*) FROM alerts WHERE rule_name = 'SSH brute force' AND group_value LIKE '198.18.0.%'`).Scan(&brute)
	if _, err := s.alerts.Check(ctx); err != nil {
		t.Error(err)
	}
	s.db.Write.QueryRow(`SELECT COUNT(*) FROM alerts WHERE rule_name = 'SSH brute force' AND group_value LIKE '198.18.0.%'`).Scan(&brute)
	if brute != senders {
		t.Errorf("SSH brute force alerts = %d, want one per sender (%d)", brute, senders)
	}
	s.healthy()
	checkBackups(t, s.backups)
	for _, e := range errs {
		t.Error(e)
	}
	if got := s.count("e.source_id = ?", gen.Source.ID); got != generated.Load() {
		t.Errorf("generator events stored = %d, accepted = %d", got, generated.Load())
	}
	t.Logf("%s: %d HTTPS events, %d syslog, %d from the log generator, %d searches, %d backups, %d alert checks, %d users created and deleted",
		dur, accepted.Load(), sentTCP.Load(), generated.Load(), searches.Load(), backupsOK.Load(), checks.Load(), churn.Load())
	if accepted.Load() == 0 || searches.Load() == 0 || backupsOK.Load() == 0 {
		t.Error("some workload never ran")
	}
}

func waitFor(t *testing.T, limit time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(end) {
			t.Error("timed out waiting for queued events")
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// checkBackups unpacks the newest backups and checks every database in them.
func checkBackups(t *testing.T, m *backup.Manager) {
	t.Helper()
	list, err := m.List()
	if err != nil || len(list) == 0 {
		t.Fatalf("no backups were written (%v)", err)
	}
	for _, b := range list[:min(len(list), 5)] {
		if err := m.Verify(context.Background(), b.Name); err != nil {
			t.Errorf("%s: %v", b.Name, err)
		}
	}
}
