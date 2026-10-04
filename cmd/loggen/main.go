// Command loggen sends random, realistic test logs (see pkg/loggen) at a
// steady rate, to try out a SIEM or load-test it.
//
//	loggen -eps 10                       # to SIEMLite on this machine
//	loggen -eps 1k -for 10m              # a load test
//	loggen -eps 100 -to udp://siem:514   # to any SIEM over syslog
//	loggen -eps 1 -to stdout             # just look at the lines
//
// For SIEMLite it posts batches to /api/v1/logs with an access token. By
// default it reads the token SIEMLite made for it (siemlite-loggen.token)
// and trusts SIEMLite's certificate (siemlite.crt), looking in the current
// folder and in /data (Docker). When SIEMLite is busy it answers 503; loggen
// waits as asked and sends the rest again, so nothing is lost and the rate
// it reports is what was actually stored.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"siemlite/pkg/loggen"
)

func main() {
	eps := flag.String("eps", "10", "events per second: 1, 10, 100, 1k, 10k, 100k or 1m (any number works)")
	dur := flag.Duration("for", 0, "how long to run, e.g. 30s or 10m (0 runs until stopped)")
	to := flag.String("to", "https://localhost:8443", "where to send: a SIEMLite URL, udp://host:port or tcp://host:port (syslog), or stdout")
	token := flag.String("token", os.Getenv("LOGGEN_TOKEN"), "access token (default: read from -token-file)")
	tokenFile := flag.String("token-file", "", "file holding the token (default: siemlite-loggen.token here or in /data)")
	caFile := flag.String("cacert", "", "certificate to trust (default: siemlite.crt here or in /data)")
	insecure := flag.Bool("insecure", false, "don't check the server's certificate")
	seed := flag.Uint64("seed", uint64(time.Now().UnixNano()), "random seed (the same seed gives the same logs)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "loggen sends random test logs at a steady rate.\n\nFormat: %s\n\n", loggen.Header)
		flag.PrintDefaults()
	}
	flag.Parse()

	rate, err := parseEPS(*eps)
	if err != nil {
		fail(err)
	}
	send, err := sender(*to, *token, *tokenFile, *caFile, *insecure)
	if err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	if *to != "stdout" {
		fmt.Fprintf(os.Stderr, "loggen: %s events a second to %s (Ctrl-C to stop)\n", humanEPS(rate), *to)
	}
	st := run(ctx, rate, *seed, send, *to == "stdout")
	if *to != "stdout" {
		fmt.Fprintln(os.Stderr, st.summary(true))
	}
	if st.failed.Load() > 0 && st.sent.Load() == 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "loggen:", err)
	os.Exit(2)
}

// parseEPS reads "10", "1k", "100k", "1m".
func parseEPS(s string) (float64, error) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.ToLower(s), "eps")))
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1e3, strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mult, s = 1e6, strings.TrimSuffix(s, "m")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 || n*mult > 10e6 {
		return 0, fmt.Errorf("-eps must be a rate like 1, 10, 100, 1k, 10k, 100k or 1m (got %q)", s)
	}
	return n * mult, nil
}

func humanEPS(r float64) string {
	switch {
	case r >= 1e6:
		return strconv.FormatFloat(r/1e6, 'f', -1, 64) + "m"
	case r >= 1e3:
		return strconv.FormatFloat(r/1e3, 'f', -1, 64) + "k"
	}
	return strconv.FormatFloat(r, 'f', -1, 64)
}

// stats counts what happened.
type stats struct {
	start                 time.Time
	made, sent            atomic.Int64 // lines generated; lines the receiver accepted
	busy, failed, batches atomic.Int64 // 503s, failed requests, requests
	lastErr               atomic.Value
}

func (s *stats) summary(final bool) string {
	el := time.Since(s.start).Seconds()
	msg := fmt.Sprintf("%.0fs: %d sent (%.0f/s)", el, s.sent.Load(), float64(s.sent.Load())/el)
	if q := s.made.Load() - s.sent.Load(); q > 0 && !final {
		msg += fmt.Sprintf(", %d waiting", q)
	}
	if n := s.busy.Load(); n > 0 {
		msg += fmt.Sprintf(", told to slow down %d times", n)
	}
	if n := s.failed.Load(); n > 0 {
		msg += fmt.Sprintf(", %d failed requests (last: %v)", n, s.lastErr.Load())
	}
	return "loggen: " + msg
}

// sendFunc delivers lines (each ending in a newline). It returns how many
// were taken; with busy set, the rest should be sent again after wait.
type sendFunc func(ctx context.Context, lines []byte, n int) (taken int, wait time.Duration, err error)

// run generates lines at rate and sends them in batches until ctx ends.
func run(ctx context.Context, rate float64, seed uint64, send sendFunc, quiet bool) *stats {
	st := &stats{start: time.Now()}
	// Several generators at high rates; each makes its share.
	workers := max(1, min(runtime.NumCPU(), int(rate/100_000)+1))
	tick := 100 * time.Millisecond
	if rate < 10 {
		tick = time.Duration(float64(time.Second) / rate)
	}
	batchMax := int(min(max(rate/10, 1), 5000))
	batches := make(chan []byte, 4*workers)
	var genWG, sendWG sync.WaitGroup

	for w := 0; w < workers; w++ {
		genWG.Add(1)
		go func() {
			defer genWG.Done()
			g := loggen.New(seed + uint64(w))
			share := rate / float64(workers)
			t := time.NewTicker(tick)
			defer t.Stop()
			var owed float64
			var batch []byte
			n := 0
			flush := func() {
				if n == 0 {
					return
				}
				select {
				case batches <- batch:
				case <-ctx.Done():
				}
				batch, n = nil, 0
			}
			for {
				select {
				case <-ctx.Done():
					flush()
					return
				case now := <-t.C:
					owed += share * tick.Seconds()
					for ; owed >= 1; owed-- {
						batch = append(append(batch, g.Next(now)...), '\n')
						n++
						st.made.Add(1)
						if n >= batchMax {
							flush()
						}
					}
					flush()
				}
			}
		}()
	}
	go func() { genWG.Wait(); close(batches) }()

	senders := max(1, min(16, int(rate/2000)+1))
	for i := 0; i < senders; i++ {
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			for b := range batches {
				for len(b) > 0 {
					n := bytes.Count(b, []byte{'\n'})
					st.batches.Add(1)
					// Lines made before the stop still go out, but not forever.
					sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					taken, wait, err := send(sctx, b, n)
					cancel()
					st.sent.Add(int64(taken))
					b = cutLines(b, taken)
					if err != nil {
						st.failed.Add(1)
						st.lastErr.Store(err.Error())
						wait = time.Second
					} else if len(b) > 0 {
						st.busy.Add(1)
					}
					if len(b) > 0 {
						if ctx.Err() != nil {
							break // stopping: don't wait on a busy or broken receiver
						}
						time.Sleep(wait)
					}
				}
			}
		}()
	}
	report := time.NewTicker(5 * time.Second)
	defer report.Stop()
	done := make(chan struct{})
	go func() { sendWG.Wait(); close(done) }()
	for {
		select {
		case <-done:
			return st
		case <-report.C:
			if !quiet {
				fmt.Fprintln(os.Stderr, st.summary(false))
			}
		}
	}
}

// cutLines drops the first n lines.
func cutLines(b []byte, n int) []byte {
	for ; n > 0 && len(b) > 0; n-- {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return nil
		}
		b = b[i+1:]
	}
	return b
}

// sender picks how to deliver lines.
func sender(to, token, tokenFile, caFile string, insecure bool) (sendFunc, error) {
	if to == "stdout" {
		w := bufio.NewWriter(os.Stdout)
		var mu sync.Mutex
		return func(_ context.Context, lines []byte, n int) (int, time.Duration, error) {
			mu.Lock()
			defer mu.Unlock()
			w.Write(lines)
			return n, 0, w.Flush()
		}, nil
	}
	u, err := url.Parse(to)
	if err != nil {
		return nil, fmt.Errorf("-to: %w", err)
	}
	switch u.Scheme {
	case "udp", "tcp":
		return syslogSender(u.Scheme, u.Host)
	case "https", "http":
		return siemliteSender(u, token, tokenFile, caFile, insecure)
	}
	return nil, fmt.Errorf("-to must be an https:// URL, udp://host:port, tcp://host:port or stdout")
}

// find returns the first of names that exists, here or in /data.
func find(names ...string) string {
	for _, dir := range []string{".", "/data"} {
		for _, n := range names {
			if p := filepath.Join(dir, n); fileExists(p) {
				return p
			}
		}
	}
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func siemliteSender(u *url.URL, token, tokenFile, caFile string, insecure bool) (sendFunc, error) {
	if token == "" {
		if tokenFile == "" {
			tokenFile = find("siemlite-loggen.token")
		}
		if tokenFile == "" {
			return nil, errors.New("no access token: pass -token or -token-file (SIEMLite writes siemlite-loggen.token next to its database on first start; or create one on the Sources page)")
		}
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	if caFile == "" && !insecure {
		caFile = find("siemlite.crt")
	}
	if caFile != "" && !insecure {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(pem)
		tlsConf.RootCAs = pool
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf, MaxIdleConnsPerHost: 32}, Timeout: 30 * time.Second}
	endpoint := strings.TrimSuffix(u.String(), "/") + "/api/v1/logs"
	return func(ctx context.Context, lines []byte, n int) (int, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(lines))
		if err != nil {
			return 0, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, err
		}
		defer resp.Body.Close()
		var body struct {
			Accepted  int    `json:"accepted"`
			Rejected  int    `json:"rejected"`
			StoppedAt int    `json:"stopped_at_index"`
			Error     string `json:"error"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
		switch resp.StatusCode {
		case http.StatusAccepted:
			return n, 0, nil // rejected lines (if any) won't do better a second time
		case http.StatusServiceUnavailable:
			wait := time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			return body.StoppedAt, wait, nil
		}
		msg := body.Error
		if msg == "" {
			msg = resp.Status
		}
		return 0, 0, fmt.Errorf("%s: %s", endpoint, msg)
	}, nil
}

// syslogSender sends each line as an RFC 3164 message (local0.info), over UDP
// one datagram each or over TCP one line each.
func syslogSender(network, addr string) (sendFunc, error) {
	var mu sync.Mutex
	var conn net.Conn
	host, _ := os.Hostname()
	return func(ctx context.Context, lines []byte, n int) (int, time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		if conn == nil {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return 0, 0, err
			}
			conn = c
		}
		sent := 0
		for _, l := range bytes.Split(bytes.TrimSuffix(lines, []byte{'\n'}), []byte{'\n'}) {
			msg := fmt.Appendf(nil, "<134>%s %s loggen: %s", time.Now().Format(time.Stamp), host, l)
			if network == "tcp" {
				msg = append(msg, '\n')
			}
			if _, err := conn.Write(msg); err != nil {
				conn.Close()
				conn = nil
				return sent, 0, err
			}
			sent++
		}
		return sent, 0, nil
	}, nil
}
