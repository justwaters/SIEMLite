package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseEPS(t *testing.T) {
	for in, want := range map[string]float64{"1": 1, "10": 10, "100": 100, "1k": 1000, "10K": 10000, "100k": 100000, "1m": 1e6, "2.5k": 2500, "5eps": 5} {
		if got, err := parseEPS(in); err != nil || got != want {
			t.Errorf("parseEPS(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "-5", "fast", "11m"} {
		if _, err := parseEPS(bad); err == nil {
			t.Errorf("parseEPS(%q) accepted", bad)
		}
	}
}

// run keeps the rate, and a busy receiver loses nothing: lines it turned
// away are sent again.
func TestRunKeepsRateAndResends(t *testing.T) {
	var got atomic.Int64
	var calls atomic.Int64
	send := func(_ context.Context, lines []byte, n int) (int, time.Duration, error) {
		if calls.Add(1)%3 == 0 { // every third request: take half, ask to wait
			got.Add(int64(n / 2))
			return n / 2, 10 * time.Millisecond, nil
		}
		got.Add(int64(n))
		return n, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st := run(ctx, 1000, 1, send, true, time.Hour)
	if st.sent.Load() != got.Load() || st.busy.Load() == 0 {
		t.Errorf("sent %d, received %d, busy %d", st.sent.Load(), got.Load(), st.busy.Load())
	}
	if n := got.Load(); n < 1700 || n > 2100 {
		t.Errorf("received %d lines in 2s at 1000/s", n)
	}
}

// The rate holds over time: a stall makes up at most a second, so the total
// is close to the rate times the run, and a long outage doesn't end in a flood.
func TestRunMakesUpStallsBriefly(t *testing.T) {
	var got atomic.Int64
	var stalled atomic.Bool
	send := func(_ context.Context, lines []byte, n int) (int, time.Duration, error) {
		if stalled.CompareAndSwap(false, true) {
			time.Sleep(1500 * time.Millisecond) // the receiver hangs for 1.5s
		}
		got.Add(int64(n))
		return n, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	run(ctx, 500, 1, send, true, time.Hour)
	// 4s at 500/s is 2000; the stall's lost time is made up, but only up to
	// a second's worth, so the total lands between 1500 and 2000.
	if n := got.Load(); n < 1500 || n > 2100 {
		t.Errorf("received %d lines in 4s at 500/s with a 1.5s stall", n)
	}
}

// With -servername, the certificate is checked against that name instead of
// the host in the URL, which is how loggen reaches SIEMLite by its Compose
// service name while SIEMLite's certificate names localhost.
func TestServerNameChecksTheRightName(t *testing.T) {
	var got atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	// httptest's certificate is for 127.0.0.1 and example.com, so "localhost"
	// in the URL doesn't match it.
	url := "https://localhost:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	try := func(serverName string) error {
		send, err := sender(url, "slk_test", "", ca, false, serverName)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = send(context.Background(), []byte("a|b\n"), 1)
		return err
	}
	if err := try(""); err == nil {
		t.Error("a certificate for another name was accepted")
	}
	if err := try("example.com"); err != nil || got.Load() != 1 {
		t.Errorf("with -servername example.com: %v (requests %d)", err, got.Load())
	}
}
