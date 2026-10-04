package main

import (
	"context"
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
	st := run(ctx, 1000, 1, send, true)
	if st.sent.Load() != got.Load() || st.busy.Load() == 0 {
		t.Errorf("sent %d, received %d, busy %d", st.sent.Load(), got.Load(), st.busy.Load())
	}
	if n := got.Load(); n < 1700 || n > 2100 {
		t.Errorf("received %d lines in 2s at 1000/s", n)
	}
}
