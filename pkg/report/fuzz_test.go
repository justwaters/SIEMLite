package report

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

// fuzzSource answers Build with whatever the fuzzer supplied, shaped the way the real store
// shapes it (every bucket present, oldest first).
type fuzzSource struct {
	name, ip string
	sev      int
	count    int64
	alerts   int
}

func (s fuzzSource) Overview(_ context.Context, start, end, bucket int64, _ storage.Filter) (*storage.Overview, error) {
	ov := &storage.Overview{BySeverity: map[int]int64{s.sev: s.count}, Total: s.count, Threats: s.count / 2}
	for t := start; t < end && len(ov.Buckets) < 400; t += bucket {
		ov.Buckets = append(ov.Buckets, storage.Bucket{Start: t, Count: s.count, Threats: s.count / 3})
	}
	ov.TopSources = []storage.NamedCount{{Name: s.name, Count: s.count}, {Name: s.ip, Count: -s.count}}
	ov.TopCountry = []storage.NamedCount{{Name: s.name, Count: 1}}
	ov.TopThreats = []storage.ThreatSummary{{IP: s.ip, Country: s.name, Count: s.count}}
	return ov, nil
}

func (s fuzzSource) AlertsInRange(_ context.Context, from, to int64, limit int) ([]storage.Alert, int64, map[int]int64, map[string]int64, error) {
	var list []storage.Alert
	for i := 0; i < s.alerts && i < limit; i++ {
		list = append(list, storage.Alert{ID: int64(i), RuleName: s.name, Severity: s.sev + i, GroupBy: s.ip, GroupValue: s.name + s.ip, Status: s.name, Count: s.count, CreatedAt: from + int64(i)})
	}
	return list, int64(s.alerts) * 3, map[int]int64{s.sev: s.count}, map[string]int64{s.name: s.count}, nil
}

// FuzzBuildAndRender: building a report from arbitrary titles, names and numbers, and drawing it
// as text and as a PDF, never panics, gives a PDF with a header, a trailer and a startxref that
// points at the xref table, and gives the same bytes twice.
func FuzzBuildAndRender(f *testing.F) {
	f.Add("SIEMLite security report", "host-01", "Spamhaus DROP", "SSH brute force (root)", "10.0.0.1", int8(4), int64(1234), int64(1_700_000_000_000), int64(86_400_000), int64(1_700_086_400_000), uint8(5))
	f.Add("", "", "", "", "", int8(0), int64(0), int64(0), int64(1), int64(0), uint8(0))
	f.Add("\xff\xfe) Tj ET (\\", "h\x00", "f\r\n", strings.Repeat("(", 3000), strings.Repeat("\\", 3000), int8(-7), int64(-1<<62), int64(-5e12), int64(366*86_400_000), int64(1<<62), uint8(60))
	f.Add(strings.Repeat("W", 50000), strings.Repeat("é", 20000), "‮́", "\U0001F600", "::1", int8(127), int64(1<<62), int64(1<<50), int64(3*86_400_000), int64(-1), uint8(40))
	f.Fuzz(func(t *testing.T, title, host, feed, name, ip string, sev int8, count, start, span, nowMs int64, nAlerts uint8) {
		if span <= 0 || span > MaxPeriodDays*24*3600_000 || start < -1<<50 || start > 1<<50 {
			span = 3600_000
			if start < -1<<50 || start > 1<<50 {
				start = 0
			}
		}
		src := fuzzSource{name: name, ip: ip, sev: int(sev), count: count, alerts: int(nAlerts % 80)}
		now := time.UnixMilli(nowMs)
		d, err := Build(context.Background(), src, start, start+span, "v1", host, []string{feed, name}, now)
		if err != nil {
			t.Fatal(err)
		}
		d.Title = title
		if txt := d.Text(); !strings.HasSuffix(txt, "attached as a PDF.\n") {
			t.Fatalf("text: %q", txt)
		}
		b, err := d.PDF()
		if err != nil {
			t.Fatal(err)
		}
		checkPDF(t, b)
		b2, err := d.PDF()
		if err != nil || !bytes.Equal(b, b2) {
			t.Fatalf("not deterministic (%v)", err)
		}
		if _, err := Build(context.Background(), src, start, start, "v", "", nil, now); err == nil {
			t.Fatal("empty period accepted")
		}
	})
}

func checkPDF(t *testing.T, b []byte) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("%PDF-")) || !bytes.HasSuffix(bytes.TrimRight(b, "\r\n"), []byte("%%EOF")) {
		t.Fatal("bad header or trailer")
	}
	i := bytes.LastIndex(b, []byte("startxref\n"))
	var at int
	if i < 0 {
		t.Fatal("no startxref")
	}
	if _, err := fmt.Sscanf(string(b[i+10:]), "%d", &at); err != nil || at <= 0 || at >= len(b) || !bytes.HasPrefix(b[at:], []byte("xref\n")) {
		t.Fatalf("startxref %d (%v)", at, err)
	}
}

// FuzzNextRun: for any schedule that Validate accepts, in any time zone, the next run is strictly
// after the moment asked about, within about a month, the same every time, and successive runs
// keep moving forward.
func FuzzNextRun(f *testing.F) {
	f.Add("daily", 9, 0, 1, int64(1_700_000_000), "UTC", 0)
	f.Add("weekly", 2, 6, 1, int64(1_710_054_000), "America/New_York", 0)   // around a US DST change
	f.Add("monthly", 3, 0, 28, int64(1_711_846_800), "Europe/London", 0)    // around a UK DST change
	f.Add("daily", 2, 0, 1, int64(1_729_998_000), "Australia/Lord_Howe", 0) // half-hour DST
	f.Add("weekly", 0, 0, 1, int64(-62135596800), "Pacific/Apia", 0)        // year 1
	f.Add("monthly", 23, 3, 28, int64(253402300799), "Asia/Kolkata", 19800) // year 9999
	f.Add("daily", 12, 0, 1, int64(0), "not/a/zone", -43200)
	f.Add("hourly", 24, 7, 29, int64(1), "", 99999)
	f.Fuzz(func(t *testing.T, freq string, hour, weekday, dom int, sec int64, tz string, offset int) {
		loc, err := time.LoadLocation(tz)
		if err != nil || tz == "" {
			loc = time.FixedZone("x", offset%(26*3600))
		}
		if sec < -62135596800+400*86400 || sec > 253402300799-400*86400 {
			sec = 0
		}
		from := time.Unix(sec, 0)
		s := New(nil, nil, nil, "v", nil)
		s.now = func() time.Time { return from }
		s.loc = loc
		in := storage.ReportSchedule{Name: "n", Frequency: freq, Hour: hour, Weekday: weekday, DayOfMonth: dom, CoversDays: 7, Recipients: "a@example.com"}
		out, err := s.Validate(in)
		if err != nil {
			return
		}
		next := time.UnixMilli(out.NextRun)
		if !next.After(from) {
			t.Fatalf("%+v from %v in %s: next %v is not after", in, from, loc, next)
		}
		if next.Sub(from) > 32*24*time.Hour {
			t.Fatalf("%+v from %v: next %v is more than a month away", in, from, next)
		}
		got := NextRun(out, from, loc)
		if !got.After(from) || got.UnixMilli() != out.NextRun || !got.Equal(NextRun(out, from, loc)) {
			t.Fatalf("NextRun %v vs validated %v (from %v)", got, next, from)
		}
		prev := got
		for i := 0; i < 6; i++ {
			n := NextRun(out, prev, loc)
			if !n.After(prev) || n.Sub(prev) > 32*24*time.Hour {
				t.Fatalf("%+v: run %d after %v gave %v", in, i, prev, n)
			}
			prev = n
		}
	})
}

// FuzzValidateSchedule: arbitrary schedule fields never panic; an accepted schedule has tidy
// recipients and a next run in the future.
func FuzzValidateSchedule(f *testing.F) {
	f.Add("Weekly", "weekly", -1, 24, 0, 7, "a@example.com, b@example.com;a@example.com", true)
	f.Add("", "", 0, 0, 0, 0, "", false)
	f.Add("n\x00", "daily", 5, 5, 5, 1, "x@y.z\r\nBcc: evil@example.com", true)
	f.Add(strings.Repeat("é", 81), "monthly", 0, 0, 29, 30, "Name <a@example.com>", true)
	f.Add("ok", "daily", 0, 23, 1, 365, strings.Repeat("a@example.com ", 11), true)
	f.Fuzz(func(t *testing.T, name, freq string, weekday, hour, dom, days int, rcpts string, enabled bool) {
		s := New(nil, nil, nil, "v", nil)
		now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
		s.now = func() time.Time { return now }
		out, err := s.Validate(storage.ReportSchedule{Name: name, Frequency: freq, Weekday: weekday, Hour: hour, DayOfMonth: dom, CoversDays: days, Recipients: rcpts, Enabled: enabled})
		if err != nil {
			return
		}
		if out.NextRun <= now.UnixMilli() {
			t.Fatalf("next run %d not after now", out.NextRun)
		}
		if strings.ContainsAny(out.Recipients, "\r\n") || strings.TrimSpace(out.Name) != out.Name || out.Name == "" {
			t.Fatalf("untidy %+v", out)
		}
		n := 0
		for _, r := range strings.Split(out.Recipients, ", ") {
			if r != "" {
				n++
			}
			if strings.ContainsAny(r, "<>\"") {
				t.Fatalf("recipient %q", r)
			}
		}
		if n > MaxRecipients {
			t.Fatalf("%d recipients", n)
		}
	})
}

// FuzzRecipientsAndFileName: arbitrary address lists and times never panic, and a download name
// is always a plain safe file name.
func FuzzRecipientsAndFileName(f *testing.F) {
	f.Add("a@example.com b@example.com", int64(1_700_000_000_000), "UTC")
	f.Add("\"a b\"@example.com,<x@y>", int64(0), "")
	f.Add("a@b\r\nBcc: c@d", int64(-1<<62), "Asia/Tokyo")
	f.Fuzz(func(t *testing.T, raw string, end int64, tz string) {
		if r, err := Recipients(raw); err == nil {
			for _, a := range r {
				if strings.ContainsAny(a, "\r\n\x00 ,;") {
					t.Fatalf("recipient %q", a)
				}
			}
		}
		loc, _ := time.LoadLocation(tz)
		name := FileName(storage.ReportRun{PeriodEnd: end}, loc)
		if !strings.HasPrefix(name, "siemlite-report-") || !strings.HasSuffix(name, ".pdf") || strings.ContainsAny(name, "/\\ \r\n\x00\"") {
			t.Fatalf("file name %q", name)
		}
	})
}
