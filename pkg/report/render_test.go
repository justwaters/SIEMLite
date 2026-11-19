package report

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

func render(t *testing.T, d *Data) []byte {
	t.Helper()
	b, err := d.PDF()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var streamRe = regexp.MustCompile(`(?s)stream\n(.*?)\nendstream`)

// pageTexts decompresses every content stream.
func pageTexts(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	for _, m := range streamRe.FindAllSubmatch(b, -1) {
		r, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(raw))
	}
	return out
}

func checkStructure(t *testing.T, b []byte) int {
	t.Helper()
	s := string(b)
	if !strings.HasPrefix(s, "%PDF-1.4") || !strings.HasSuffix(s, "%%EOF\n") {
		t.Fatal("bad header or trailer")
	}
	i := strings.LastIndex(s, "startxref\n")
	off, err := strconv.Atoi(strings.Fields(s[i+len("startxref\n"):])[0])
	if err != nil || !strings.HasPrefix(s[off:], "xref\n0 ") {
		t.Fatal("startxref does not point at the xref table")
	}
	lines := strings.Split(s[off:], "\n")
	size, _ := strconv.Atoi(strings.Fields(lines[1])[1])
	for n := 1; n < size; n++ {
		o, err := strconv.Atoi(strings.Fields(lines[2+n])[0])
		if err != nil || !strings.HasPrefix(s[o:], fmt.Sprintf("%d 0 obj", n)) {
			t.Fatalf("xref entry %d is wrong", n)
		}
	}
	if !strings.Contains(s, fmt.Sprintf("/Size %d", size)) {
		t.Fatal("trailer /Size mismatch")
	}
	pages := strings.Count(s, "/Type /Page ")
	m := regexp.MustCompile(`/Type /Pages /Count (\d+)`).FindStringSubmatch(s)
	if m == nil || m[1] != strconv.Itoa(pages) {
		t.Fatalf("/Pages count %v vs %d page objects", m, pages)
	}
	if len(pageTexts(t, b)) != pages {
		t.Fatal("content stream count differs from page count")
	}
	return pages
}

func TestStructure(t *testing.T) {
	b := render(t, sampleData())
	if n := checkStructure(t, b); n < 2 {
		t.Fatalf("expected a multi-page sample, got %d", n)
	}
	if !bytes.Equal(b, render(t, sampleData())) {
		t.Fatal("output is not deterministic")
	}
}

func TestContent(t *testing.T) {
	d := sampleData()
	b := render(t, d)
	n := checkStructure(t, b)
	all := strings.Join(pageTexts(t, b), "\n")
	for _, want := range []string{
		"SIEMLite security report", "SSH brute force", "185.220.101.4", "Source IP: 185.220.101.4",
		"Spamhaus DROP", "Top sources", "Top countries", "Threat-listed addresses", "Alerts opened",
		fmt.Sprintf("Page 1 of %d", n), fmt.Sprintf("Page %d of %d", n, n), "SIEMLite v0.52", "and 12 more alerts not listed",
		"83,570", "Generated ", "siem-edge-01",
	} {
		if !strings.Contains(all, want) && !strings.Contains(all, strings.ReplaceAll(want, "…", `\205`)) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(all, "Page 1 of 2") {
		t.Errorf("sample should be two pages, got %d", n)
	}
}

func TestEmptyMessages(t *testing.T) {
	all := strings.Join(pageTexts(t, render(t, &Data{})), "\n")
	for _, want := range []string{"None in this period.", "No feeds are turned on.", "No events in this period.", "Page 1 of 1"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRobustness(t *testing.T) {
	long := strings.Repeat("A very long string without end ", 330)[:10000]
	cases := map[string]func() *Data{
		"empty":        func() *Data { return &Data{} },
		"zero buckets": func() *Data { d := sampleData(); d.Buckets = nil; return d },
		"one bucket": func() *Data {
			d := sampleData()
			d.Buckets = d.Buckets[:1]
			return d
		},
		"all zero buckets": func() *Data {
			d := sampleData()
			for i := range d.Buckets {
				d.Buckets[i].Count, d.Buckets[i].Threats = 0, 0
			}
			return d
		},
		"huge strings": func() *Data {
			d := sampleData()
			d.Title, d.Host, d.Version = long, long, long
			d.Feeds = []string{long, long}
			d.TopSources[0].Name = long
			d.TopThreats[0].Country = long
			d.Alerts.List[0].RuleName, d.Alerts.List[0].GroupValue, d.Alerts.List[0].Status = long, long, long
			d.Alerts.ByStatus[long] = 3
			return d
		},
		"non-latin": func() *Data {
			d := sampleData()
			d.Title = "安全レポート \U0001F6E1 Русский"
			d.Alerts.List[0].RuleName = "สวัสดี مرحبا café"
			d.Feeds = []string{"フィード"}
			return d
		},
		"40 alerts": func() *Data {
			d := sampleData()
			for len(d.Alerts.List) < 40 {
				d.Alerts.List = append(d.Alerts.List, d.Alerts.List[len(d.Alerts.List)%25])
			}
			return d
		},
		"31 daily": func() *Data {
			d := sampleData()
			d.Buckets = nil
			for i := 0; i < 31; i++ {
				d.Buckets = append(d.Buckets, storage.Bucket{Start: time.Date(2026, 10, 1+i, 0, 0, 0, 0, time.Local).UnixMilli(), Count: int64(100 * (i + 1)), Threats: int64(i)})
			}
			return d
		},
		"24 hourly": func() *Data {
			d := sampleData()
			d.BucketMs = 3600_000
			d.Buckets = nil
			for i := 0; i < 24; i++ {
				d.Buckets = append(d.Buckets, storage.Bucket{Start: time.Date(2026, 11, 17, i, 0, 0, 0, time.Local).UnixMilli(), Count: int64(50 + i*7), Threats: int64(i % 5)})
			}
			return d
		},
		"many ranked": func() *Data {
			d := sampleData()
			for i := 0; i < 30; i++ {
				d.TopSources = append(d.TopSources, storage.NamedCount{Name: fmt.Sprint("host", i), Count: int64(i)})
				d.TopThreats = append(d.TopThreats, storage.ThreatSummary{IP: fmt.Sprint("1.2.3.", i), Count: 1})
			}
			return d
		},
		"negative or odd": func() *Data {
			d := sampleData()
			d.Total = 0
			d.BySeverity = map[int]int64{9: 4, 1: 2}
			d.Alerts.List[0].Severity = 42
			return d
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			b := render(t, mk())
			checkStructure(t, b)
		})
	}
}

func TestNoContentIntoFooter(t *testing.T) {
	d := sampleData()
	for len(d.Alerts.List) < 40 {
		d.Alerts.List = append(d.Alerts.List, d.Alerts.List[len(d.Alerts.List)%25])
	}
	b := render(t, d)
	n := checkStructure(t, b)
	if n < 3 {
		t.Fatalf("expected 3+ pages, got %d", n)
	}
	// Every page has the footer and a repeated table header after the first alerts page.
	texts := pageTexts(t, b)
	for i, s := range texts {
		if !strings.Contains(s, fmt.Sprintf("(Page %d of %d)", i+1, n)) {
			t.Errorf("page %d lacks its footer", i+1)
		}
	}
	if c := strings.Count(strings.Join(texts, ""), "(WHO / WHAT)"); c < 2 {
		t.Errorf("table header appears %d times, want it repeated after a page break", c)
	}
	// Rectangles and text baselines stay above the footer rule (PDF y from the bottom).
	reY := regexp.MustCompile(`([\d.]+) ([\d.]+) Td \((?:[^()\\]|\\.)*\) Tj`)
	for i, s := range texts {
		for _, m := range reY.FindAllStringSubmatch(s, -1) {
			y, _ := strconv.ParseFloat(m[2], 64)
			if y < 46 && !strings.Contains(m[0], "Page ") && !strings.Contains(m[0], "SIEMLite v") {
				t.Errorf("page %d: text at y=%v inside the footer", i+1, y)
			}
		}
	}
}

func TestNum(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -4321: "-4,321"} {
		if got := num(in); got != want {
			t.Errorf("num(%d)=%q want %q", in, got, want)
		}
	}
}
