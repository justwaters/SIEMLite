package sample

import (
	"sort"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/enrich"
)

func TestGenerate(t *testing.T) {
	now := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	evs := Generate(now)
	if len(evs) < 300 {
		t.Fatalf("only %d events", len(evs))
	}

	e := NewEnricher()
	hosts, products := map[string]bool{}, map[string]bool{}
	var threats, geo, lastHour int
	matched := map[string]bool{}
	for _, ev := range evs {
		if err := ev.Prepare(); err != nil {
			t.Fatalf("invalid event %q: %v", ev.RawData, err)
		}
		at := time.UnixMilli(ev.Time)
		if at.After(now) || at.Before(now.Add(-25*time.Hour)) {
			t.Errorf("event outside the last day: %s %q", at, ev.RawData)
		}
		if at.After(now.Add(-time.Hour)) {
			lastHour++
		}
		hosts[ev.DeviceName()], products[ev.ProductName()] = true, true

		var d enrich.Data
		e.Enrich(ev, &d)
		if len(d.ThreatIntel) > 0 {
			threats++
			for _, m := range d.ThreatIntel {
				matched[m.Type] = true
			}
		}
		if d.Src.Country() != "" || d.Dst.Country() != "" {
			geo++
		}
	}
	if lastHour < 20 {
		t.Errorf("only %d events in the last hour; the default view would look empty", lastHour)
	}
	for _, typ := range []string{"ip", "cidr", "domain", "hash"} {
		if !matched[typ] {
			t.Errorf("no %s indicator matched", typ)
		}
	}
	if threats < 50 || geo < 100 {
		t.Errorf("threat hits = %d, geo hits = %d", threats, geo)
	}
	want := "db1,dc01,dns1,fw01,vpn1,web1,web2"
	if got := keys(hosts); got != want {
		t.Errorf("hosts = %s, want %s", got, want)
	}
	if !products["sshd"] || !products["nginx"] || !products["Microsoft Windows"] {
		t.Errorf("products = %s", keys(products))
	}

	// Same input, same output.
	if again := Generate(now); len(again) != len(evs) || again[100].RawData != evs[100].RawData {
		t.Error("Generate is not deterministic")
	}
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
