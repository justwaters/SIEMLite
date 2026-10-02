package intel

import (
	"strings"
	"testing"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

func TestNormalize(t *testing.T) {
	for _, tc := range []struct{ typ, in, wantType, want string }{
		{"", "203.0.113.7", TypeIP, "203.0.113.7"},
		{"", "::ffff:203.0.113.7", TypeIP, "203.0.113.7"},
		{"", "198.51.100.17/24", TypeCIDR, "198.51.100.0/24"},
		{"", "10.0.0.1/32", TypeIP, "10.0.0.1"},
		{"", "Evil.Example.", TypeDomain, "evil.example"},
		{"", "https://user@bad.example:8443/payload.exe?x=1", TypeDomain, "bad.example"},
		{"", "D41D8CD98F00B204E9800998ECF8427E", TypeHash, "d41d8cd98f00b204e9800998ecf8427e"},
		{TypeDomain, "*.tracker.example", TypeDomain, "tracker.example"},
	} {
		typ, v, err := Normalize(tc.typ, tc.in)
		if err != nil || typ != tc.wantType || v != tc.want {
			t.Errorf("Normalize(%q, %q) = %q, %q, %v; want %q, %q", tc.typ, tc.in, typ, v, err, tc.wantType, tc.want)
		}
	}
	for _, bad := range []struct{ typ, in string }{{TypeIP, "evil.example"}, {TypeHash, "abc"}, {"", "not a thing"}, {"url", "x"}} {
		if _, _, err := Normalize(bad.typ, bad.in); err == nil {
			t.Errorf("Normalize(%q, %q) accepted", bad.typ, bad.in)
		}
	}
}

func TestParseFeed(t *testing.T) {
	feed := `# Feodo Tracker style
first_seen,dst_ip,port
203.0.113.7
198.51.100.0/24 ; SBL12345
0.0.0.0 ads.example
http://malware.example/x.exe
garbage line!
203.0.113.7
`
	inds, skipped, err := ParseFeed(strings.NewReader(feed), "", "test", "desc")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, in := range inds {
		got = append(got, in.Type+":"+in.Value)
		if in.Source != "test" || in.Description != "desc" {
			t.Errorf("indicator %+v lost source/description", in)
		}
	}
	want := "ip:203.0.113.7 cidr:198.51.100.0/24 domain:ads.example domain:malware.example"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v\nwant %s", got, want)
	}
	if skipped != 2 { // CSV header and garbage
		t.Errorf("skipped = %d, want 2", skipped)
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher()
	m.Load([]storage.Indicator{
		{Type: TypeIP, Value: "203.0.113.7", Source: "feodo", Description: "botnet C2"},
		{Type: TypeCIDR, Value: "198.51.100.0/24", Source: "drop"},
		{Type: TypeCIDR, Value: "2001:db8::/32", Source: "drop"},
		{Type: TypeDomain, Value: "evil.example", Source: "urlhaus"},
		{Type: TypeHash, Value: strings.Repeat("ab", 32), Source: "mb"},
	})
	if m.Size() != 5 {
		t.Fatalf("size = %d", m.Size())
	}

	match := func(ev *ocsf.Event) []enrich.IntelMatch {
		var d enrich.Data
		m.Enrich(ev, &d)
		return d.ThreatIntel
	}
	ev := &ocsf.Event{SrcEndpoint: &ocsf.Endpoint{IP: "203.0.113.7"}, DstEndpoint: &ocsf.Endpoint{IP: "198.51.100.42"},
		RawData: "conn 203.0.113.7 -> 198.51.100.42"}
	got := match(ev)
	if len(got) != 2 || got[0].Field != "src_endpoint.ip" || got[0].Description != "botnet C2" ||
		got[1].Value != "198.51.100.0/24" || got[1].Matched != "198.51.100.42" {
		t.Errorf("ip matches = %+v", got)
	}

	if got := match(&ocsf.Event{SrcEndpoint: &ocsf.Endpoint{IP: "2001:db8::1"}}); len(got) != 1 {
		t.Errorf("v6 cidr matches = %+v", got)
	}
	got = match(&ocsf.Event{RawData: "GET http://cdn.EVIL.example/a.js from 10.0.0.2"})
	if len(got) != 1 || got[0].Value != "evil.example" || got[0].Matched != "cdn.evil.example" || got[0].Field != "raw_data" {
		t.Errorf("subdomain matches = %+v", got)
	}
	if got := match(&ocsf.Event{RawData: "notevil.example and evil.example.org"}); len(got) != 0 {
		t.Errorf("lookalike domains matched: %+v", got)
	}
	if got := match(&ocsf.Event{RawData: "sha256=" + strings.Repeat("AB", 32)}); len(got) != 1 || got[0].Type != TypeHash {
		t.Errorf("hash matches = %+v", got)
	}
	if got := match(&ocsf.Event{RawData: "all quiet 10.1.2.3"}); len(got) != 0 {
		t.Errorf("unexpected matches = %+v", got)
	}
}
