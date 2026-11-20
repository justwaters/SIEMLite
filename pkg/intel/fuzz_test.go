package intel

import (
	"net/netip"
	"strings"
	"testing"
	"unicode"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// clean reports whether s is non-empty with no whitespace or control characters.
func clean(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// FuzzNormalize: a normalized indicator is stable (normalizing it again
// gives the same value) and is never empty or padded.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"203.0.113.7", "203.0.113.0/24", "HTTPS://Evil.Example/x?y", "evil.example.", "::ffff:1.2.3.4",
		"2001:db8::/32", "\"bad.example\"", "a..b", "xn--80ak6aa92e.com", "1.2.3.4:80", "[2001:db8::1]:443"} {
		f.Add("", s)
		f.Add(TypeDomain, s)
	}
	f.Fuzz(func(t *testing.T, typ, value string) {
		gotType, v, err := Normalize(typ, value)
		if err != nil {
			return
		}
		if v == "" || strings.TrimSpace(v) != v || v != strings.ToLower(v) {
			t.Fatalf("Normalize(%q, %q) = %q", typ, value, v)
		}
		t2, v2, err := Normalize(gotType, v)
		if err != nil || t2 != gotType || v2 != v {
			t.Fatalf("not stable: %q -> (%s %q) -> (%s %q, %v)", value, gotType, v, t2, v2, err)
		}
	})
}

// FuzzParseFeed: any feed parses without panicking, every indicator is
// valid and none repeats.
func FuzzParseFeed(f *testing.F) {
	f.Add("# comment\n203.0.113.7\nip,description\n1.2.3.0/24 ; SBL123\n0.0.0.0 evil.example\nhttps://bad.example/x\n")
	f.Add("\"a\",\"b\"\n;;\n//\n\xff\xfe")
	f.Fuzz(func(t *testing.T, feed string) {
		inds, _, err := ParseFeed(strings.NewReader(feed), "", "fuzz", "")
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, in := range inds {
			typ, v, err := Normalize(in.Type, in.Value)
			if err != nil || typ != in.Type || v != in.Value {
				t.Fatalf("feed indicator %+v isn't normalized (%s %q %v)", in, typ, v, err)
			}
			if seen[in.Type+" "+in.Value] {
				t.Fatalf("duplicate %+v", in)
			}
			seen[in.Type+" "+in.Value] = true
		}
	})
}

// FuzzParseFeedValues: every indicator value a feed yields is clean (no space, control
// character or invalid UTF-8) and normalization is idempotent, with or without a forced type.
func FuzzParseFeedValues(f *testing.F) {
	for _, typ := range []string{"", TypeIP, TypeCIDR, TypeDomain, TypeHash} {
		f.Add(typ, "# Spamhaus\n1.2.3.0/24 ; SBL12345\n\n203.0.113.7,Possible Cobaltstrike C2 IP\n0.0.0.0 evil.example\n127.0.0.1\tbad.example\nhttps://user:pw@Bad.Example:8443/p?q#f\nd41d8cd98f00b204e9800998ecf8427e|x\n\"quoted.example\",1,2\n*.wild.example.\n[2001:db8::1]\n::ffff:1.2.3.4\n10.0.0.0/8 \x00\x01 note\n\xff\xfe.example\n\u00e9vil.example\n")
	}
	f.Add("", "ip,description\r\n1.1.1.1,\"a\tb\"\r\n//c\r\n;d\r\n"+strings.Repeat("a", 70000)+".com\n")
	f.Fuzz(func(t *testing.T, typ, feed string) {
		inds, skipped, err := ParseFeed(strings.NewReader(feed), typ, "src", "fallback")
		if err != nil {
			return
		}
		if skipped < 0 {
			t.Fatalf("skipped %d", skipped)
		}
		for _, in := range inds {
			if !clean(in.Value) || in.Value != strings.ToLower(in.Value) {
				t.Fatalf("bad value %q from %q", in.Value, feed)
			}
			if in.Type == "" || in.Source != "src" {
				t.Fatalf("bad indicator %+v", in)
			}
			if strings.ContainsAny(in.Description, "\r\n") {
				t.Fatalf("description has a line break: %q", in.Description)
			}
			t2, v2, err := Normalize(in.Type, in.Value)
			if err != nil || t2 != in.Type || v2 != in.Value {
				t.Fatalf("not idempotent: %+v -> %s %q %v", in, t2, v2, err)
			}
		}
	})
}

// FuzzLineNote: a note is the feed's fallback or text taken from the line, never longer than the cap.
func FuzzLineNote(f *testing.F) {
	f.Add("1.2.3.4,Possible Cobaltstrike C2 IP", "1.2.3.4", "fb")
	f.Add("1.2.0.0/16 ; SBL12345", "1.2.0.0/16", "")
	f.Add("0.0.0.0 evil.example", "evil.example", "fb")
	f.Add("1.2.3.4 \x00\xff\u2028"+strings.Repeat("\u00e9", 500), "1.2.3.4", "fb")
	f.Add("abc", "", "fb")
	f.Add("", "x", "")
	f.Fuzz(func(t *testing.T, line, indicator, fallback string) {
		got := lineNote(line, indicator, fallback)
		if got == fallback {
			return
		}
		if n := len([]rune(got)); n > 121 {
			t.Fatalf("note of %d runes", n)
		}
		if got == "" {
			t.Fatalf("empty note for %q %q", line, indicator)
		}
	})
}

// FuzzParseFriendly: friendly addresses come back normalized and clean, stable under another
// normalization, and without repeats; what was rejected is never empty.
func FuzzParseFriendly(f *testing.F) {
	f.Add("10.0.0.0/8, 192.168.1.5; 2001:db8::/32 # office\n::ffff:10.1.2.3\n::ffff:0:0/80\n1.2.3.4/32\n1.2.3.4/24\nfe80::1%eth0\n[::1]\n0.0.0.0/0\n::/0")
	f.Add("\r\n\t 8.8.8.8\u00a0 \x00 1.1.1.1\xff #")
	f.Add("1.2.3.4/33 ::1/129 01.2.3.4 1.2.3 ::ffff:1.2.3.4/200 ::ffff:1.2.3.4/96")
	f.Fuzz(func(t *testing.T, text string) {
		values, bad := ParseFriendly(text)
		seen := map[string]bool{}
		for _, v := range values {
			if !clean(v) {
				t.Fatalf("bad value %q", v)
			}
			if seen[v] {
				t.Fatalf("repeat %q", v)
			}
			seen[v] = true
			n, ok := normalizeFriendly(v)
			if !ok || n != v {
				t.Fatalf("not idempotent: %q -> %q %v", v, n, ok)
			}
			if p, err := netip.ParsePrefix(v); err == nil && p != p.Masked() {
				t.Fatalf("host bits set in %q", v)
			}
			if a, err := netip.ParseAddr(v); err == nil && (a.Is4In6() || a.Zone() != "") {
				t.Fatalf("not canonical: %q", v)
			}
		}
		for _, b := range bad {
			if b == "" {
				t.Fatal("empty bad token")
			}
		}
		again, bad2 := ParseFriendly(strings.Join(values, "\n"))
		if len(bad2) != 0 || strings.Join(again, "\n") != strings.Join(values, "\n") {
			t.Fatalf("re-parse changed %q -> %q (bad %q)", values, again, bad2)
		}
	})
}

// FuzzMatcher: loading arbitrary indicators and friendly addresses and checking arbitrary
// addresses and text never panics, matches are clean, and a friendly address is never flagged,
// even when it is also listed as an indicator.
func FuzzMatcher(f *testing.F) {
	f.Add("203.0.113.0/24", "10.0.0.0/8\n192.168.1.1", "203.0.113.9", "10.1.2.3", "see evil.example and 203.0.113.9 d41d8cd98f00b204e9800998ecf8427e", "evil.example")
	f.Add("10.0.0.0/8", "10.0.0.0/8", "10.1.2.3", "::ffff:10.1.2.3", "10.9.9.9", "ip")
	f.Add("::ffff:1.2.3.4", "1.2.3.4", "1.2.3.4", "::ffff:1.2.3.4", "1.2.3.4", "")
	f.Add("2001:db8::/32", "2001:db8::1", "2001:db8::1", "2001:db8::2", "", "x")
	f.Add("0.0.0.0/0", "0.0.0.0/0", "8.8.8.8", "fe80::1%en0", "999.1.1.1 1.1.1.1.1 \x00", "cidr")
	f.Fuzz(func(t *testing.T, indicator, friendlyText, src, dst, raw, typ string) {
		friendly, _ := ParseFriendly(friendlyText)
		var inds []storage.Indicator
		add := func(typ, v string) {
			if tt, nv, err := Normalize(typ, v); err == nil {
				inds = append(inds, storage.Indicator{Type: tt, Value: nv, Source: "s", Description: "d"})
			}
		}
		add(typ, indicator)
		add("", indicator)
		for _, fr := range friendly {
			add("", fr) // the friendly ranges are listed as threats too
		}
		m := NewMatcher()
		m.Load(inds, friendly)
		var fnet []netip.Prefix
		for _, fr := range friendly {
			if p, err := netip.ParsePrefix(fr); err == nil {
				fnet = append(fnet, p)
			} else if a, err := netip.ParseAddr(fr); err == nil {
				fnet = append(fnet, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		isFriendly := func(ip string) bool {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				return false
			}
			a = a.Unmap()
			for _, p := range fnet {
				if p.Contains(a) {
					return true
				}
			}
			return false
		}
		ev := &ocsf.Event{SrcEndpoint: &ocsf.Endpoint{IP: src}, DstEndpoint: &ocsf.Endpoint{IP: dst}, RawData: raw}
		var d enrich.Data
		m.Enrich(ev, &d)
		if len(d.ThreatIntel) > maxMatches {
			t.Fatalf("%d matches", len(d.ThreatIntel))
		}
		for _, mt := range d.ThreatIntel {
			if !clean(mt.Value) || !clean(mt.Matched+"x") || mt.Type == "" || mt.Field == "" {
				t.Fatalf("bad match %+v", mt)
			}
			var ip string
			switch mt.Field {
			case "src_endpoint.ip":
				ip = src
			case "dst_endpoint.ip":
				ip = dst
			}
			if ip != "" && isFriendly(ip) {
				t.Fatalf("friendly address %q flagged: %+v (friendly %q)", ip, mt, friendly)
			}
			if mt.Field == "raw_data" && (mt.Type == TypeIP || mt.Type == TypeCIDR) && isFriendly(mt.Matched) {
				t.Fatalf("friendly address %q flagged in text: %+v", mt.Matched, mt)
			}
		}
	})
}
