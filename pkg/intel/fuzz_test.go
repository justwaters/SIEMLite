package intel

import (
	"strings"
	"testing"
)

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
