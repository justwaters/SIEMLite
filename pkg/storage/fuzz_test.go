package storage

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzRepeatKeywords(f *testing.F) {
	f.Add("denied, failed, blocked")
	f.Add(`"bad password", ,"x"`)
	f.Add("a,A,a\x1e\n\"\"")
	f.Fuzz(func(t *testing.T, in string) {
		kw := RepeatKeywords(in)
		seen := map[string]bool{}
		for _, k := range kw {
			if k == "" || k != strings.TrimSpace(k) || strings.ContainsAny(k, `",`) || strings.Contains(k, "  ") {
				t.Fatalf("bad keyword %q from %q", k, in)
			}
			if p := KeywordPhrase(k); strings.Count(p, `"`) != 2 || !strings.HasPrefix(p, `"`) || !strings.HasSuffix(p, `"`) {
				t.Fatalf("phrase %q is not one quoted phrase", p)
			}
			if l := strings.ToLower(k); seen[l] {
				t.Fatalf("repeat %q from %q", k, in)
			} else {
				seen[l] = true
			}
		}
		if again := RepeatKeywords(strings.Join(kw, ", ")); !reflect.DeepEqual(again, kw) && len(kw) > 0 {
			t.Fatalf("not stable: %q then %q", kw, again)
		}
	})
}
