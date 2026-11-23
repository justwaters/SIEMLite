package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRepeatKeywords(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"denied, failed, blocked", []string{"denied", "failed", "blocked"}},
		{"  denied ,, failed  ,", []string{"denied", "failed"}},
		{"Denied, denied, DENIED", []string{"Denied"}},
		{`bad   password, "quoted"`, []string{"bad password", "quoted"}},
		{"", nil},
		{" , ,", nil},
		{`"`, nil},
	}
	for _, c := range cases {
		if got := RepeatKeywords(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("RepeatKeywords(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := RepeatSearch("a, bad password"); got != `"a" OR "bad password"` {
		t.Errorf("RepeatSearch = %q", got)
	}
}

func TestRepeatRuleStoredAsAMatchRule(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	for _, kind := range []string{RuleRepeatSeverity, RuleRepeatKeyword, RuleRepeatBoth} {
		ru := Rule{Name: kind, Kind: kind, Enabled: true, Severity: 3, Query: "denied, failed", GroupBy: "host", Threshold: 5, WindowMinutes: 10}
		id, err := repo.SaveRule(ctx, ru, 1)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		got, err := repo.GetRule(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind != kind || got.Query != "denied, failed" || got.GroupBy != "user" || !got.IsRepeat() {
			t.Errorf("%s: read back %+v", kind, got)
		}
		// Editing to another kind and back keeps it readable.
		ru.ID, ru.Kind, ru.Query = id, RuleMatch, "plain"
		if _, err := repo.SaveRule(ctx, ru, 2); err != nil {
			t.Fatal(err)
		}
		if got, _ = repo.GetRule(ctx, id); got.Kind != RuleMatch || got.Query != "plain" {
			t.Errorf("%s: edited to match: %+v", kind, got)
		}
	}
}

// Repeat rules count per user and per level, leaving out events with no user.
func TestRepeatGroupsBySeverityAndIgnoresNoUser(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	rec := func(user string, sev int, ts int64) Record {
		return Record{Timestamp: ts, CategoryUID: 3, ClassUID: 3002, SeverityID: sev, UserName: user, Message: "m", RawData: "m"}
	}
	if err := repo.InsertBatch(ctx, []Record{rec("a", 4, 1_000_000), rec("a", 4, 1_001_000), rec("a", 2, 1_002_000), rec("", 4, 1_003_000)}); err != nil {
		t.Fatal(err)
	}
	top, _ := repo.MaxEventSeq(ctx)
	ru := Rule{GroupBy: "user", BySeverity: true, NeedGroup: true, Name: "x"}
	groups, err := repo.NewMatches(ctx, ru, 0, top)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, g := range groups {
		got[g.Value] = g.New
	}
	want := map[string]int64{"a" + GroupSep + "4": 2, "a" + GroupSep + "2": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("groups = %v, want %v", got, want)
	}
}
