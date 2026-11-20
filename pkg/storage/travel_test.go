package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestEnsureTravelRuleIsIdempotentAndKeepsEdits(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	find := func() (rules []Rule) {
		list, err := repo.ListRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range list {
			if r.Name == TravelRuleName {
				rules = append(rules, r)
			}
		}
		return rules
	}
	for i := 0; i < 2; i++ {
		if err := repo.EnsureTravelRule(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := find()
	if len(got) != 1 {
		t.Fatalf("rules = %+v", got)
	}
	r := got[0]
	if !r.Builtin || !r.Enabled || r.Kind != RuleMatch || r.Severity != 4 || r.GroupBy != "user" || r.Threshold != 900 ||
		r.WindowMinutes != 1440 || r.Query != TravelRuleQuery || r.Description == "" {
		t.Errorf("rule = %+v", r)
	}
	// An administrator's edits survive another call (a restart).
	r.Severity, r.Enabled, r.Threshold, r.Query = 2, false, 500, "action=signin"
	if _, err := repo.SaveRule(ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnsureTravelRule(ctx); err != nil {
		t.Fatal(err)
	}
	got = find()
	if len(got) != 1 || got[0].Severity != 2 || got[0].Enabled || got[0].Threshold != 500 || got[0].Query != "action=signin" || !got[0].Builtin {
		t.Errorf("after the edit and another call: %+v", got)
	}
}
