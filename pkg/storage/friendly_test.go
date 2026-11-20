package storage

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

// openTempTB is openTemp for anything with a testing.TB (a fuzz target opens its store once).
func openTempTB(tb testing.TB) (*DB, *Repository) {
	tb.Helper()
	db, err := Open(context.Background(), Options{Path: filepath.Join(tb.TempDir(), "siemlite.db")})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { db.Close() })
	return db, NewRepository(db)
}

func intelVer(t *testing.T, repo *Repository) int64 {
	t.Helper()
	v, err := repo.IntelVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFriendlyListLifecycle(t *testing.T) {
	ctx := context.Background()
	_, repo := openTemp(t)

	id, err := repo.CreateFriendlyList(ctx, "Office", "our office", 100)
	if err != nil || id == 0 {
		t.Fatalf("create: %d %v", id, err)
	}
	if _, err := repo.CreateFriendlyList(ctx, "Office", "dup", 101); !errors.Is(err, ErrFriendlyNameTaken) {
		t.Errorf("duplicate name: got %v, want ErrFriendlyNameTaken", err)
	}
	id2, err := repo.CreateFriendlyList(ctx, "Partner", "", 102)
	if err != nil {
		t.Fatal(err)
	}

	// Update: rename, collide, and unknown id; only a real change bumps the intel version.
	v0 := intelVer(t, repo)
	if err := repo.UpdateFriendlyList(ctx, id, "HQ", "headquarters"); err != nil {
		t.Fatal(err)
	}
	if v := intelVer(t, repo); v != v0+1 {
		t.Errorf("update bumped intel version %d -> %d, want +1", v0, v)
	}
	if err := repo.UpdateFriendlyList(ctx, id, "Partner", "x"); !errors.Is(err, ErrFriendlyNameTaken) {
		t.Errorf("rename onto existing: got %v", err)
	}
	if err := repo.UpdateFriendlyList(ctx, 9999, "Nope", ""); !errors.Is(err, ErrFriendlyListNotFound) {
		t.Errorf("update unknown: got %v", err)
	}
	if v := intelVer(t, repo); v != v0+1 {
		t.Errorf("failed updates must not bump the version, got %d", v)
	}

	// Entries: dedupe within a call and across calls, per-list scoping.
	n, err := repo.AddFriendlyEntries(ctx, id, []string{"1.2.3.4", "10.0.0.0/8", "1.2.3.4"}, "n", 200)
	if err != nil || n != 2 {
		t.Fatalf("add: n=%d err=%v, want 2", n, err)
	}
	if n, _ := repo.AddFriendlyEntries(ctx, id, []string{"1.2.3.4", "5.6.7.8"}, "other", 300); n != 1 {
		t.Errorf("second add new=%d, want 1", n)
	}
	if n, err := repo.AddFriendlyEntries(ctx, id2, []string{"1.2.3.4"}, "", 400); err != nil || n != 1 {
		t.Errorf("same value in another list: n=%d err=%v, want 1", n, err)
	}
	if n, err := repo.AddFriendlyEntries(ctx, id, nil, "", 500); err != nil || n != 0 {
		t.Errorf("empty add: n=%d err=%v", n, err)
	}
	if _, err := repo.AddFriendlyEntries(ctx, 9999, []string{"1.1.1.1"}, "", 1); !errors.Is(err, ErrFriendlyListNotFound) {
		t.Errorf("add to unknown list: %v", err)
	}

	lists, err := repo.FriendlyLists(ctx)
	if err != nil || len(lists) != 2 {
		t.Fatalf("lists: %v %v", lists, err)
	}
	// by name, case-insensitive: HQ, Partner
	if lists[0].Name != "HQ" || lists[0].Description != "headquarters" || lists[1].Name != "Partner" {
		t.Errorf("order/fields: %+v", lists)
	}
	if len(lists[0].Entries) != 3 || len(lists[1].Entries) != 1 {
		t.Errorf("entry counts %d/%d, want 3/1", len(lists[0].Entries), len(lists[1].Entries))
	}
	// newest first, and the first add's note is kept for the duplicate
	if lists[0].Entries[0].Value != "5.6.7.8" || lists[0].Entries[0].Note != "other" {
		t.Errorf("newest entry: %+v", lists[0].Entries[0])
	}
	for _, e := range lists[0].Entries {
		if e.Value == "1.2.3.4" && (e.Note != "n" || e.CreatedAt != 200) {
			t.Errorf("duplicate overwrote the original: %+v", e)
		}
	}

	vals, err := repo.FriendlyValues(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(vals)
	if want := []string{"1.2.3.4", "10.0.0.0/8", "5.6.7.8"}; !slices.Equal(vals, want) {
		t.Errorf("FriendlyValues = %v, want %v (distinct across lists)", vals, want)
	}

	// DeleteFriendlyEntry
	v1 := intelVer(t, repo)
	if ok, err := repo.DeleteFriendlyEntry(ctx, id, "10.0.0.0/8"); err != nil || !ok {
		t.Errorf("delete entry: %v %v", ok, err)
	}
	if intelVer(t, repo) != v1+1 {
		t.Error("deleting an entry should bump the intel version")
	}
	if ok, err := repo.DeleteFriendlyEntry(ctx, id, "10.0.0.0/8"); err != nil || ok {
		t.Errorf("delete again: %v %v, want false", ok, err)
	}
	if intelVer(t, repo) != v1+1 {
		t.Error("a no-op delete must not bump the intel version")
	}
	if ok, _ := repo.DeleteFriendlyEntry(ctx, id2, "5.6.7.8"); ok {
		t.Error("delete must be scoped to the list")
	}

	// DeleteFriendlyList cascades its entries only.
	v2 := intelVer(t, repo)
	name, err := repo.DeleteFriendlyList(ctx, id)
	if err != nil || name != "HQ" {
		t.Fatalf("delete list: %q %v", name, err)
	}
	if intelVer(t, repo) != v2+1 {
		t.Error("deleting a list should bump the intel version")
	}
	var orphans int
	if err := repo.db.Read.QueryRow(`SELECT COUNT(*) FROM friendly_entries WHERE list_id = ?`, id).Scan(&orphans); err != nil || orphans != 0 {
		t.Errorf("entries left behind: %d %v", orphans, err)
	}
	vals, _ = repo.FriendlyValues(ctx)
	if !slices.Equal(vals, []string{"1.2.3.4"}) {
		t.Errorf("other list's entries lost: %v", vals)
	}
	if _, err := repo.DeleteFriendlyList(ctx, id); !errors.Is(err, ErrFriendlyListNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}

func TestBumpIntel(t *testing.T) {
	_, repo := openTemp(t)
	ctx := context.Background()
	v := intelVer(t, repo)
	for i := 1; i <= 3; i++ {
		if err := repo.bumpIntel(ctx); err != nil {
			t.Fatal(err)
		}
		if got := intelVer(t, repo); got != v+int64(i) {
			t.Errorf("after %d bumps version=%d, want %d", i, got, v+int64(i))
		}
	}
}

func TestFriendlyListsEmpty(t *testing.T) {
	_, repo := openTemp(t)
	ctx := context.Background()
	l, err := repo.FriendlyLists(ctx)
	if err != nil || len(l) != 0 {
		t.Errorf("empty: %v %v", l, err)
	}
	id, _ := repo.CreateFriendlyList(ctx, "empty", "", 1)
	l, _ = repo.FriendlyLists(ctx)
	if len(l) != 1 || l[0].ID != id || l[0].Entries == nil || len(l[0].Entries) != 0 {
		t.Errorf("a list with no entries should have a non-nil empty slice: %+v", l)
	}
}

func FuzzAddFriendlyEntries(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "10.0.0.0/8", "", "a'b\"c;--", "\x00", "é‮漢字", "1.2.3.4\n5.6.7.8", "%", "' OR 1=1 --"} {
		f.Add(s, s, "note")
	}
	ctx := context.Background()
	_, repo := openTempTB(f)
	id, err := repo.CreateFriendlyList(ctx, "fuzz", "", 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, a, b, note string) {
		// a leading "\x00-less" clean state per call: remove what earlier calls stored
		if _, err := repo.db.Write.Exec(`DELETE FROM friendly_entries`); err != nil {
			t.Fatal(err)
		}
		vals := []string{a, b, a}
		n, err := repo.AddFriendlyEntries(ctx, id, vals, note, 7)
		if err != nil {
			t.Fatalf("add %q: %v", vals, err)
		}
		want := map[string]bool{a: true, b: true}
		if n != len(want) {
			t.Fatalf("added %d, want %d distinct for %q", n, len(want), vals)
		}
		lists, err := repo.FriendlyLists(ctx)
		if err != nil || len(lists) != 1 {
			t.Fatalf("lists: %v %v", lists, err)
		}
		got := map[string]FriendlyEntry{}
		for _, e := range lists[0].Entries {
			got[e.Value] = e
		}
		if len(got) != len(want) {
			t.Fatalf("stored %d entries, want %d", len(got), len(want))
		}
		for v := range want {
			e, ok := got[v]
			if !ok || e.Note != note || e.CreatedAt != 7 {
				t.Fatalf("entry %q stored wrong: %+v ok=%v", v, e, ok)
			}
		}
		// re-adding adds nothing and the schema survives
		if n2, err := repo.AddFriendlyEntries(ctx, id, vals, note, 8); err != nil || n2 != 0 {
			t.Fatalf("re-add: %d %v", n2, err)
		}
		if _, err := repo.FriendlyValues(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
