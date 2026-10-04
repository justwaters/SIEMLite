package storage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"testing"
)

// TestDenseSearchIsExact checks the fast plan for searches with many matches
// returns exactly what sorting every match would, including events that
// arrived late with old timestamps and clocks running ahead.
func TestDenseSearchIsExact(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	rng := rand.New(rand.NewPCG(3, 3))
	words := []string{"alpha", "beta", "gamma", "delta"}
	n := 6000
	if raceEnabled {
		n = 1500 // SQLite runs far slower under the race detector
	}
	var recs []Record
	for i := 0; i < n; i++ {
		ts := int64(i) * 6_000_000 / int64(n) // 6000 seconds, however many events
		switch rng.IntN(20) {
		case 0:
			ts -= int64(rng.IntN(3_000_000)) // arrived late
		case 1:
			ts += int64(rng.IntN(3_000_000)) // clock ahead
		case 2:
			ts = int64(rng.IntN(6000)) * 1000 // anything, with ties
		}
		recs = append(recs, Record{Timestamp: ts, CategoryUID: 1, ClassUID: 1001, SeverityID: rng.IntN(7),
			RawData: words[rng.IntN(4)] + " " + words[rng.IntN(4)], Host: fmt.Sprintf("h%d", rng.IntN(3)), SourceID: int64(1 + rng.IntN(3))})
	}
	if err := repo.InsertBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	ids := func(rs []Record) []int64 {
		out := []int64{}
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	sev := 3
	for _, f := range []Filter{
		{Match: "alpha"},
		{Match: "alpha OR beta"},
		{Match: "alpha", Host: "h1"},
		{Match: "gamma", SeverityID: &sev},
		{Match: "delta", StartMs: 1_000_000, EndMs: 2_500_000},
		{Match: "beta", StartMs: 5_500_000},
		{Match: "beta", EndMs: 100_000},
		{Match: "alpha", Restrict: true, AllowedSources: []int64{2}},
		{Match: "alpha", Restrict: true},
		{Match: "zeta"},
	} {
		for _, page := range [][2]int{{10, 0}, {100, 0}, {50, 30}, {7, 900}, {1000, 0}, {20, 5000}} {
			f.Limit, f.Offset = page[0], page[1]
			denseMatches, denseFactor = 1_000_000, 20
			want, err := repo.Search(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			denseMatches, denseFactor = 1, 0
			got, err := repo.Search(ctx, f)
			denseMatches, denseFactor = 2000, 20
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ids(got), ids(want)) {
				t.Errorf("%+v: dense plan gave %d events, sorting gave %d (first difference in %v vs %v)",
					f, len(got), len(want), head(ids(got)), head(ids(want)))
			}
		}
	}
}

func head(s []int64) []int64 { return s[:min(len(s), 8)] }
