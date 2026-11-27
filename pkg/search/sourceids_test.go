package search

import (
	"context"
	"slices"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

// SourceIDs is "any of these sources"; it still combines with SourceID and,
// as an intersection, with a restricted user's allowed sources.
func TestSourceIDsFilter(t *testing.T) {
	e, repo := setup(t)
	ctx := context.Background()
	var ids []int64
	for _, name := range []string{"A", "B", "C", "D"} {
		id, err := repo.CreateTokenSource(ctx, name, "k-"+name, nil, false, 1)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	now := time.Now().UnixMilli()
	var recs []storage.Record
	for i, id := range ids {
		recs = append(recs, storage.Record{Timestamp: now - int64(i), Message: "hello", RawData: "hello", SourceID: id})
	}
	if err := repo.InsertBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	got := func(q Query) []int64 {
		t.Helper()
		q.Text, q.Limit = "hello", 100
		res, err := e.Search(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, ev := range res.Events {
			out = append(out, ev.SourceID)
		}
		slices.Sort(out)
		return out
	}
	a, b, c, d := ids[0], ids[1], ids[2], ids[3]
	for name, tc := range map[string]struct {
		q    Query
		want []int64
	}{
		"none":                     {Query{}, []int64{a, b, c, d}},
		"union of two":             {Query{SourceIDs: []int64{a, c}}, []int64{a, c}},
		"one in the list":          {Query{SourceIDs: []int64{d}}, []int64{d}},
		"the old single id":        {Query{SourceID: b}, []int64{b}},
		"single id and list":       {Query{SourceID: b, SourceIDs: []int64{a, b}}, []int64{b}},
		"restricted, no list":      {Query{Restrict: true, AllowedSources: []int64{b, c}}, []int64{b, c}},
		"restricted, overlapping":  {Query{Restrict: true, AllowedSources: []int64{b, c}, SourceIDs: []int64{a, b}}, []int64{b}},
		"restricted, disjoint":     {Query{Restrict: true, AllowedSources: []int64{b, c}, SourceIDs: []int64{a, d}}, nil},
		"restricted, nothing":      {Query{Restrict: true, SourceIDs: []int64{a}}, nil},
		"unknown id in the list":   {Query{SourceIDs: []int64{a, 9999}}, []int64{a}},
		"restricted, ask for more": {Query{Restrict: true, AllowedSources: []int64{a}, SourceIDs: []int64{a, b, c, d}}, []int64{a}},
	} {
		if g := got(tc.q); !slices.Equal(g, tc.want) {
			t.Errorf("%s: got %v, want %v", name, g, tc.want)
		}
	}
}
