package sources

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

func def(pattern string) string {
	b, _ := json.Marshal(parser.Definition{Name: "p", Format: "pattern", Pattern: pattern})
	return string(b)
}

func TestParserChangeTakesEffectAtOnce(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	pid, err := repo.CreateParser(ctx, "p", def("A {x}"), 1)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := repo.CreateTokenSource(ctx, "s", "hash", &pid, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	r := New(repo)
	_, extra, err := r.Parse(ctx, sid, "A one", parser.Defaults{})
	if err != nil || extra["parse_error"] != "" {
		t.Fatalf("first parse: %v %v", extra, err)
	}
	if err := repo.UpdateParser(ctx, pid, "p", def("B {x}"), 2); err != nil {
		t.Fatal(err)
	}
	r.Invalidate()
	if _, extra, _ = r.Parse(ctx, sid, "A one", parser.Defaults{}); extra["parse_error"] == "" {
		t.Error("the old parser was still used after Invalidate")
	}
	if _, extra, _ = r.Parse(ctx, sid, "B one", parser.Defaults{}); extra["parse_error"] != "" {
		t.Errorf("the new parser was not used: %v", extra)
	}
}

// A lookup that read the database before Invalidate must not put its stale
// result into the cache afterwards.
func TestInvalidateDiscardsInFlightLookup(t *testing.T) {
	r := New(nil)
	r.mu.Lock()
	gen := r.gen
	r.mu.Unlock()
	r.Invalidate()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gen == gen {
		t.Fatal("Invalidate did not advance the generation, so an in-flight lookup would cache stale data")
	}
}
