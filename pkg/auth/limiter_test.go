package auth

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"siemlite/pkg/storage"
)

// TestTakeIsAtomic: concurrent attempts can't get past the limit between
// being checked and being counted.
func TestTakeIsAtomic(t *testing.T) {
	l := newLoginLimiter(maxFailures)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.take("7") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != maxFailures {
		t.Errorf("%d attempts allowed, want %d", got, maxFailures)
	}
	l.reset("7")
	if !l.take("7") {
		t.Error("still blocked after a reset")
	}
}

// TestParallelLoginsAreLimited: guesses sent at once can't all be tested
// before the first failure is counted.
func TestParallelLoginsAreLimited(t *testing.T) {
	HashCost = bcrypt.MinCost
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	a := New(repo, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := CreateUser(ctx, repo, "alice", "correct horse battery", RoleStandard); err != nil {
		t.Fatal(err)
	}
	var tested, refused atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := a.Login(ctx, "192.0.2.9", "alice", "wrong"); err == ErrTooManyAttempts {
				refused.Add(1)
			} else {
				tested.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := tested.Load(); got > maxFailures {
		t.Errorf("%d passwords were tested at once, the limit is %d", got, maxFailures)
	}
}
