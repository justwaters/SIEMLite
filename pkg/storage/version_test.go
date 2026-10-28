package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Starting on a different version ends every session; restarting on the same
// one leaves them alone.
func TestRollVersionEndsSessionsOnAChange(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "v.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	now := time.Now().UnixMilli()
	local, err := repo.CreateUser(ctx, "root", "x", "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	sso, err := repo.CreateExternalUser(ctx, "entra", "oid-1", "ann@example.com", "standard", now)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func() {
		t.Helper()
		for i, u := range []int64{local, sso} {
			if err := repo.CreateSession(ctx, []string{"h-local", "h-sso"}[i], u, now, now+3_600_000); err != nil {
				t.Fatal(err)
			}
		}
	}
	alive := func() int {
		var n int
		db.Read.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
		return n
	}

	// The first start of a version that has never been recorded counts as a change.
	signIn()
	prev, ended, changed, err := repo.RollVersion(ctx, "v1")
	if err != nil || prev != "" || ended != 2 || !changed || alive() != 0 {
		t.Fatalf("first start = %q %d %v %v, %d sessions left", prev, ended, changed, err, alive())
	}
	// Starting again on the same version keeps sessions.
	signIn()
	if prev, ended, changed, err = repo.RollVersion(ctx, "v1"); err != nil || prev != "v1" || ended != 0 || changed || alive() != 2 {
		t.Fatalf("same version = %q %d %v %v, %d sessions", prev, ended, changed, err, alive())
	}
	// An update ends them all, local and Microsoft accounts alike.
	if prev, ended, changed, err = repo.RollVersion(ctx, "v2"); err != nil || prev != "v1" || ended != 2 || !changed || alive() != 0 {
		t.Fatalf("update = %q %d %v %v, %d sessions left", prev, ended, changed, err, alive())
	}
	// So does going back.
	signIn()
	if prev, ended, changed, err = repo.RollVersion(ctx, "v1"); err != nil || prev != "v2" || ended != 2 || !changed {
		t.Fatalf("rollback = %q %d %v %v", prev, ended, changed, err)
	}
	// People can sign in again afterwards and stay signed in.
	signIn()
	if _, _, changed, _ = repo.RollVersion(ctx, "v1"); changed || alive() != 2 {
		t.Errorf("sessions made after the update were ended: %d left", alive())
	}
}
