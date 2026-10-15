package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestExternalUsers(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)

	root, _ := repo.CreateUser(ctx, "root", "hash", "admin", 1)
	if u, _ := repo.GetUser(ctx, root); u.AuthProvider != ProviderLocal || u.Disabled || u.ExternalID != "" {
		t.Errorf("a local user = %+v", u)
	}

	// An external account is found by its provider id, not its name.
	id, err := repo.CreateExternalUser(ctx, "entra", "oid-1", "ann@example.com", "standard", 5)
	if err != nil {
		t.Fatal(err)
	}
	u, err := repo.FindExternalUser(ctx, "entra", "oid-1")
	if err != nil || u.ID != id || u.Username != "ann@example.com" || u.AuthProvider != "entra" || u.ExternalID != "oid-1" || u.Role != "standard" {
		t.Fatalf("FindExternalUser = %+v %v", u, err)
	}
	if _, err := repo.FindExternalUser(ctx, "entra", "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := repo.FindExternalUser(ctx, "other", "oid-1"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("the same id at another provider: %v", err)
	}

	// A name that is taken is never taken over: not a local account's, not another person's.
	if _, err := repo.CreateExternalUser(ctx, "entra", "oid-2", "ROOT", "admin", 6); !errors.Is(err, ErrUserExists) {
		t.Errorf("taking over a local name: %v", err)
	}
	if _, err := repo.CreateExternalUser(ctx, "entra", "oid-3", "ann@example.com", "standard", 6); !errors.Is(err, ErrUserExists) {
		t.Errorf("taking over another person's name: %v", err)
	}
	// The same person can't be added twice under a new name.
	if _, err := repo.CreateExternalUser(ctx, "entra", "oid-1", "ann.new@example.com", "standard", 6); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate external id: %v", err)
	}
	if _, err := repo.CreateExternalUser(ctx, ProviderLocal, "x", "bob", "standard", 6); err == nil {
		t.Error("an external account with the local provider was created")
	}
	if _, err := repo.CreateExternalUser(ctx, "entra", "", "bob", "standard", 6); err == nil {
		t.Error("an external account with no id was created")
	}

	// It has no password to sign in with.
	if ok, err := repo.SetPassword(ctx, "ann@example.com", "newhash"); ok || !errors.Is(err, ErrExternalUser) {
		t.Errorf("SetPassword for an external user = %v %v", ok, err)
	}
	if ok, err := repo.SetPassword(ctx, "root", "newhash"); !ok || err != nil {
		t.Errorf("SetPassword for a local user = %v %v", ok, err)
	}
	if ok, err := repo.SetPassword(ctx, "nobody", "x"); ok || err != nil {
		t.Errorf("SetPassword for no one = %v %v", ok, err)
	}

	list, _ := repo.ListExternalUsers(ctx, "entra")
	if len(list) != 1 || list[0].ID != id {
		t.Errorf("ListExternalUsers = %+v", list)
	}

	// Disabling ends sessions and blocks new ones; enabling brings the account back.
	if err := repo.CreateSession(ctx, "tok", id, 10, 1<<50); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.FindSession(ctx, "tok", 20); err != nil || got.ID != id || got.AuthProvider != "entra" {
		t.Fatalf("session before disable: %+v %v", got, err)
	}
	if err := repo.SetUserDisabled(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindSession(ctx, "tok", 20); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("a disabled user's session still works: %v", err)
	}
	var n int
	db.Read.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, id).Scan(&n)
	if n != 0 {
		t.Errorf("%d sessions left after disabling", n)
	}
	if u, _ := repo.GetUser(ctx, id); !u.Disabled {
		t.Error("not marked disabled")
	}
	if err := repo.SetUserDisabled(ctx, id, true); err != nil {
		t.Errorf("disabling twice: %v", err)
	}
	if err := repo.SetUserDisabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if u, _ := repo.GetUser(ctx, id); u.Disabled {
		t.Error("still disabled")
	}
	if err := repo.SetUserDisabled(ctx, 9999, true); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("disabling no one: %v", err)
	}
}

func TestDisabledAdminsDontCount(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	local, _ := repo.CreateUser(ctx, "root", "h", "admin", 1)
	sso, _ := repo.CreateExternalUser(ctx, "entra", "o1", "boss@example.com", "admin", 2)

	// Two admins: either can be disabled, but not both.
	if err := repo.SetUserDisabled(ctx, sso, true); err != nil {
		t.Fatalf("disabling one of two admins: %v", err)
	}
	if err := repo.SetUserDisabled(ctx, local, true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last enabled admin: %v", err)
	}
	// A disabled admin doesn't count as the admin who has to remain.
	if err := repo.UpdateUserAccess(ctx, local, "standard", false, nil); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last enabled admin: %v", err)
	}
	if err := repo.DeleteUserByID(ctx, local); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the last enabled admin: %v", err)
	}
	if err := repo.SetUserDisabled(ctx, sso, false); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetUserDisabled(ctx, local, true); err != nil {
		t.Errorf("with another enabled admin: %v", err)
	}
}

func TestSessionsAndAdminsByProvider(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRepository(db)
	local, _ := repo.CreateUser(ctx, "root", "h", "admin", 1)
	a, _ := repo.CreateExternalUser(ctx, "entra", "o1", "boss@example.com", "admin", 2)
	b, _ := repo.CreateExternalUser(ctx, "entra", "o2", "ann@example.com", "standard", 2)
	for tok, id := range map[string]int64{"t-local": local, "t-a": a, "t-b": b} {
		if err := repo.CreateSession(ctx, tok, id, 1, 1<<50); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := repo.CountEnabledAdmins(ctx, "entra"); n != 1 {
		t.Errorf("entra admins = %d", n)
	}
	if n, _ := repo.CountEnabledAdmins(ctx, ProviderLocal); n != 1 {
		t.Errorf("local admins = %d", n)
	}
	repo.SetUserDisabled(ctx, a, true)
	if n, _ := repo.CountEnabledAdmins(ctx, "entra"); n != 0 {
		t.Errorf("a disabled admin is counted: %d", n)
	}

	// Only that provider's sessions go. (Disabling `a` already ended theirs.)
	n, err := repo.DeleteSessionsByProvider(ctx, "entra")
	if err != nil || n != 1 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	if _, err := repo.FindSession(ctx, "t-b", 2); !errors.Is(err, ErrUserNotFound) {
		t.Error("an entra session survived")
	}
	if _, err := repo.FindSession(ctx, "t-local", 2); err != nil {
		t.Errorf("a local session was ended: %v", err)
	}
	if n, _ := repo.DeleteSessionsByProvider(ctx, "entra"); n != 0 {
		t.Errorf("second delete = %d", n)
	}
}
