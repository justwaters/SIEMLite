package main

import (
	"context"
	"errors"
	"flag"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"siemlite/pkg/auth"
	"siemlite/pkg/storage"
)

func TestFlagsFromEnv(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	city := fs.String("geoip-city", "", "")
	days := fs.Int("retention-days", 30, "")
	verbose := fs.Bool("verbose", true, "")
	var feeds feedFlag
	fs.Var(&feeds, "intel-feed", "")

	t.Setenv("SIEMLITE_GEOIP_CITY", "/geoip/City.mmdb")
	t.Setenv("SIEMLITE_RETENTION_DAYS", "90")
	t.Setenv("SIEMLITE_VERBOSE", "false")
	t.Setenv("SIEMLITE_INTEL_FEED", "a=https://a.example/list\n  b=https://b.example/list")
	if err := flagsFromEnv(fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-retention-days", "7"}); err != nil {
		t.Fatal(err)
	}
	if *city != "/geoip/City.mmdb" || *days != 7 || *verbose || len(feeds) != 2 || feeds[1].Name != "b" {
		t.Errorf("city=%q days=%d verbose=%v feeds=%+v", *city, *days, *verbose, feeds)
	}

	t.Setenv("SIEMLITE_RETENTION_DAYS", "lots")
	if err := flagsFromEnv(fs); err == nil {
		t.Error("bad value accepted")
	}
}

func TestKeysEnableDisableDelete(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "t.db")
	db, repo, err := openForCLI(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	id, token, err := auth.CreateKey(ctx, repo, "app", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	syslog, _ := repo.BuiltinSource(ctx, storage.SourceSyslog)
	db.Close()

	keys := func(cmd string, sid int64) error {
		return runKeys([]string{cmd, "-db", dbPath, "-id", strconv.FormatInt(sid, 10)})
	}
	state := func() (enabled bool, found bool) {
		db, repo, err := openForCLI(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = repo.FindActiveToken(ctx, auth.HashKey(token))
		return err == nil, err == nil || !errors.Is(err, storage.ErrSourceNotFound)
	}

	for _, cmd := range []string{"disable", "revoke"} { // revoke is the old name for disable
		if err := keys("enable", id); err != nil {
			t.Fatal(err)
		}
		if on, _ := state(); !on {
			t.Fatal("enable didn't accept the token")
		}
		if err := keys(cmd, id); err != nil {
			t.Fatal(err)
		}
		if on, _ := state(); on {
			t.Fatalf("%s left the token working", cmd)
		}
	}
	if err := keys("enable", syslog.ID); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("enable built-in = %v", err)
	}
	if err := keys("delete", syslog.ID); err == nil {
		t.Error("deleted a built-in source")
	}
	if err := keys("delete", 9999); err == nil {
		t.Error("deleted a missing source")
	}
	if err := keys("delete", id); err != nil {
		t.Fatal(err)
	}
	if err := keys("enable", id); err == nil {
		t.Error("enabled a deleted source")
	}

	// Each change is in the INTERNAL log.
	db, repo, err = openForCLI(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, err := repo.Search(ctx, storage.Filter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range recs {
		for _, a := range []string{"source.enable", "source.disable", "source.delete"} {
			if strings.Contains(string(r.Fields), `"action":"`+a+`"`) {
				seen[a]++
			}
		}
	}
	if seen["source.enable"] != 2 || seen["source.disable"] != 2 || seen["source.delete"] != 1 {
		t.Errorf("audit events = %v", seen)
	}
}
