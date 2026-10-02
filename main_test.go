package main

import (
	"flag"
	"testing"
)

func TestFlagsFromEnv(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	city := fs.String("geoip-city", "", "")
	days := fs.Int("retention-days", 30, "")
	sample := fs.Bool("sample", true, "")
	var feeds feedFlag
	fs.Var(&feeds, "intel-feed", "")

	t.Setenv("SIEMLITE_GEOIP_CITY", "/geoip/City.mmdb")
	t.Setenv("SIEMLITE_RETENTION_DAYS", "90")
	t.Setenv("SIEMLITE_SAMPLE", "false")
	t.Setenv("SIEMLITE_INTEL_FEED", "a=https://a.example/list\n  b=https://b.example/list")
	if err := flagsFromEnv(fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"-retention-days", "7"}); err != nil {
		t.Fatal(err)
	}
	if *city != "/geoip/City.mmdb" || *days != 7 || *sample || len(feeds) != 2 || feeds[1].Name != "b" {
		t.Errorf("city=%q days=%d sample=%v feeds=%+v", *city, *days, *sample, feeds)
	}

	t.Setenv("SIEMLITE_RETENTION_DAYS", "lots")
	if err := flagsFromEnv(fs); err == nil {
		t.Error("bad value accepted")
	}
}
