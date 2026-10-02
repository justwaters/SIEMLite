package parser

import (
	"testing"
	"time"

	"siemlite/pkg/ocsf"
)

func TestParseLine(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	d := Defaults{Now: now}

	t.Run("blank", func(t *testing.T) {
		if ParseLine("  \n", d) != nil {
			t.Fatal("blank line should yield nil")
		}
	})

	t.Run("rfc3164 failed ssh", func(t *testing.T) {
		line := "<38>Oct  2 11:58:01 web1 sshd[311]: Failed password for invalid user admin from 203.0.113.7 port 22 ssh2"
		ev := parse(t, line, d)
		if ev.SrcIP() != "203.0.113.7" {
			t.Errorf("src endpoint = %+v", ev.SrcEndpoint)
		}
		if ev.DeviceName() != "web1" || ev.ProductName() != "sshd" {
			t.Errorf("device = %+v, product = %q", ev.Device, ev.ProductName())
		}
		if ev.UserName() != "admin" {
			t.Errorf("user = %q", ev.UserName())
		}
		if ev.SeverityID != ocsf.SeverityMedium {
			t.Errorf("severity = %d", ev.SeverityID)
		}
		if ev.RawData != line {
			t.Error("raw line not preserved")
		}
		if got := time.UnixMilli(ev.Time).UTC().Format("01-02 15:04"); got != "10-02 11:58" {
			t.Errorf("time = %s", got)
		}
	})

	t.Run("syslog priority sets severity", func(t *testing.T) {
		ev := parse(t, "<10>Oct  2 11:00:00 db1 kernel: disk on fire", d)
		if ev.SeverityID != ocsf.SeverityHigh { // pri 10 -> severity 2
			t.Errorf("severity = %d", ev.SeverityID)
		}
	})

	t.Run("rfc5424 app name", func(t *testing.T) {
		ev := parse(t, "<34>1 2026-10-02T11:00:00Z fw01 pf 77 - - block in on em0 from 198.51.100.9", d)
		if ev.DeviceName() != "fw01" || ev.ProductName() != "pf" || ev.SrcIP() != "198.51.100.9" {
			t.Errorf("device = %q, product = %q, src = %q", ev.DeviceName(), ev.ProductName(), ev.SrcIP())
		}
	})

	t.Run("source default wins over tag", func(t *testing.T) {
		ev := parse(t, "Oct  2 11:58:01 web1 sshd[311]: hello", Defaults{Now: now, Source: "myapp"})
		if ev.ProductName() != "myapp" {
			t.Errorf("product = %q", ev.ProductName())
		}
	})

	t.Run("json app log", func(t *testing.T) {
		ev := parse(t, `{"ts":"2026-10-02T11:00:00Z","level":"error","msg":"db timeout"}`, d)
		if ev.SeverityID != ocsf.SeverityHigh || ev.Message != "db timeout" {
			t.Errorf("got sev=%d msg=%q", ev.SeverityID, ev.Message)
		}
	})

	t.Run("severity override", func(t *testing.T) {
		sev := ocsf.SeverityLow
		ev := parse(t, "fatal crash", Defaults{Now: now, SeverityID: &sev})
		if ev.SeverityID != ocsf.SeverityLow {
			t.Errorf("severity = %d", ev.SeverityID)
		}
	})
}

func parse(t *testing.T, line string, d Defaults) *ocsf.Event {
	t.Helper()
	ev := ParseLine(line, d)
	if ev == nil {
		t.Fatal("nil event")
	}
	if err := ev.Prepare(); err != nil {
		t.Fatalf("event invalid: %v", err)
	}
	return ev
}
