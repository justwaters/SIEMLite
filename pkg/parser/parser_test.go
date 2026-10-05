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

func TestParseLineMessage(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	d := Defaults{Now: now}
	cases := []struct{ name, line, message string }{
		{"3164 with PRI", "<38>Oct  3 11:58:01 web1 sshd[311]: Failed password for root from 203.0.113.7 port 22 ssh2", "Failed password for root from 203.0.113.7 port 22 ssh2"},
		{"3164 without PRI", "Oct  3 11:58:01 web1 sshd[311]: Failed password for root", "Failed password for root"},
		{"5424", "<34>1 2026-10-03T11:58:01Z host app 1234 ID47 [sd@1 a=\"b\"] hello there", "hello there"},
		{"5424 without PRI", "1 2026-10-03T11:58:01Z host app 1234 ID47 - hello there", "hello there"},
		{"no header", "user=bob action=login", "user=bob action=login"},
		{"PRI only", "<13>just a note", "<13>just a note"},
		{"ISO timestamp kept", "2026-10-04T13:42:07Z ERROR payment failed user=bob", "2026-10-04T13:42:07Z ERROR payment failed user=bob"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ev := parse(t, c.line, d); ev.Message != c.message {
				t.Errorf("message = %q, want %q", ev.Message, c.message)
			}
		})
	}
}

func TestParseLineHeaders(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	d := Defaults{Now: now}

	t.Run("iso timestamp and level is not a syslog header", func(t *testing.T) {
		line := "2026-10-04T13:42:07Z ERROR payment failed user=bob"
		ev := parse(t, line, d)
		if ev.Device != nil {
			t.Errorf("host = %+v, want none", ev.Device)
		}
		if got := time.UnixMilli(ev.Time).UTC().Format(time.RFC3339); got != "2026-10-04T13:42:07Z" {
			t.Errorf("time = %s", got)
		}
		if ev.SeverityID != ocsf.SeverityHigh {
			t.Errorf("severity = %d", ev.SeverityID)
		}
		if ev.Message != line || ev.UserName() != "bob" {
			t.Errorf("message = %q, user = %q", ev.Message, ev.UserName())
		}
	})

	t.Run("rfc5424", func(t *testing.T) {
		ev := parse(t, "<34>1 2026-10-03T11:58:01Z host app 1234 ID47 [sd@1 a=\"b\"] msg", d)
		if ev.DeviceName() != "host" || ev.ProductName() != "app" || ev.SeverityID != ocsf.SeverityHigh {
			t.Errorf("host = %q, product = %q, severity = %d", ev.DeviceName(), ev.ProductName(), ev.SeverityID)
		}
		if got := time.UnixMilli(ev.Time).UTC().Format(time.RFC3339); got != "2026-10-03T11:58:01Z" {
			t.Errorf("time = %s", got)
		}
	})

	t.Run("rfc5424 without PRI", func(t *testing.T) {
		ev := parse(t, "1 2026-10-03T11:58:01Z host app 1234 ID47 - msg", d)
		if ev.DeviceName() != "host" || ev.ProductName() != "app" {
			t.Errorf("host = %q, product = %q", ev.DeviceName(), ev.ProductName())
		}
	})

	for _, line := range []string{
		"<38>Oct  3 11:58:01 web1 sshd[311]: Failed password for root",
		"Oct  3 11:58:01 web1 sshd[311]: Failed password for root",
	} {
		t.Run("rfc3164 "+line[:4], func(t *testing.T) {
			ev := parse(t, line, d)
			if ev.DeviceName() != "web1" || ev.ProductName() != "sshd" {
				t.Errorf("host = %q, product = %q", ev.DeviceName(), ev.ProductName())
			}
			if got := time.UnixMilli(ev.Time).UTC().Format("01-02 15:04:05"); got != "10-03 11:58:01" {
				t.Errorf("time = %s", got)
			}
		})
	}
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

func TestPlainLine(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	if PlainLine("  \r\n", Defaults{Now: now}) != nil {
		t.Fatal("blank line should yield nil")
	}

	for _, line := range []string{
		"<38>Oct  3 11:58:01 web1 sshd[311]: Failed password for root from 203.0.113.7 port 22 ssh2",
		"2026-10-04T13:42:07Z ERROR payment failed user=bob",
		`{"level":"error","msg":"boom","user":"bob","src_ip":"198.51.100.9"}`,
		"1 2026-10-03T11:58:01Z host app 1234 ID47 - fatal",
	} {
		ev := PlainLine(line+"\r\n", Defaults{Now: now})
		if ev == nil {
			t.Fatalf("nil event for %q", line)
		}
		if err := ev.Prepare(); err != nil {
			t.Fatalf("event invalid: %v", err)
		}
		if ev.Message != line || ev.RawData != line {
			t.Errorf("message = %q, raw = %q", ev.Message, ev.RawData)
		}
		if ev.Time != now.UnixMilli() || ev.SeverityID != ocsf.SeverityInformational {
			t.Errorf("time = %d, severity = %d for %q", ev.Time, ev.SeverityID, line)
		}
		if ev.CategoryUID != ocsf.CategoryApplicationActivity || ev.ClassUID != 6003 {
			t.Errorf("category = %d, class = %d", ev.CategoryUID, ev.ClassUID)
		}
		if ev.SrcEndpoint != nil || ev.DstEndpoint != nil || ev.Device != nil || ev.Actor != nil || ev.Unmapped != nil || ev.Metadata.Product != nil {
			t.Errorf("detected something in %q: %+v", line, ev)
		}
	}

	t.Run("explicit defaults apply", func(t *testing.T) {
		sev := ocsf.SeverityLow
		ev := PlainLine("fatal crash", Defaults{Now: now, Source: "myapp", SeverityID: &sev})
		if ev.ProductName() != "myapp" || ev.SeverityID != ocsf.SeverityLow {
			t.Errorf("product = %q, severity = %d", ev.ProductName(), ev.SeverityID)
		}
	})
}

// rsyslog's default file format (RFC 3339 time, host, tag) is a syslog header:
// the host and program are read and the message is what follows the tag. A
// level word after a timestamp is not a host.
func TestParseLineRsyslogFormat(t *testing.T) {
	for _, tc := range []struct {
		line, host, app, message string
		hostKnown                bool
	}{
		{`2026-10-03T11:58:01.123456+00:00 web1 sshd[311]: Failed password for root from 203.0.113.7`, "web1", "sshd", "Failed password for root from 203.0.113.7", true},
		{`2026-10-03T11:58:01Z web1 CRON[9]: (root) CMD (run-parts /etc/cron.hourly)`, "web1", "CRON", "(root) CMD (run-parts /etc/cron.hourly)", true},
		{`2026-10-04T13:42:07Z ERROR payment failed user=bob`, "", "", `2026-10-04T13:42:07Z ERROR payment failed user=bob`, false},
		{`2026-10-04T13:42:07Z ERROR payment: card declined`, "", "", `2026-10-04T13:42:07Z ERROR payment: card declined`, false},
	} {
		ev := ParseLine(tc.line, Defaults{Now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)})
		if (ev.Device != nil) != tc.hostKnown || (tc.hostKnown && ev.Device.Hostname != tc.host) {
			t.Errorf("%q: host %+v, want %q", tc.line, ev.Device, tc.host)
		}
		if tc.app != "" && (ev.Metadata.Product == nil || ev.Metadata.Product.Name != tc.app) {
			t.Errorf("%q: program %+v, want %q", tc.line, ev.Metadata.Product, tc.app)
		}
		if ev.Message != tc.message {
			t.Errorf("%q: message %q, want %q", tc.line, ev.Message, tc.message)
		}
		if ev.Time == 0 || time.UnixMilli(ev.Time).UTC().Year() != 2026 {
			t.Errorf("%q: time %d", tc.line, ev.Time)
		}
	}
}
