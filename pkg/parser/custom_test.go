package parser

import (
	"strings"
	"testing"
	"time"

	"siemlite/pkg/ocsf"
)

func TestCompilePattern(t *testing.T) {
	re, names, err := CompilePattern(`{ip} - [{time}]  "{req}" {status:\d+}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "ip,time,req,status" {
		t.Errorf("names = %v", names)
	}
	if !re.MatchString(`1.2.3.4 -   [x] "GET /" 200`) {
		t.Error("runs of spaces should match any whitespace")
	}
	if re.MatchString(`1.2.3.4 - [x] "GET /" abc`) {
		t.Error("custom regex {status:\\d+} matched letters")
	}
	for _, bad := range []string{"", "no fields", "{a} {a}", "{bad name}", `{x:(}`} {
		if _, _, err := CompilePattern(bad); err == nil {
			t.Errorf("pattern %q accepted", bad)
		}
	}
}

func TestTemplates(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, def := range Templates {
		p, err := Compile(def)
		if err != nil {
			t.Fatalf("%s: %v", def.Name, err)
		}
		for _, line := range def.Samples {
			res, err := p.Parse(line, Defaults{Now: now})
			if err != nil {
				t.Errorf("%s: %q: %v", def.Name, line, err)
				continue
			}
			if err := res.Event.Prepare(); err != nil {
				t.Errorf("%s: %q: invalid event: %v", def.Name, line, err)
			}
		}
	}
}

func TestWebTemplate(t *testing.T) {
	p, _ := Compile(Templates[0])
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	// Through syslog: the header is removed and supplies the host.
	line := `<190>Oct  3 10:17:12 web1 nginx: 203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.5"`
	res, err := p.Parse(line, Defaults{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Event
	if ev.SrcIP() != "203.0.113.7" || ev.DeviceName() != "web1" || ev.ProductName() != "nginx" || ev.UserName() != "" {
		t.Errorf("src=%q device=%q product=%q user=%q", ev.SrcIP(), ev.DeviceName(), ev.ProductName(), ev.UserName())
	}
	if ev.SeverityID != ocsf.SeverityMedium || ev.CategoryUID != 4 || ev.ClassUID != 4001 {
		t.Errorf("severity=%d category=%d class=%d", ev.SeverityID, ev.CategoryUID, ev.ClassUID)
	}
	if got := time.UnixMilli(ev.Time).UTC().Format(time.RFC3339); got != "2026-10-03T10:17:12Z" {
		t.Errorf("time = %s", got)
	}
	if res.Extra["method"] != "POST" || res.Extra["status"] != "401" || res.Extra["user_agent"] != "curl/8.5" {
		t.Errorf("extra = %v", res.Extra)
	}
	if ev.RawData != line {
		t.Error("raw line not kept")
	}
	if _, err := p.Parse("not an access log", Defaults{Now: now}); err != ErrNoMatch {
		t.Errorf("non-matching line: %v", err)
	}
}

func TestJSONAndKV(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	jp, _ := Compile(Templates[1])
	res, err := jp.Parse(Templates[1].Samples[0], Defaults{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if ev := res.Event; ev.SrcIP() != "192.0.2.10" || ev.UserName() != "bob" || ev.Message != "payment failed" || ev.SeverityID != ocsf.SeverityHigh {
		t.Errorf("json event: src=%q user=%q msg=%q sev=%d", ev.SrcIP(), ev.UserName(), ev.Message, ev.SeverityID)
	}

	kp, _ := Compile(Templates[2])
	res, err = kp.Parse(`<134>1 2026-10-03T10:00:00Z fw01 filterlog 77 - - action=block src=203.0.113.34 spt=51515 dst=10.0.0.5 dpt=3389 rule="inbound default"`, Defaults{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Event
	if ev.SrcIP() != "203.0.113.34" || ev.SrcEndpoint.Port != 51515 || ev.DstEndpoint.Port != 3389 || ev.DeviceName() != "fw01" || ev.SeverityID != ocsf.SeverityLow {
		t.Errorf("kv event: %+v %+v device=%q sev=%d", ev.SrcEndpoint, ev.DstEndpoint, ev.DeviceName(), ev.SeverityID)
	}
	if res.Extra["rule"] != "inbound default" {
		t.Errorf("quoted value = %q", res.Extra["rule"])
	}
}

func TestMappingAndSeverity(t *testing.T) {
	p, err := Compile(Definition{
		Name: "custom", Format: FormatPattern, Pattern: `{when} {who} logged in from {addr} ({lvl})`,
		Fields:   map[string]string{"when": "time", "who": "user", "addr": "src_ip", "lvl": ""},
		Severity: SeverityRule{From: "fixed", Fixed: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Parse("1759486632 alice logged in from not-an-ip (warn)", Defaults{})
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Event
	if ev.UserName() != "alice" || ev.SrcIP() != "" || ev.SeverityID != 3 || time.UnixMilli(ev.Time).Unix() != 1759486632 {
		t.Errorf("user=%q src=%q sev=%d time=%d", ev.UserName(), ev.SrcIP(), ev.SeverityID, ev.Time)
	}
	// An invalid IP is kept as an extra field rather than lost; lvl was
	// explicitly unmapped.
	if res.Extra["addr"] != "not-an-ip" || res.Extra["lvl"] != "warn" {
		t.Errorf("extra = %v", res.Extra)
	}
	if _, err := Compile(Definition{Name: "x", Format: FormatJSON, Fields: map[string]string{"a": "nope"}}); err == nil {
		t.Error("unknown target accepted")
	}
}

func TestParseTime(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-03T10:17:12Z":       "2026-10-03T10:17:12Z",
		"2026-10-03 10:17:12":        "2026-10-03T10:17:12Z",
		"03/Oct/2026:10:17:12 +0000": "2026-10-03T10:17:12Z",
		"1759486632":                 "2025-10-03T10:17:12Z",
		"1759486632000":              "2025-10-03T10:17:12Z",
		"Oct  3 10:17:12":            "2026-10-03T10:17:12Z",
	} {
		got, ok := ParseTime(in, now)
		if !ok || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("ParseTime(%q) = %s, %v; want %s", in, got.UTC().Format(time.RFC3339), ok, want)
		}
	}
	if _, ok := ParseTime("yesterday", now); ok {
		t.Error("nonsense parsed")
	}
}
