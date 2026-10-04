package parser

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var fuzzNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

var seedLines = []string{
	"Oct  2 11:58:01 web1 sshd[311]: Failed password for root from 203.0.113.7 port 22 ssh2",
	`<34>1 2026-10-03T10:17:12.481Z host app 1234 ID47 [x@1 a="b"] message`,
	`{"time":"2026-10-03T10:17:12Z","level":"error","user":"bob","src_ip":"192.0.2.10","msg":"x"}`,
	`203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "POST /login HTTP/1.1" 401 512`,
	"user=alice ip=10.0.0.41 action=login result=ok",
	"999.999.999.999 panic: \x00\xff user ",
	`{"a":{"b":[1,2,{"c":null}]},"time":1e309}`,
	"",
}

// FuzzParseLine: any line parses without panicking into a sane event.
func FuzzParseLine(f *testing.F) {
	for _, s := range seedLines {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ev := ParseLine(line, Defaults{Now: fuzzNow})
		if strings.TrimSpace(strings.TrimRight(line, "\r\n")) == "" {
			if ev != nil {
				t.Fatalf("blank line gave an event")
			}
			return
		}
		if ev == nil {
			t.Fatalf("no event for %q", line)
		}
		if ev.SeverityID < 0 || ev.SeverityID > 6 {
			t.Fatalf("severity %d out of range for %q", ev.SeverityID, line)
		}
		if ev.RawData != strings.TrimRight(line, "\r\n") {
			t.Fatalf("raw data changed: %q -> %q", line, ev.RawData)
		}
	})
}

// FuzzPattern: any pattern either compiles or is refused, and a compiled
// pattern parses any line without panicking.
func FuzzPattern(f *testing.F) {
	f.Add("{ip} - {user} [{time}] \"{method} {path} {}\" {status:\\d+} {bytes}", seedLines[3])
	f.Add("{time} {host} {app}[{pid}]: {message}", seedLines[0])
	f.Add("{a:(}", "x")
	f.Add("{{}}{:}{a:\\}", "{}")
	f.Add("[{x:.*}]{y:a{2,3}}", "[q]aaa")
	f.Fuzz(func(t *testing.T, pattern, line string) {
		p, err := Compile(Definition{Name: "fuzz", Format: FormatPattern, Pattern: pattern, StripSyslog: len(line)%2 == 0})
		if err != nil {
			return
		}
		res, err := p.Parse(line, Defaults{Now: fuzzNow})
		if err == nil && res != nil && res.Event == nil {
			t.Fatalf("matched without an event")
		}
		Explain(pattern, line)
	})
}

// FuzzDraftPattern: a drafted pattern compiles and matches every line it was
// drafted from, which is what the pattern builder promises.
func FuzzDraftPattern(f *testing.F) {
	f.Add("2026-10-03 10:17:12,481 WARN  [auth] login failed user=bob ip=192.0.2.10\n2026-10-03 10:17:15,002 INFO  [auth] login ok user=alice ip=10.0.0.41")
	f.Add(seedLines[3] + "\n" + `10.0.0.41 - alice [03/Oct/2026:10:18:01 +0000] "GET /api/orders HTTP/1.1" 200 2048`)
	f.Add("a b c\na b\na")
	f.Add("{x} [y] (z)\n{q} [y] (z) w")
	f.Add("same\nsame")
	f.Fuzz(func(t *testing.T, text string) {
		if !utf8.ValidString(text) {
			return
		}
		lines := strings.Split(text, "\n")
		if len(lines) > 20 {
			lines = lines[:20]
		}
		pat := DraftPattern(lines)
		if pat == "" {
			return
		}
		p, err := Compile(Definition{Name: "draft", Format: FormatPattern, Pattern: pat})
		if err != nil {
			if strings.Contains(err.Error(), "too long") {
				return
			}
			t.Fatalf("draft %q doesn't compile: %v", pat, err)
		}
		for _, l := range lines {
			if strings.TrimSpace(strings.TrimRight(l, "\r")) == "" {
				continue
			}
			if _, err := p.Parse(l, Defaults{Now: fuzzNow}); err != nil {
				t.Fatalf("draft %q doesn't match %q: %v", pat, l, err)
			}
		}
	})
}
