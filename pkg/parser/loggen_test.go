package parser

import (
	"strings"
	"testing"
	"time"

	"siemlite/pkg/loggen"
)

// Every line loggen makes is read by the built-in Log generator parser,
// with its fields where they belong.
func TestLogGeneratorParser(t *testing.T) {
	p, err := Compile(LogGenerator)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range LogGenerator.Samples {
		if _, err := p.Parse(s, Defaults{}); err != nil {
			t.Errorf("sample %q: %v", s, err)
		}
	}
	g := loggen.New(42)
	at := time.Date(2026, 10, 4, 13, 42, 7, 123e6, time.UTC)
	sev := map[string]int{"info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5}
	for i := 0; i < 20000; i++ {
		line := string(g.Next(at))
		res, err := p.Parse(line, Defaults{Now: at.Add(time.Hour)})
		if err != nil {
			t.Fatalf("line %d %q: %v", i, line, err)
		}
		f := strings.Split(line, "|")
		ev := res.Event
		if ev.Time != at.UnixMilli() || ev.Device == nil || ev.Device.Hostname != f[1] || ev.SeverityID != sev[f[3]] ||
			res.Extra["action"] != f[4] || ev.Message != strings.Join(f[10:], "|") {
			t.Fatalf("line %q read as time %d host %v severity %d extra %v message %q", line, ev.Time, ev.Device, ev.SeverityID, res.Extra, ev.Message)
		}
		if f[5] != "-" && ev.SrcIP() != f[5] {
			t.Fatalf("line %q: source IP %q", line, ev.SrcIP())
		}
		if f[9] != "-" && ev.UserName() != f[9] {
			t.Fatalf("line %q: user %q", line, ev.UserName())
		}
	}
}
