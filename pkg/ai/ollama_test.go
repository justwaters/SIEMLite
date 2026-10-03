package ai

import (
	"strings"
	"testing"

	"siemlite/pkg/parser"
)

func TestPreparation(t *testing.T) {
	bodies, strip := syslogBodies([]string{
		"Oct  3 10:20:01 vpn1 openvpn[812]: 203.0.113.9:51820 TLS Auth Error",
		"<34>1 2026-10-03T10:00:00Z fw01 pf 77 - - block in from 198.51.100.9",
	})
	if !strip || bodies[0] != "203.0.113.9:51820 TLS Auth Error" || bodies[1] != "block in from 198.51.100.9" {
		t.Errorf("bodies = %q, strip = %v", bodies, strip)
	}
	if _, strip := syslogBodies([]string{"plain line", "another"}); strip {
		t.Error("plain lines treated as syslog")
	}
	for want, lines := range map[string][]string{
		parser.FormatJSON:    {`{"a":1}`, `{"b":"x"}`},
		parser.FormatKV:      {"action=block src=1.2.3.4 dst=5.6.7.8", "action=allow src=1.2.3.5 dst=5.6.7.9 rule=x"},
		parser.FormatPattern: {"2026-10-03 WARN login failed user=bob", "plain"},
	} {
		if got := detectFormat(lines); got != want {
			t.Errorf("detectFormat(%q) = %s, want %s", lines, got, want)
		}
	}
}

func TestFeedback(t *testing.T) {
	def := parser.Definition{Pattern: "{time} {host} {app}[{pid}]: {message}"}
	fb := feedback(def, []string{"203.0.113.9:51820 TLS Auth Error"})
	if !strings.Contains(fb, `doesn't continue with "[`) {
		t.Errorf("feedback should point at the missing [: %s", fb)
	}
	matched, next, ok := parser.Explain("{ip} - [{time}] {rest}", "1.2.3.4 - (x) y")
	if ok || matched != "{ip} - " || next != "[" {
		t.Errorf("Explain = %q, %q, %v", matched, next, ok)
	}
}
