package parser

import (
	"testing"
	"time"
)

func TestDraftPattern(t *testing.T) {
	cases := map[string][]string{
		"app log": {
			"2026-10-03 10:17:12,481 WARN  [auth-service] login failed user=bob ip=192.0.2.10 reason=bad_password",
			"2026-10-03 10:17:15,002 INFO  [auth-service] login ok user=alice ip=10.0.0.41",
			"2026-10-03 10:18:40,117 ERROR [billing] charge declined user=carol ip=198.51.100.7 reason=card_expired"},
		"vpn": {
			"203.0.113.9:51820 TLS Auth Error: Auth Username/Password verification failed for peer",
			"192.0.2.10:51822 [alice] Peer Connection Initiated with [AF_INET]192.0.2.10:51822",
			"198.51.100.77:40311 [bob] Peer Connection Initiated with [AF_INET]198.51.100.77:40311"},
		"access log": {
			`203.0.113.7 - - [03/Oct/2026:10:17:12 +0000] "POST /login HTTP/1.1" 401 512`,
			`10.0.0.41 - alice [03/Oct/2026:10:18:01 +0000] "GET /api/orders HTTP/1.1" 200 2048`},
		"identical": {"service started", "service started"},
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for name, lines := range cases {
		pat := DraftPattern(lines)
		p, err := Compile(Definition{Name: name, Format: FormatPattern, Pattern: pat})
		if err != nil {
			t.Errorf("%s: draft %q doesn't compile: %v", name, pat, err)
			continue
		}
		for _, l := range lines {
			if _, err := p.Parse(l, Defaults{Now: now}); err != nil {
				t.Errorf("%s: draft %q doesn't match %q", name, pat, l)
			}
		}
		t.Logf("%s: %s", name, pat)
	}
	// The app log draft should find the useful fields.
	p, _ := Compile(Definition{Name: "x", Format: FormatPattern, Pattern: DraftPattern(cases["app log"])})
	res, _ := p.Parse(cases["app log"][0], Defaults{Now: now})
	if ev := res.Event; ev.UserName() != "bob" || ev.SrcIP() != "192.0.2.10" || ev.SeverityID != 2 ||
		time.UnixMilli(ev.Time).UTC().Format("15:04:05") != "10:17:12" {
		t.Errorf("app log event: user=%q ip=%q sev=%d time=%s extra=%v", ev.UserName(), ev.SrcIP(), ev.SeverityID,
			time.UnixMilli(ev.Time).UTC().Format("15:04:05"), res.Extra)
	}
}
