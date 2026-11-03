package parser

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/ocsf"
)

const prettyAudit = `{
      "id": 1577,
      "created_at": "2026-10-19T13:00:58Z",
      "username": "system",
      "user_id": null,
      "action": "stipulation_digest",
      "entity": null,
      "entity_id": null,
      "detail": "Emailed digest to 1 user(s)",
      "ip": "",
      "dest_ip": "",
      "via": "auto",
      "changes": null,
      "meta": {
        "users": [
          "Jonathan Martinez"
        ],
        "failed": []
      }
    }`

func TestSplitSamples(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want int
	}{
		"pretty object":     {prettyAudit, 1},
		"two pretty":        {prettyAudit + "\n" + prettyAudit, 2},
		"array":             {"[" + prettyAudit + "," + prettyAudit + "]", 2},
		"json lines":        {`{"a":1}` + "\n" + `{"a":2}` + "\n", 2},
		"text":              {"line one\n\nline two\r\n", 2},
		"broken json":       {"{\"a\": 1,\n oops", 2},
		"not json at start": {"x {\"a\":1}", 1},
	} {
		got := SplitSamples(c.in)
		if len(got) != c.want {
			t.Errorf("%s: %d samples %q", name, len(got), got)
		}
		for _, g := range got {
			if strings.HasPrefix(g, "{") && strings.Contains(g, "\n") {
				t.Errorf("%s: not compact: %q", name, g)
			}
		}
	}
	if got := SplitSamples(prettyAudit); !strings.HasPrefix(got[0], `{"id":1577,"created_at":"2026-10-19T13:00:58Z"`) {
		t.Errorf("compact = %q", got[0])
	}
}

func TestDraftJSONAuditLog(t *testing.T) {
	lines := SplitSamples(prettyAudit + "\n" +
		`{"id":1580,"created_at":"2026-10-19T13:05:12Z","username":"jmartinez","user_id":42,"action":"login_failed","entity":"user","entity_id":42,"detail":"Wrong password","ip":"203.0.113.7","dest_ip":"10.0.0.5","via":"web","changes":null,"meta":{}}`)
	def := Draft(lines)
	want := map[string]string{"created_at": "time", "username": "user", "detail": "message", "ip": "src_ip", "dest_ip": "dst_ip"}
	for k, v := range want {
		if def.Fields[k] != v {
			t.Errorf("%s -> %q, want %q (fields %v)", k, def.Fields[k], v, def.Fields)
		}
	}
	if def.Fields["user_id"] != "" || def.Fields["entity_id"] != "" {
		t.Errorf("numeric IDs mapped: %v", def.Fields)
	}
	if def.Format != FormatJSON || def.Severity.From != "field" || def.Severity.Field != "action" || def.Category != 3 {
		t.Errorf("draft = %+v", def)
	}
	p, err := Compile(def)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := p.Parse(lines[1], Defaults{Now: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if e := ev.Event; e.Message != "Wrong password" || e.SeverityID != ocsf.SeverityLow || e.SrcEndpoint == nil || e.SrcEndpoint.IP != "203.0.113.7" || e.Actor == nil || e.Actor.User.Name != "jmartinez" {
		t.Errorf("parsed = %+v", ev.Event)
	}
	if ev2, _ := p.Parse(lines[0], Defaults{}); ev2.Event.SeverityID != 1 || ev2.Event.Message != "Emailed digest to 1 user(s)" {
		t.Errorf("first line = %+v", ev2.Event)
	}
}

func TestDraftOtherShapes(t *testing.T) {
	// key=value with a level and ports.
	kv := Draft([]string{
		"ts=2026-10-03T10:17:12Z level=warn src=10.0.0.1 sport=51000 dst=192.0.2.9 dport=443 msg=\"conn reset\"",
		"ts=2026-10-03T10:18:12Z level=info src=10.0.0.2 sport=51001 dst=192.0.2.9 dport=443 msg=\"conn ok\"",
	})
	if kv.Format != FormatKV || kv.Fields["ts"] != "time" || kv.Fields["src"] != "src_ip" || kv.Fields["dst"] != "dst_ip" ||
		kv.Fields["dport"] != "dst_port" || kv.Fields["level"] != "severity" || kv.Severity.From != "auto" || kv.Category != 4 {
		t.Errorf("kv = %+v", kv)
	}
	// HTTP status decides severity.
	web := Draft([]string{`{"when":"2026-10-03T10:17:12Z","client":"203.0.113.7","status":200,"path":"/"}`, `{"when":"2026-10-03T10:17:13Z","client":"203.0.113.8","status":503,"path":"/x"}`})
	if web.Fields["when"] != "time" || web.Fields["client"] != "src_ip" || web.Severity.Field != "status" || web.Severity.Rules[0].Match != "^5" {
		t.Errorf("web = %+v", web)
	}
	// Free text gets a pattern.
	txt := Draft([]string{"Failed password for root from 203.0.113.7 port 51234 ssh2", "Failed password for bob from 198.51.100.2 port 4022 ssh2"})
	if txt.Format != FormatPattern || txt.Pattern == "" {
		t.Errorf("text = %+v", txt)
	}
}

func TestDefaultKeywordSeverities(t *testing.T) {
	rules := DefaultSeverityRules()
	rate := func(v string) int {
		for _, r := range rules {
			if regexp.MustCompile(r.Match).MatchString(v) {
				return r.Severity
			}
		}
		t.Fatalf("no rule matched %q", v)
		return 0
	}
	for _, w := range defaultSeverityWords {
		if got := rate(w.stem); got != w.sev {
			t.Errorf("%q rated %d, want %d", w.stem, got, w.sev)
		}
		if got := rate("X " + strings.ToUpper(w.stem) + "ed"); got < w.sev {
			t.Errorf("%q (upper case, in a longer word) rated %d, want at least %d", w.stem, got, w.sev)
		}
	}
	for v, want := range map[string]int{
		"login failed":                ocsf.SeverityLow,
		"password reset":              ocsf.SeverityMedium, // reset and password are both medium
		"failed admin login":          ocsf.SeverityHigh,   // the worst keyword wins, not the first
		"malware blocked":             ocsf.SeverityCritical,
		"user role removed":           ocsf.SeverityMedium,
		"account disabled":            ocsf.SeverityHigh,
		"Emailed digest to 1 user(s)": ocsf.SeverityInformational,
	} {
		if got := rate(v); got != want {
			t.Errorf("%q rated %d, want %d", v, got, want)
		}
	}
}
