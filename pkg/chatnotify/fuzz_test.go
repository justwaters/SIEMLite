package chatnotify

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// markup collects the strings Slack reads as markup: the top-level text and mrkdwn text objects.
func markup(v any, top bool, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		if top {
			if t, ok := x["text"].(string); ok {
				*out = append(*out, t)
			}
		}
		if x["type"] == "mrkdwn" {
			if t, ok := x["text"].(string); ok {
				*out = append(*out, t)
			}
		}
		for _, e := range x {
			markup(e, false, out)
		}
	case []any:
		for _, e := range x {
			markup(e, false, out)
		}
	}
}

var amp = regexp.MustCompile(`&(?:amp|lt|gt);`)

// FuzzPayload: both services turn any alert into valid UTF-8 JSON, and in what Slack reads as
// markup nothing from the alert can start a link, mention or channel ping.
func FuzzPayload(f *testing.F) {
	f.Add("SSH brute force", "10 failures from one address", "src_ip", "203.0.113.9", "Raised by hand", 4, int64(10), true)
	f.Add("<!channel> <!here> <@U123|x> <https://evil.example|click>", "&lt;b&gt; <!everyone> &amp;<", "user", "<!subteam^S1>", "_*~`> quote", 5, int64(-1), false)
	f.Add("\xff\xfe\x00\x01", "line\r\nbreak  ", "\xc0", "‮\u0000", strings.Repeat("<", 4000), 99, int64(1<<62), true)
	f.Add("", "", "", "", "", 0, int64(0), false)
	f.Add("é\U0001F600", strings.Repeat("&", 5000), "host", strings.Repeat(">", 5000), "```", -3, int64(5), true)
	f.Fuzz(func(t *testing.T, title, desc, groupBy, groupValue, note string, sev int, count int64, manual bool) {
		a := Alert{Title: title, Description: desc, GroupBy: groupBy, GroupValue: groupValue, Note: note, Severity: sev, Count: count, At: time.Unix(0, 0), Manual: manual}
		for _, kind := range []Kind{Slack, Teams} {
			s := New(kind, nil, "unused")
			b := s.payload(a)
			if !json.Valid(b) || !utf8.Valid(b) {
				t.Fatalf("%s: bad JSON %q", kind, b[:min(len(b), 200)])
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			if kind == Teams {
				if m, _ := v.(map[string]any); m["type"] != "message" {
					t.Fatalf("teams payload %q", b)
				}
				continue
			}
			var texts []string
			markup(v, true, &texts)
			if len(texts) < 1 {
				t.Fatal("no text")
			}
			for _, text := range texts {
				if bare := amp.ReplaceAllString(text, ""); strings.ContainsAny(bare, "<>&") {
					t.Fatalf("slack text has unescaped markup characters: %q", text)
				}
			}
		}
	})
}

// FuzzWebhookCheck: an address is accepted only if it is https and the host the request would
// really go to (as Go parses it) is one of the service's own, whatever userinfo, port, case,
// trailing dot, escapes, IP literal or look-alike characters surround it.
func FuzzWebhookCheck(f *testing.F) {
	for _, u := range []string{
		"https://hooks.slack.com/services/T000/B000/XXXX", "https://HOOKS.SLACK.COM/services/x", "https://hooks.slack.com./services/x",
		"https://hooks.slack.com:443/services/x", "https://hooks.slack.com:evil@evil.example/", "https://evil.example\\@hooks.slack.com/",
		"https://evil.example#@hooks.slack.com/", "https://evil.example?@hooks.slack.com/", "https://hooks.slack.com@evil.example/",
		"https://hooks.slack.com%2eevil.example/", "https://hooks.slack.com%00.evil.example/", "https://[::1]/", "https://127.0.0.1/", "https://2130706433/",
		"https://hоoks.slack.com/", "https://hooks.slack.com。evil.example/", "https://hooks．slack．com/", "http://hooks.slack.com/x",
		"//hooks.slack.com/x", "https:hooks.slack.com/x", "https://x.logic.azure.com/workflows/1", "https://x.logic.azure.com.evil.example/", "https://evil.example/.logic.azure.com",
		"https://evil.example?.logic.azure.com", "https://evil.logic.azure.com:8443/", "https://evilwebhook.office.com/", "https://x.webhook.office.com/webhookb2/x",
		"https://x.API.POWERPLATFORM.COM./powerautomate", " \thttps://hooks.slack.com/x\r\n", "https://hooks.slack.com/\x00", "https://hooks.slack-gov.com/x",
		"https://tenant.westus.logic.azure.com:443/workflows/x?sig=y", "https://.logic.azure.com/", "https://a@b@hooks.slack.com/", "https://[hooks.slack.com]/", "https://hooks.slack.com%25/",
	} {
		f.Add(u, true)
		f.Add(u, false)
	}
	slack := map[string]bool{"hooks.slack.com": true, "hooks.slack-gov.com": true}
	teams := []string{".logic.azure.com", ".webhook.office.com", ".powerplatform.com", ".api.powerplatform.com"}
	label := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	f.Fuzz(func(t *testing.T, raw string, isSlack bool) {
		kind := Teams
		if isSlack {
			kind = Slack
		}
		s := New(kind, nil, "unused")
		if s.CheckWebhook(raw) != "" {
			return
		}
		trimmed := strings.TrimSpace(raw)
		u, err := url.Parse(trimmed)
		if err != nil || u.Scheme != "https" {
			t.Fatalf("%s accepted %q (scheme %q, %v)", kind, raw, u.Scheme, err)
		}
		// What the HTTP client dials is what NewRequest makes of the same text.
		req, err := http.NewRequest(http.MethodPost, trimmed, nil)
		if err != nil {
			t.Fatalf("%s accepted %q but a request can't be made: %v", kind, raw, err)
		}
		host := req.URL.Hostname()
		if host != strings.ToLower(host) && host != u.Hostname() {
			t.Fatalf("hosts differ for %q", raw)
		}
		host = strings.ToLower(host)
		ok := slack[host] && kind == Slack
		for _, suf := range teams {
			ok = ok || (kind == Teams && strings.HasSuffix(host, suf) && len(host) > len(suf))
		}
		if !ok {
			t.Fatalf("%s accepted %q: host %q is not the service's", kind, raw, host)
		}
		for _, l := range strings.Split(host, ".") {
			if !label.MatchString(l) {
				t.Fatalf("%s accepted %q: odd host %q", kind, raw, host)
			}
		}
		if u.Hostname() != req.URL.Hostname() {
			t.Fatalf("parse mismatch %q vs %q", u.Hostname(), req.URL.Hostname())
		}
	})
}
