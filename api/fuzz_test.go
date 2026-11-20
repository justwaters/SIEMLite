package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
)

// fuzzEndpoint is one route the fuzzer can reach; {id} is replaced by the fuzzed path segment.
type fuzzEndpoint struct {
	method, path string
	shape        string // what a 200/201 body must be: "object", "array", "pdf", "" (no body expected, or anything)
	upstream     bool   // may answer 502 when a real service is unreachable
}

var fuzzEndpoints = []fuzzEndpoint{
	{"GET", "/api/v1/intel/feeds", "object", false},
	{"PUT", "/api/v1/intel/feeds", "object", false},
	{"POST", "/api/v1/intel/feeds/refresh", "object", false},
	{"GET", "/api/v1/intel/friendly", "array", false},
	{"POST", "/api/v1/intel/friendly", "object", false},
	{"PATCH", "/api/v1/intel/friendly/{id}", "", false},
	{"DELETE", "/api/v1/intel/friendly/{id}", "", false},
	{"POST", "/api/v1/intel/friendly/{id}/entries", "object", false},
	{"DELETE", "/api/v1/intel/friendly/{id}/entries", "", false},
	{"GET", "/api/v1/reports/summary", "object", false},
	{"POST", "/api/v1/reports/runs", "object", false},
	{"GET", "/api/v1/reports/runs", "array", false},
	{"GET", "/api/v1/reports/runs/{id}/pdf", "pdf", false},
	{"DELETE", "/api/v1/reports/runs/{id}", "", false},
	{"GET", "/api/v1/reports/schedules", "object", false},
	{"POST", "/api/v1/reports/schedules", "object", false},
	{"PUT", "/api/v1/reports/schedules/{id}", "object", false},
	{"DELETE", "/api/v1/reports/schedules/{id}", "", false},
	{"POST", "/api/v1/reports/schedules/{id}/run", "object", false},
	{"GET", "/api/v1/integrations/slack", "object", false},
	{"PUT", "/api/v1/integrations/slack", "object", false},
	{"POST", "/api/v1/integrations/slack/test", "object", true},
	{"GET", "/api/v1/integrations/teams", "object", false},
	{"PUT", "/api/v1/integrations/teams", "object", false},
	{"POST", "/api/v1/integrations/teams/test", "object", true},
	{"GET", "/api/v1/activity", "object", false},
}

// rawEscape percent-encodes everything a client library would refuse to send, keeping every byte reachable.
func rawEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '#' || c == '?' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func nestedJSON(depth int) []byte {
	return []byte(strings.Repeat(`{"feeds":`, depth) + `[]` + strings.Repeat(`}`, depth))
}

// FuzzAPIBodies throws arbitrary bodies, query strings and path segments at the Intel, friendly-list, report,
// chat and activity endpoints of one shared server, signed in as an admin. It must never answer 5xx, never drop
// the connection (a handler panic does), and always answer with the kind of body the endpoint promises.
func FuzzAPIBodies(f *testing.F) {
	log.SetOutput(io.Discard)
	e := newEnvTB(f, nil, fullDeps(f, offline{}))
	e.user("root", auth.RoleAdmin)
	c := e.client()
	c.Timeout = time.Minute
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if got := e.login(c, "root", password); got.StatusCode != 200 {
		f.Fatalf("login = %d", got.StatusCode)
	}

	big := strings.Repeat("A", 1<<20+1)
	seeds := []struct {
		seg, query string
		body       string
	}{
		{"1", "", `{"feeds":["feodo"]}`},
		{"1", "days=7", `{"days":7}`},
		{"1", "", `{"name":"Office","description":"HQ"}`},
		{"1", "value=10.0.0.1", `{"values":"10.0.0.1 10.0.0.0/8","note":"n"}`},
		{"1", "", `{"name":"w","frequency":"weekly","weekday":1,"hour":8,"covers_days":7,"recipients":"a@example.com"}`},
		{"1", "", `{"webhook":"https://hooks.slack.com/services/T/B/X","min_severity":4}`},
		{"1", "from=1&to=2", `{"from":1,"to":9223372036854775807}`},
		{"-1", "days=-5", `{"days":-9223372036854775808,"hour":-1,"covers_days":-1,"min_severity":-7}`},
		{"0", "", `{"days":99999999999999999999999,"id":1e400,"hour":1e999}`},
		{"99999999999999999999", "days=99999999999999999999", `{"days":1.5e300}`},
		{"abc", "value=", `null`},
		{"1", "", `{"name":null,"description":null,"values":null,"note":null,"feeds":null,"webhook":null,"recipients":null,"frequency":null}`},
		{"1", "", `{"name":5,"values":[1,2],"feeds":"x","webhook":{},"days":"7","hour":"3","enabled":"yes","frequency":[]}`},
		{"1", "", `[]`}, {"1", "", `"str"`}, {"1", "", `12`}, {"1", "", ``}, {"1", "", `{`},
		{"1", "", string(nestedJSON(10000))},
		{"1", "", `{"name":"` + strings.Repeat("é‮\U0001F600", 40) + `","description":"\u0000\ud800"}`},
		{"1\x00", "value=\x00\x00", "{\"name\":\"a\x00b\",\"values\":\"1.2.3.4\x00\",\"webhook\":\"https://hooks.slack.com/\x00\"}"},
		{"%00", "days=%00&value=%ff%fe", "\xff\xfe\x00\x01"},
		{"1", "value=" + strings.Repeat("x", 70000), `{"name":"` + big + `"}`},
		{"1", "", `{"values":"` + big + `","note":"` + big + `","webhook":"` + big + `"}`},
		{"../../x", "days=7&days=8&days=9", `{"days":7,"days":8}`},
		{"1", "", `{"name":"x","frequency":"monthly","day_of_month":28,"hour":23,"covers_days":30,"id":5,"enabled":false,"next_run":-1,"last_run":1e18}`},
	}
	for i := range fuzzEndpoints {
		for _, s := range seeds {
			f.Add(uint8(i), s.seg, s.query, []byte(s.body))
		}
	}

	f.Fuzz(func(t *testing.T, sel uint8, seg, query string, body []byte) {
		ep := fuzzEndpoints[int(sel)%len(fuzzEndpoints)]
		escaped := url.PathEscape(seg)
		if sel&0x80 != 0 && ep.method != "" {
			escaped = rawEscape(seg) // keeps '/', '%' and dots live as path syntax
		}
		if seg == "" {
			escaped = "1"
		}
		path := strings.ReplaceAll(ep.path, "{id}", escaped)
		target := e.srv.URL + path
		if query != "" {
			target += "?" + rawEscape(query)
		}
		req, err := http.NewRequest(ep.method, target, bytes.NewReader(body))
		if err != nil {
			t.Skip()
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s: no response (a panic closes the connection): %v", ep.method, path, err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s %s: reading the response: %v", ep.method, path, err)
		}
		st := resp.StatusCode
		if st >= 500 && !(st == http.StatusBadGateway && ep.upstream) {
			t.Fatalf("%s %s -> %d %.200s", ep.method, path, st, out)
		}
		ct := resp.Header.Get("Content-Type")
		switch {
		case st == http.StatusNoContent || st == http.StatusNotModified:
			if len(out) != 0 {
				t.Errorf("%s %s -> %d with a body", ep.method, path, st)
			}
		case st >= 300 && st < 400, st == 404 && strings.HasPrefix(ct, "text/plain"), st == 405:
			// the router's own answers for odd paths
		case st == 200 && ep.shape == "pdf":
			if !bytes.HasPrefix(out, []byte("%PDF-")) || ct != "application/pdf" {
				t.Errorf("%s %s: not a PDF (%s, %.20q)", ep.method, path, ct, out)
			}
		default:
			if !strings.HasPrefix(ct, "application/json") || !json.Valid(out) {
				t.Fatalf("%s %s -> %d: not JSON (%s) %.200q", ep.method, path, st, ct, out)
			}
			var v any
			_ = json.Unmarshal(out, &v)
			if st >= 400 {
				if m, ok := v.(map[string]any); !ok || m["error"] == nil {
					t.Errorf("%s %s -> %d: an error without an \"error\": %.200s", ep.method, path, st, out)
				}
				break
			}
			switch ep.shape {
			case "object":
				if _, ok := v.(map[string]any); !ok {
					t.Errorf("%s %s -> %d: want an object, got %.100s", ep.method, path, st, out)
				}
			case "array":
				if _, ok := v.([]any); !ok {
					t.Errorf("%s %s -> %d: want an array, got %.100s", ep.method, path, st, out)
				}
			case "pdf", "":
				if ep.shape == "pdf" || st != 200 && st != 201 {
					t.Errorf("%s %s -> %d: unexpected JSON %.100s", ep.method, path, st, out)
				}
			}
		}
		// Chat settings never echo a webhook address back.
		if strings.Contains(path, "/integrations/") && bytes.Contains(out, []byte("hooks.slack.com/services/T/B/X")) {
			t.Errorf("%s %s echoed the webhook address: %.200s", ep.method, path, out)
		}
	})
}
