package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/ocsf"
)

// SIEMLite drafts a parser from sample lines on its own, with no AI model:
// it works out the format, and for JSON and key=value lines which keys hold
// the time, addresses, user, message and so on, from both their names and
// their values. AI Parsers starts from this draft when it is on.

// SplitSamples turns pasted text into sample lines. JSON objects, pretty-printed
// over many lines or in an array, become one compact line each; any other text
// is split into lines.
func SplitSamples(text string) []string {
	if objs, ok := JSONValues([]byte(text)); ok {
		return objs
	}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// JSONValues reads b as a series of JSON values (objects, or arrays of
// objects, pretty-printed or not) and returns each object as a compact line.
// It reports false when b isn't entirely JSON, so the caller can read it as
// lines instead.
func JSONValues(b []byte) ([]string, bool) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	var out []string
	add := func(v json.RawMessage) bool {
		var c bytes.Buffer
		if json.Compact(&c, v) != nil {
			return false
		}
		out = append(out, c.String())
		return true
	}
	for {
		var v json.RawMessage
		if err := dec.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			return nil, false
		}
		v = bytes.TrimSpace(v)
		if len(v) > 0 && v[0] == '[' {
			var items []json.RawMessage
			if json.Unmarshal(v, &items) != nil {
				return nil, false
			}
			for _, it := range items {
				if !add(it) {
					return nil, false
				}
			}
			continue
		}
		if !add(v) {
			return nil, false
		}
	}
	return out, len(out) > 0
}

// Draft writes a parser that reads the sample lines, without a model.
func Draft(lines []string) Definition {
	bodies, strip := syslogBodies(lines)
	def := Definition{Name: "Drafted parser", Format: detectFormat(bodies), StripSyslog: strip, Category: 6,
		Severity: SeverityRule{From: "auto"}, Samples: lines}
	if def.Format == FormatPattern {
		def.Pattern = DraftPattern(bodies)
		return def
	}
	values := fieldValues(def, bodies)
	def.Fields = inferFields(values)
	def.Severity = inferSeverity(def.Fields, values)
	def.Category = inferCategory(def.Fields, values)
	return def
}

func syslogBodies(samples []string) ([]string, bool) {
	bodies := make([]string, len(samples))
	n := 0
	for i, l := range samples {
		b, ok := SyslogBody(l)
		bodies[i] = b
		if ok {
			n++
		}
	}
	if n*2 < len(samples) {
		return samples, false
	}
	return bodies, true
}

var kvLike = regexp.MustCompile(`(^|\s)[A-Za-z_][A-Za-z0-9_.-]*=`)

func detectFormat(bodies []string) string {
	jsonN, kvN := 0, 0
	for _, b := range bodies {
		var obj map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(b)), &obj) == nil {
			jsonN++
		}
		if len(kvLike.FindAllString(b, -1)) >= 3 {
			kvN++
		}
	}
	switch {
	case len(bodies) > 0 && jsonN == len(bodies):
		return FormatJSON
	case len(bodies) > 0 && kvN == len(bodies):
		return FormatKV
	}
	return FormatPattern
}

// fieldValues collects each field's values across the lines.
func fieldValues(def Definition, bodies []string) map[string][]string {
	out := map[string][]string{}
	p, err := Compile(Definition{Name: "x", Format: def.Format})
	if err != nil {
		return out
	}
	for _, b := range bodies {
		f, err := p.Fields(b)
		if err != nil {
			continue
		}
		for k, v := range f {
			out[k] = append(out[k], v)
		}
	}
	return out
}

// The names a key's last part may have, for each event field, best first.
var nameHints = []struct {
	target string
	names  []string
}{
	{"time", []string{"timestamp", "@timestamp", "time", "datetime", "date", "ts", "created_at", "createdat", "created", "event_time",
		"eventtime", "logged_at", "occurred_at", "time_stamp", "when", "at", "received_at"}},
	{"user", []string{"username", "user_name", "user", "login", "actor", "account", "principal", "email", "user_email", "usr", "who"}},
	{"message", []string{"message", "msg", "detail", "details", "description", "desc", "summary", "text", "reason", "log"}},
	{"host", []string{"hostname", "host", "host_name", "device", "computer", "machine", "node", "server"}},
	{"app", []string{"app", "application", "program", "process", "service", "component", "logger", "source"}},
	{"severity", []string{"severity", "level", "log_level", "loglevel", "lvl", "priority"}},
}

var ipNames = map[string]bool{"ip": true, "ip_address": true, "ipaddress": true, "ip_addr": true, "addr": true, "address": true,
	"src_ip": true, "source_ip": true, "client_ip": true, "remote_ip": true, "remote_addr": true, "srcip": true,
	"dst_ip": true, "dest_ip": true, "destination_ip": true, "target_ip": true, "server_ip": true, "dstip": true}

var dstHint = regexp.MustCompile(`(?i)(^|[._-])(dst|dest|destination|target|server|to)([._-]|$)|^(dst|dest)|^d(st|est)?port$`)

func leaf(k string) string { return strings.ToLower(k[strings.LastIndex(k, ".")+1:]) }

// inferFields maps keys to event fields by name and by value.
func inferFields(values map[string][]string) map[string]string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	taken := map[string]bool{}
	set := func(k, t string) {
		if !taken[t] && out[k] == "" {
			out[k], taken[t] = t, true
		}
	}
	now := time.Now()

	// Addresses and ports by value: every non-empty value an IP address
	// (or a port number, for a key named like a port).
	for _, k := range keys {
		nonEmpty := nonEmptyValues(values[k])
		if len(nonEmpty) == 0 {
			continue
		}
		switch {
		case all(nonEmpty, func(v string) bool { _, err := netip.ParseAddr(strings.Trim(v, "[]")); return err == nil }):
			if dstHint.MatchString(k) {
				set(k, "dst_ip")
			} else {
				set(k, "src_ip")
			}
		case strings.Contains(leaf(k), "port") && all(nonEmpty, func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= 0 && n < 65536 }):
			if dstHint.MatchString(k) {
				set(k, "dst_port")
			} else {
				set(k, "src_port")
			}
		}
	}
	// Addresses by name, when the values are addresses or empty (a sample
	// may not have one yet).
	for _, k := range keys {
		if out[k] != "" || !all(nonEmptyValues(values[k]), func(v string) bool { _, err := netip.ParseAddr(strings.Trim(v, "[]")); return err == nil }) {
			continue
		}
		switch l := leaf(k); {
		case ipNames[l] && dstHint.MatchString(k):
			set(k, "dst_ip")
		case ipNames[l]:
			set(k, "src_ip")
		}
	}
	// Then by name, best name first, checking the values make sense.
	for _, h := range nameHints {
		for _, name := range h.names {
			for _, k := range keys {
				if leaf(k) != name || out[k] != "" || taken[h.target] {
					continue
				}
				nonEmpty := nonEmptyValues(values[k])
				if len(nonEmpty) == 0 {
					continue
				}
				switch h.target {
				case "time":
					if !all(nonEmpty, func(v string) bool { _, ok := ParseTime(v, now); return ok }) {
						continue
					}
				case "user", "host", "app":
					if all(nonEmpty, isNumber) || all(nonEmpty, isJSONish) {
						continue
					}
				case "message":
					if all(nonEmpty, isJSONish) {
						continue
					}
				}
				set(k, h.target)
			}
		}
	}
	// A time by value alone, if no key is named like one.
	if !taken["time"] {
		for _, k := range keys {
			nonEmpty := nonEmptyValues(values[k])
			if len(nonEmpty) > 0 && !all(nonEmpty, isNumber) && all(nonEmpty, func(v string) bool { _, ok := ParseTime(v, now); return ok }) {
				set(k, "time")
				break
			}
		}
	}
	return out
}

// defaultSeverityWords are the keywords a new parser rates an event by, as stems
// matched anywhere in the value ("remov" is remove, removed, removal), and how
// severe each one is.
var defaultSeverityWords = []struct {
	stem string
	sev  int
}{
	{"delete", ocsf.SeverityMedium},
	{"remov", ocsf.SeverityMedium},
	{"disable", ocsf.SeverityHigh},
	{"revok", ocsf.SeverityHigh},
	{"error", ocsf.SeverityLow},
	{"denied", ocsf.SeverityMedium},
	{"deny", ocsf.SeverityMedium},
	{"refus", ocsf.SeverityMedium},
	{"unauthori", ocsf.SeverityHigh},
	{"forbidden", ocsf.SeverityMedium},
	{"reset", ocsf.SeverityMedium},
	{"password", ocsf.SeverityMedium},
	{"role", ocsf.SeverityMedium},
	{"permission", ocsf.SeverityMedium},
	{"privilege", ocsf.SeverityHigh},
	{"admin", ocsf.SeverityHigh},
	{"grant", ocsf.SeverityHigh},
	{"fail", ocsf.SeverityLow},
	{"reject", ocsf.SeverityMedium},
	{"invalid", ocsf.SeverityLow},
	{"lock", ocsf.SeverityMedium},
	{"breach", ocsf.SeverityCritical},
	{"attack", ocsf.SeverityCritical},
	{"malware", ocsf.SeverityCritical},
	{"block", ocsf.SeverityMedium},
	{"alert", ocsf.SeverityMedium},
	{"critical", ocsf.SeverityHigh},
}

// DefaultSeverityRules turns defaultSeverityWords into rules, worst first so a
// value holding several keywords gets the most severe one's level, and anything
// else informational.
func DefaultSeverityRules() []SeverityCase {
	var rules []SeverityCase
	for _, sev := range []int{ocsf.SeverityCritical, ocsf.SeverityHigh, ocsf.SeverityMedium, ocsf.SeverityLow} {
		var stems []string
		for _, w := range defaultSeverityWords {
			if w.sev == sev {
				stems = append(stems, w.stem)
			}
		}
		rules = append(rules, SeverityCase{Match: "(?i)" + strings.Join(stems, "|"), Severity: sev})
	}
	return append(rules, SeverityCase{Match: ".", Severity: ocsf.SeverityInformational})
}

// inferSeverity uses a level field when there is one, else an action,
// outcome or status field rated by defaultSeverityWords (a breach, attack or
// malware critical; disabling, revoking, privileges and admin high; refusals,
// deletions and password or role changes medium; failures and errors low; the
// rest informational).
func inferSeverity(fields map[string]string, values map[string][]string) SeverityRule {
	for _, t := range fields {
		if t == "severity" {
			return SeverityRule{From: "auto"}
		}
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range []string{"action", "event", "event_type", "eventtype", "type", "outcome", "result", "status", "activity", "operation", "op"} {
		for _, k := range keys {
			if leaf(k) != name || fields[k] != "" {
				continue
			}
			nonEmpty := nonEmptyValues(values[k])
			if len(nonEmpty) == 0 {
				continue
			}
			if all(nonEmpty, func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= 100 && n < 600 }) {
				return SeverityRule{From: "field", Field: k, Rules: []SeverityCase{{Match: `^5`, Severity: 3}, {Match: `^4`, Severity: 2}, {Match: `.`, Severity: 1}}}
			}
			if all(nonEmpty, isNumber) {
				continue
			}
			return SeverityRule{From: "field", Field: k, Rules: DefaultSeverityRules()}
		}
	}
	return SeverityRule{From: "auto"}
}

var authWords = regexp.MustCompile(`(?i)login|logon|log_in|signin|sign_in|logout|auth|password|mfa|session`)

// inferCategory: sign-in and account activity is authentication (3), traffic
// with both addresses and a port is network activity (4), the rest application (6).
func inferCategory(fields map[string]string, values map[string][]string) int {
	for k, vs := range values {
		if authWords.MatchString(k) {
			return 3
		}
		for _, v := range vs {
			if len(v) < 80 && authWords.MatchString(v) {
				return 3
			}
		}
	}
	got := map[string]bool{}
	for _, t := range fields {
		got[t] = true
	}
	if got["src_ip"] && got["dst_ip"] && (got["dst_port"] || got["src_port"]) {
		return 4
	}
	return 6
}

func nonEmptyValues(vs []string) []string {
	var out []string
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" && v != "null" {
			out = append(out, v)
		}
	}
	return out
}

func isNumber(v string) bool { _, err := strconv.ParseFloat(v, 64); return err == nil }

func isJSONish(v string) bool { return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{") }
