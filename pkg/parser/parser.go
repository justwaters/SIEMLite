// Package parser turns raw log lines (syslog, JSON, plain text) into OCSF
// events. The original line is always preserved in RawData so it can be
// searched and displayed exactly as received.
package parser

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/ocsf"
)

// Defaults apply to lines that do not carry the information themselves.
type Defaults struct {
	Source     string    // product name, e.g. "nginx" or "sshd"
	SeverityID *int      // overrides severity detection when set
	Now        time.Time // fallback timestamp (default: time.Now)
}

var (
	syslogPRI  = regexp.MustCompile(`^<(\d{1,3})>`)
	syslog5424 = regexp.MustCompile(`^(\d)?\s*(\d{4}-\d{2}-\d{2}T[^\s]+)\s+(\S+)`)
	syslog3164 = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)`)
	syslogTag  = regexp.MustCompile(`^([A-Za-z0-9_./-]{1,48})(?:\[\d+\])?:\s`)
	isoPrefix  = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)`)
	ipv4       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	userField  = regexp.MustCompile(`(?i)\b(?:user(?:name)?[=:]\s*|for (?:invalid user )?|user )([A-Za-z0-9_.\-]+)`)

	critical = regexp.MustCompile(`(?i)\b(fatal|panic|critical|emerg(ency)?|alert)\b`)
	high     = regexp.MustCompile(`(?i)\b(error|err|denied|blocked|attack|exploit|injection)\b`)
	medium   = regexp.MustCompile(`(?i)\b(fail(ed|ure)?|invalid|refused|unauthori[sz]ed|forbidden)\b`)
	low      = regexp.MustCompile(`(?i)\b(warn(ing)?)\b`)
)

// ParseLine converts one log line into an event. Blank lines return nil.
func ParseLine(line string, d Defaults) *ocsf.Event {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return nil
	}
	if d.Now.IsZero() {
		d.Now = time.Now()
	}

	if ev := parseJSON(line, d); ev != nil {
		return ev
	}

	ev := &ocsf.Event{
		Time:        d.Now.UnixMilli(),
		CategoryUID: ocsf.CategoryApplicationActivity,
		ClassUID:    6003,
		ActivityID:  99,
		SeverityID:  ocsf.SeverityInformational,
		Message:     line,
		RawData:     line,
		Metadata:    ocsf.Metadata{},
	}
	if d.Source != "" {
		ev.Metadata.Product = &ocsf.Product{Name: d.Source}
	}

	body := line
	sevFromPRI := -1
	if m := syslogPRI.FindStringSubmatch(body); m != nil {
		pri, _ := strconv.Atoi(m[1])
		sevFromPRI = prioritySeverity(pri % 8)
		body = body[len(m[0]):]
	}
	if t, host, app, rest, ok := syslogHeader(body, d.Now); ok {
		ev.Time = t.UnixMilli()
		if host != "" {
			ev.Device = &ocsf.Endpoint{Hostname: host}
		}
		if app != "" && ev.Metadata.Product == nil {
			ev.Metadata.Product = &ocsf.Product{Name: app}
		}
		body = rest
	} else if m := isoPrefix.FindString(body); m != "" {
		if t, ok := parseISO(m); ok {
			ev.Time = t.UnixMilli()
		}
	}

	ips := ipv4.FindAllString(body, 2)
	var valid []string
	for _, ip := range ips {
		if _, err := netip.ParseAddr(ip); err == nil {
			valid = append(valid, ip)
		}
	}
	if len(valid) > 0 {
		ev.SrcEndpoint = &ocsf.Endpoint{IP: valid[0]}
	}
	if len(valid) > 1 {
		ev.DstEndpoint = &ocsf.Endpoint{IP: valid[1]}
	}
	if m := userField.FindStringSubmatch(body); m != nil {
		ev.Actor = &ocsf.Actor{User: &ocsf.User{Name: m[1]}}
	}

	switch {
	case d.SeverityID != nil:
		ev.SeverityID = *d.SeverityID
	case sevFromPRI >= 0 && sevFromPRI != ocsf.SeverityInformational:
		ev.SeverityID = sevFromPRI
	default:
		ev.SeverityID = keywordSeverity(body)
	}
	return ev
}

// ParseLines parses every non-blank line of text.
func ParseLines(lines []string, d Defaults) []*ocsf.Event {
	out := make([]*ocsf.Event, 0, len(lines))
	for _, l := range lines {
		if ev := ParseLine(l, d); ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// parseJSON handles JSON-lines input. Objects that already look like OCSF
// (category_uid + class_uid) are used as-is; any other object is stored as
// an application log with its message/level fields mapped.
func parseJSON(line string, d Defaults) *ocsf.Event {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(trimmed), &generic); err != nil {
		return nil
	}

	if _, hasCat := generic["category_uid"]; hasCat {
		var ev ocsf.Event
		if err := json.Unmarshal([]byte(trimmed), &ev); err == nil {
			ev.RawData = trimmed
			return &ev
		}
	}

	ev := &ocsf.Event{
		Time:        d.Now.UnixMilli(),
		CategoryUID: ocsf.CategoryApplicationActivity,
		ClassUID:    6003,
		ActivityID:  99,
		SeverityID:  ocsf.SeverityInformational,
		RawData:     trimmed,
		Unmapped:    generic,
	}
	if d.Source != "" {
		ev.Metadata.Product = &ocsf.Product{Name: d.Source}
	}
	for _, k := range []string{"message", "msg", "log"} {
		if s, ok := generic[k].(string); ok {
			ev.Message = s
			break
		}
	}
	for _, k := range []string{"timestamp", "time", "ts", "@timestamp"} {
		if s, ok := generic[k].(string); ok {
			if t, ok := parseISO(s); ok {
				ev.Time = t.UnixMilli()
				break
			}
		}
	}
	level := ""
	for _, k := range []string{"level", "severity", "lvl"} {
		if s, ok := generic[k].(string); ok {
			level = s
			break
		}
	}
	switch {
	case d.SeverityID != nil:
		ev.SeverityID = *d.SeverityID
	case level != "":
		ev.SeverityID = keywordSeverity(level)
	default:
		ev.SeverityID = keywordSeverity(ev.Message)
	}
	return ev
}

// prioritySeverity maps a syslog severity (0-7) to OCSF severity_id.
func prioritySeverity(s int) int {
	switch {
	case s <= 1:
		return ocsf.SeverityCritical
	case s == 2:
		return ocsf.SeverityHigh
	case s == 3:
		return ocsf.SeverityMedium
	case s == 4:
		return ocsf.SeverityLow
	default:
		return ocsf.SeverityInformational
	}
}

func keywordSeverity(s string) int {
	switch {
	case critical.MatchString(s):
		return ocsf.SeverityCritical
	case high.MatchString(s):
		return ocsf.SeverityHigh
	case medium.MatchString(s):
		return ocsf.SeverityMedium
	case low.MatchString(s):
		return ocsf.SeverityLow
	default:
		return ocsf.SeverityInformational
	}
}

// syslogHeader strips an RFC5424 or RFC3164 header, returning the time, host,
// application name (APP-NAME or TAG, when present) and remaining message.
func syslogHeader(s string, now time.Time) (t time.Time, host, app, rest string, ok bool) {
	if m := syslog5424.FindStringSubmatch(s); m != nil {
		if ts, err := time.Parse(time.RFC3339Nano, m[2]); err == nil {
			host = m[3]
			if host == "-" {
				host = ""
			}
			rest = strings.TrimSpace(s[len(m[0]):])
			// RFC5424: APP-NAME PROCID MSGID ... ("-" when absent). Only
			// trust it when the version digit says this really is 5424.
			if m[1] != "" {
				if first, _, _ := strings.Cut(rest, " "); first != "-" && len(first) <= 48 {
					app = first
				}
			}
			return ts, host, app, rest, true
		}
	}
	if m := syslog3164.FindStringSubmatch(s); m != nil {
		// RFC3164 omits the year; assume the current one (or last year if that
		// would put the timestamp in the future).
		ts, err := time.ParseInLocation("Jan _2 15:04:05", m[1], now.Location())
		if err == nil {
			ts = ts.AddDate(now.Year(), 0, 0)
			if ts.After(now.Add(24 * time.Hour)) {
				ts = ts.AddDate(-1, 0, 0)
			}
			rest = strings.TrimSpace(s[len(m[0]):])
			if tag := syslogTag.FindStringSubmatch(rest); tag != nil {
				app = tag[1]
			}
			return ts, m[2], app, rest, true
		}
	}
	return time.Time{}, "", "", s, false
}

func parseISO(s string) (time.Time, bool) {
	s = strings.Replace(s, ",", ".", 1)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
