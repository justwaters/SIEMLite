package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/ocsf"
)

// Parser formats.
const (
	FormatPattern = "pattern" // text with {field} placeholders
	FormatJSON    = "json"    // one JSON object per line
	FormatKV      = "kv"      // key=value pairs
)

// Targets are the event fields a parsed value can fill. Anything else is
// kept as an extra field.
var Targets = []string{"time", "src_ip", "src_port", "dst_ip", "dst_port", "user", "host", "app", "message", "severity"}

// aliases map common field names to targets, so a pattern like {client_ip}
// or a JSON key like "level" is understood without a mapping.
var aliases = map[string]string{
	"time": "time", "timestamp": "time", "ts": "time", "@timestamp": "time", "date": "time", "datetime": "time",
	"src_ip": "src_ip", "src": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip", "client": "src_ip", "remote_addr": "src_ip", "srcip": "src_ip",
	"src_port": "src_port", "sport": "src_port", "source_port": "src_port", "srcport": "src_port",
	"dst_ip": "dst_ip", "dst": "dst_ip", "dest_ip": "dst_ip", "destination_ip": "dst_ip", "server_ip": "dst_ip", "dstip": "dst_ip",
	"dst_port": "dst_port", "dport": "dst_port", "dest_port": "dst_port", "destination_port": "dst_port", "dstport": "dst_port",
	"user": "user", "username": "user", "user_name": "user", "account": "user",
	"host": "host", "hostname": "host", "device": "host",
	"app": "app", "program": "app", "process": "app", "service": "app",
	"message": "message", "msg": "message",
	"severity": "severity", "level": "severity", "lvl": "severity", "priority": "severity",
}

// Definition is a parser as saved, uploaded and exported.
type Definition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Format      string `json:"format"`
	// Pattern is used by FormatPattern.
	Pattern string `json:"pattern,omitempty"`
	// StripSyslog parses and removes a syslog header first, so the pattern
	// only has to describe the message. The header supplies time, host and
	// program unless the pattern finds them too.
	StripSyslog bool `json:"strip_syslog,omitempty"`
	// Fields maps a captured name or JSON/key name to a target, or to ""
	// to keep it as an extra field. Names not listed use their alias, if any.
	Fields   map[string]string `json:"fields,omitempty"`
	Severity SeverityRule      `json:"severity"`
	// Category is the OCSF category for parsed events (default: application).
	Category int `json:"category,omitempty"`
	// Samples are example lines kept with the parser for testing.
	Samples []string `json:"samples,omitempty"`
}

// SeverityRule decides an event's severity.
type SeverityRule struct {
	// From is "auto" (the severity field if mapped, else keywords in the
	// line), "fixed", or "field" (Rules over Field's value).
	From  string         `json:"from,omitempty"`
	Fixed int            `json:"fixed,omitempty"`
	Field string         `json:"field,omitempty"`
	Rules []SeverityCase `json:"rules,omitempty"`
}

// SeverityCase sets Severity when the field's value matches the regex Match.
type SeverityCase struct {
	Match    string `json:"match"`
	Severity int    `json:"severity"`
}

// Parser is a compiled Definition. It is safe for concurrent use.
type Parser struct {
	def      Definition
	re       *regexp.Regexp
	names    []string
	sevRules []compiledCase
	classUID int
}

type compiledCase struct {
	re  *regexp.Regexp
	sev int
}

var (
	placeholder = regexp.MustCompile(`\{([^{}:]*)(?::((?:[^{}]|\{[0-9,]*\})*))?\}`)
	fieldName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.@-]{0,48}$`)
	spaces      = regexp.MustCompile(`\s+`)
)

// classFor is the generic OCSF class used for each category.
var classFor = map[int]int{1: 1007, 2: 2004, 3: 3002, 4: 4001, 5: 5001, 6: 6003, 7: 7001, 8: 8001}

// Compile validates a definition.
func Compile(def Definition) (*Parser, error) {
	def.Name = strings.TrimSpace(def.Name)
	if def.Name == "" || len(def.Name) > 80 {
		return nil, errors.New("name must be 1-80 characters")
	}
	if def.Category == 0 {
		def.Category = ocsf.CategoryApplicationActivity
	}
	p := &Parser{def: def, classUID: classFor[def.Category]}
	if p.classUID == 0 {
		return nil, fmt.Errorf("category must be 1-8 (got %d)", def.Category)
	}
	for name, target := range def.Fields {
		if target != "" && !isTarget(target) {
			return nil, fmt.Errorf("field %q maps to unknown target %q", name, target)
		}
	}
	switch def.Format {
	case FormatPattern:
		re, names, err := CompilePattern(def.Pattern)
		if err != nil {
			return nil, err
		}
		p.re, p.names = re, names
	case FormatJSON, FormatKV:
	default:
		return nil, fmt.Errorf("format must be pattern, json or kv (got %q)", def.Format)
	}
	switch def.Severity.From {
	case "", "auto":
	case "fixed":
		if !validSev(def.Severity.Fixed) {
			return nil, errors.New("fixed severity must be 0-6")
		}
	case "field":
		if def.Severity.Field == "" {
			return nil, errors.New("severity rules need a field")
		}
		for i, c := range def.Severity.Rules {
			re, err := regexp.Compile(c.Match)
			if err != nil {
				return nil, fmt.Errorf("severity rule %d: %w", i+1, err)
			}
			if !validSev(c.Severity) {
				return nil, fmt.Errorf("severity rule %d: severity must be 0-6", i+1)
			}
			p.sevRules = append(p.sevRules, compiledCase{re, c.Severity})
		}
	default:
		return nil, fmt.Errorf("severity must come from auto, fixed or field (got %q)", def.Severity.From)
	}
	return p, nil
}

func validSev(n int) bool { return n >= 0 && n <= 6 }
func isTarget(t string) bool {
	for _, x := range Targets {
		if x == t {
			return true
		}
	}
	return false
}

// CompilePattern turns "{a} - [{b}] {c:\d+}" into an anchored regexp.
// Literal text matches itself, runs of spaces match any whitespace, {name}
// matches as little as possible (or the rest of the line when last), {} skips
// text, and {name:regex} uses a custom expression.
func CompilePattern(pattern string) (*regexp.Regexp, []string, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, nil, errors.New("pattern is empty")
	}
	if len(pattern) > 2000 {
		return nil, nil, errors.New("pattern is too long")
	}
	var sb strings.Builder
	var names []string
	seen := map[string]bool{}
	sb.WriteString(`^\s*`)
	locs := placeholder.FindAllStringSubmatchIndex(pattern, -1)
	if len(locs) == 0 {
		return nil, nil, errors.New("pattern has no {fields}")
	}
	literal := func(s string) {
		for i, part := range spaces.Split(s, -1) {
			if i > 0 {
				sb.WriteString(`\s+`)
			}
			sb.WriteString(regexp.QuoteMeta(part))
		}
	}
	prev := 0
	for i, m := range locs {
		literal(pattern[prev:m[0]])
		name := strings.TrimSpace(pattern[m[2]:m[3]])
		custom := ""
		if m[4] >= 0 {
			custom = pattern[m[4]:m[5]]
			if _, err := regexp.Compile(custom); err != nil {
				return nil, nil, fmt.Errorf("{%s}: %w", name, err)
			}
		}
		expr := `.*?`
		if i == len(locs)-1 && strings.TrimSpace(pattern[m[1]:]) == "" {
			expr = `.*`
		}
		if custom != "" {
			expr = custom
		}
		switch {
		case name == "" || name == "_":
			sb.WriteString(`(?:` + expr + `)`)
		case !fieldName.MatchString(name):
			return nil, nil, fmt.Errorf("{%s}: field names use letters, numbers and _ . @ -", name)
		case seen[name]:
			return nil, nil, fmt.Errorf("{%s} appears twice", name)
		default:
			seen[name] = true
			names = append(names, name)
			sb.WriteString(`(` + expr + `)`)
		}
		prev = m[1]
	}
	literal(pattern[prev:])
	sb.WriteString(`\s*$`)
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return nil, nil, fmt.Errorf("pattern: %w", err)
	}
	return re, names, nil
}

// Definition returns the parser's definition.
func (p *Parser) Definition() Definition { return p.def }

// ErrNoMatch means a line didn't fit the parser.
var ErrNoMatch = errors.New("the line doesn't match this parser")

// Result is one parsed line.
type Result struct {
	Event *ocsf.Event
	// Fields are every extracted value, by name, including mapped ones.
	Fields map[string]string
	// Extra are the values not mapped to an event field.
	Extra map[string]string
}

// Parse turns one line into an event. Blank lines return (nil, nil).
func (p *Parser) Parse(line string, d Defaults) (*Result, error) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	if d.Now.IsZero() {
		d.Now = time.Now()
	}
	ev := &ocsf.Event{
		Time: d.Now.UnixMilli(), CategoryUID: p.def.Category, ClassUID: p.classUID, ActivityID: 99,
		SeverityID: ocsf.SeverityInformational, RawData: line,
	}
	if d.Source != "" {
		ev.Metadata.Product = &ocsf.Product{Name: d.Source}
	}

	body := line
	sevFromPRI := -1
	if p.def.StripSyslog {
		if h, ok := splitSyslog(line, d.Now); ok {
			ev.Time = h.time.UnixMilli()
			if h.host != "" {
				ev.Device = &ocsf.Endpoint{Hostname: h.host}
			}
			if h.app != "" && d.Source == "" {
				ev.Metadata.Product = &ocsf.Product{Name: h.app}
			}
			sevFromPRI, body = h.sevFromPRI, h.body
		}
	}

	fields, err := p.extract(body)
	if err != nil {
		return nil, err
	}
	res := &Result{Event: ev, Fields: fields, Extra: map[string]string{}}
	mappedSev := ""
	for name, value := range fields {
		target, ok := p.def.Fields[name]
		if !ok {
			target = aliases[strings.ToLower(name)]
		}
		if target == "" || !p.apply(ev, target, value, d.Now, &mappedSev) {
			res.Extra[name] = value
		}
	}
	if ev.Message == "" {
		ev.Message = strings.TrimSpace(body)
	}

	switch p.def.Severity.From {
	case "fixed":
		ev.SeverityID = p.def.Severity.Fixed
	case "field":
		ev.SeverityID = keywordSeverity(body)
		v := fields[p.def.Severity.Field]
		for _, c := range p.sevRules {
			if c.re.MatchString(v) {
				ev.SeverityID = c.sev
				break
			}
		}
	default:
		switch {
		case mappedSev != "":
			ev.SeverityID = severityValue(mappedSev)
		case sevFromPRI >= 0 && sevFromPRI != ocsf.SeverityInformational:
			ev.SeverityID = sevFromPRI
		default:
			ev.SeverityID = keywordSeverity(body)
		}
	}
	if d.SeverityID != nil {
		ev.SeverityID = *d.SeverityID
	}
	return res, nil
}

type syslogParts struct {
	time       time.Time
	host, app  string
	body       string // the message, after the whole header
	rest       string // everything after the host and time, tag included
	sevFromPRI int
}

// splitSyslog separates a syslog header (RFC 3164 or 5424, with or without
// the <PRI>) from the message. ok is false when the line has no header.
func splitSyslog(line string, now time.Time) (syslogParts, bool) {
	h := syslogParts{sevFromPRI: -1}
	body := line
	if m := syslogPRI.FindStringSubmatch(body); m != nil {
		pri, _ := strconv.Atoi(m[1])
		h.sevFromPRI = prioritySeverity(pri % 8)
		body = body[len(m[0]):]
	}
	is5424 := syslog5424.MatchString(body)
	t, host, app, rest, ok := syslogHeader(body, now)
	if !ok {
		return h, false
	}
	h.rest = rest
	if is5424 {
		rest = rfc5424Rest.ReplaceAllString(rest, "")
	} else if tag := syslogTag.FindStringSubmatch(rest); tag != nil && app != "" {
		rest = rest[len(tag[0]):]
	}
	h.time, h.host, h.app, h.body = t, host, app, rest
	return h, true
}

// SyslogBody returns the message part of a syslog line, and whether the
// line had a syslog header.
func SyslogBody(line string) (string, bool) {
	h, ok := splitSyslog(strings.TrimRight(line, "\r\n"), time.Now())
	if !ok {
		return line, false
	}
	return h.body, true
}

// Fields extracts the raw field values from a line body without building an
// event, for tools that need to see what a format yields.
func (p *Parser) Fields(body string) (map[string]string, error) { return p.extract(body) }

// apply sets one event field; it reports false when the value doesn't fit
// (e.g. an invalid IP), so the caller keeps it as an extra field instead.
func (p *Parser) apply(ev *ocsf.Event, target, v string, now time.Time, sev *string) bool {
	v = strings.TrimSpace(v)
	if v == "" || v == "-" {
		return true
	}
	switch target {
	case "time":
		t, ok := ParseTime(v, now)
		if ok {
			ev.Time = t.UnixMilli()
		}
		return ok
	case "src_ip", "dst_ip":
		a, err := netip.ParseAddr(strings.Trim(v, "[]"))
		if err != nil {
			return false
		}
		ep := endpoint(ev, target == "src_ip")
		ep.IP = a.String()
	case "src_port", "dst_port":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return false
		}
		endpoint(ev, target == "src_port").Port = n
	case "user":
		ev.Actor = &ocsf.Actor{User: &ocsf.User{Name: v}}
	case "host":
		if ev.Device == nil {
			ev.Device = &ocsf.Endpoint{}
		}
		ev.Device.Hostname = v
	case "app":
		if ev.Metadata.Product == nil {
			ev.Metadata.Product = &ocsf.Product{Name: v}
		}
	case "message":
		ev.Message = v
	case "severity":
		*sev = v
	}
	return true
}

func endpoint(ev *ocsf.Event, src bool) *ocsf.Endpoint {
	if src {
		if ev.SrcEndpoint == nil {
			ev.SrcEndpoint = &ocsf.Endpoint{}
		}
		return ev.SrcEndpoint
	}
	if ev.DstEndpoint == nil {
		ev.DstEndpoint = &ocsf.Endpoint{}
	}
	return ev.DstEndpoint
}

// severityValue reads a level name ("error", "warn") or a number: 0-6 as
// OCSF severity.
func severityValue(v string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= 6 {
		return n
	}
	return keywordSeverity(v)
}

const (
	maxFields   = 50
	maxFieldLen = 1024
)

func (p *Parser) extract(body string) (map[string]string, error) {
	out := map[string]string{}
	put := func(k, v string) {
		if len(out) >= maxFields {
			return
		}
		if len(v) > maxFieldLen {
			v = v[:maxFieldLen]
		}
		out[k] = v
	}
	switch p.def.Format {
	case FormatPattern:
		m := p.re.FindStringSubmatch(body)
		if m == nil {
			return nil, ErrNoMatch
		}
		for i, name := range p.names {
			put(name, m[i+1])
		}
	case FormatJSON:
		var obj map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &obj); err != nil {
			return nil, ErrNoMatch
		}
		flatten("", obj, put)
	case FormatKV:
		pairs := kvPair.FindAllStringSubmatch(body, -1)
		if len(pairs) == 0 {
			return nil, ErrNoMatch
		}
		for _, kv := range pairs {
			v := kv[2]
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			put(kv[1], v)
		}
	}
	return out, nil
}

// rfc5424Rest is APP-NAME PROCID MSGID STRUCTURED-DATA before the message.
var rfc5424Rest = regexp.MustCompile(`^\S+ \S+ \S+ (?:-|(?:\[(?:[^\]"]|"(?:[^"\\]|\\.)*")*\])+) ?`)

var kvPair = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.@-]*)=("[^"]*"|'[^']*'|\S*)`)

// flatten turns nested JSON into dotted keys ("client.ip").
func flatten(prefix string, v any, put func(k, v string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, val, put)
		}
	case nil:
	case string:
		put(prefix, x)
	case float64:
		put(prefix, strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		put(prefix, strconv.FormatBool(x))
	default:
		b, _ := json.Marshal(x)
		put(prefix, string(b))
	}
}

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05,999",
	"02/Jan/2006:15:04:05 -0700", // nginx and Apache
	"2006/01/02 15:04:05",
	"01/02/2006 15:04:05",
	"Mon Jan _2 15:04:05 2006",
	"Mon Jan _2 15:04:05 MST 2006",
	time.RFC1123Z,
	time.RFC1123,
}

// ParseTime reads the common timestamp formats, syslog's yearless
// "Jan  2 15:04:05", and Unix epoch seconds or milliseconds.
func ParseTime(v string, now time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseFloat(v, 64); err == nil && !strings.ContainsAny(v, "eE") {
		switch {
		case n > 1e11 && n < 1e14: // milliseconds
			return time.UnixMilli(int64(n)), true
		case n > 1e8 && n < 1e11: // seconds
			return time.Unix(int64(n), int64((n-float64(int64(n)))*1e9)), true
		}
		return time.Time{}, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	if t, _, _, _, ok := syslogHeader(v+" x", now); ok {
		return t, true
	}
	return time.Time{}, false
}

// Explain says where pattern stops matching line: the longest leading part
// of the pattern that still matches, and the piece after it. ok is true when
// the whole pattern matches.
func Explain(pattern, line string) (matched, next string, ok bool) {
	if re, _, err := CompilePattern(pattern); err == nil && re.MatchString(line) {
		return pattern, "", true
	}
	// Cut points: the end of each literal run and of each placeholder.
	var cuts []int
	prev := 0
	for _, m := range placeholder.FindAllStringIndex(pattern, -1) {
		if m[0] > prev {
			cuts = append(cuts, m[0])
		}
		cuts = append(cuts, m[1])
		prev = m[1]
	}
	if prev < len(pattern) {
		cuts = append(cuts, len(pattern))
	}
	best := 0
	for _, c := range cuts {
		re, _, err := CompilePattern(pattern[:c] + "{}")
		if err != nil || !re.MatchString(line) {
			break
		}
		best = c
	}
	end := len(pattern)
	for _, c := range cuts {
		if c > best {
			end = c
			break
		}
	}
	// Inside a literal run, find the exact character that fails.
	if !strings.HasPrefix(pattern[best:end], "{") {
		for k := best + 1; k < end; k++ {
			re, _, err := CompilePattern(pattern[:k] + "{}")
			if err != nil || !re.MatchString(line) {
				break
			}
			best = k
		}
		// Report from the start of the failing word, so spaces aren't the culprit.
		for best > 0 && pattern[best-1] != ' ' && pattern[best-1] != '}' && best < end && pattern[best] != ' ' {
			if re, _, err := CompilePattern(pattern[:best-1] + "{}"); err != nil || !re.MatchString(line) {
				break
			}
			best--
		}
	}
	return pattern[:best], pattern[best:end], false
}
