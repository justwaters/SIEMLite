package parser

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DraftPattern writes a pattern that matches every line, by lining the lines
// up word by word: words that are the same everywhere stay literal, words
// that differ become placeholders named by what their values look like, and
// variable text in the middle or at the end is absorbed. It returns "" when
// there are no lines.
func DraftPattern(lines []string) string {
	var toks [][]string
	minLen := -1
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		t := strings.FieldsFunc(l, isSpace)
		toks = append(toks, t)
		if minLen < 0 || len(t) < minLen {
			minLen = len(t)
		}
	}
	if len(toks) == 0 {
		return ""
	}
	sameLen := true
	for _, t := range toks {
		sameLen = sameLen && len(t) == minLen
	}

	column := func(i int, fromEnd bool) []string {
		col := make([]string, len(toks))
		for j, t := range toks {
			if fromEnd {
				col[j] = t[len(t)-1-i]
			} else {
				col[j] = t[i]
			}
		}
		return col
	}
	// Lines with the same number of words line up position by position.
	// Otherwise line up from the start while words look alike, then from
	// the end, and absorb the middle.
	prefix := 0
	if sameLen {
		prefix = minLen
	}
	for prefix < minLen && compatible(column(prefix, false)) {
		prefix++
	}
	suffix := 0
	if !sameLen || prefix < minLen {
		for suffix < minLen-prefix && compatible(column(suffix, true)) {
			suffix++
		}
	}

	var segs []segment
	for i := 0; i < prefix; i++ {
		if i+1 < prefix {
			if seg, ok := timePair(column(i, false), column(i+1, false)); ok {
				segs = append(segs, seg)
				i++
				continue
			}
		}
		segs = append(segs, describe(column(i, false))...)
	}
	middle := prefix < minLen-suffix || (!sameLen && suffix > 0)
	if middle && prefix+suffix == minLen {
		suffix-- // the shortest line must still have a word for {message}
	}
	if middle {
		segs = append(segs, segment{name: "message", multi: true})
	}
	for i := suffix - 1; i >= 0; i-- {
		segs = append(segs, describe(column(i, true))...)
	}
	trailing := !sameLen && !middle // extra words after the aligned part on some lines
	pat := render(mergeWords(segs), trailing)
	if _, names, err := CompilePattern(pat); err != nil || len(names) == 0 {
		return "{message}" // every line is the same (or the draft is unusable)
	}
	return pat
}

// isSpace matches the regexp \s class used by patterns (which, unlike
// strings.Fields, doesn't include \v or Unicode spaces).
func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r' }

// braces writes literal braces as unnamed placeholders, since patterns have
// no other way to match them.
var braces = strings.NewReplacer("{", `{:\x7b}`, "}", `{:\x7d}`)

// timePair recognises a timestamp written as two words, like nginx's
// [03/Oct/2026:10:17:12 +0000], keeping any wrapping punctuation literal.
func timePair(a, b []string) (segment, bool) {
	joined := make([]string, len(a))
	for i := range a {
		joined[i] = a[i] + " " + b[i]
	}
	return timeWord(joined, true)
}

// timeWord recognises a column of timestamps, possibly wrapped in brackets
// or quotes.
func timeWord(col []string, multi bool) (segment, bool) {
	lead := strings.IndexFunc(col[0], func(r rune) bool { return r >= 128 || isAlnum(byte(r)) || r == '+' || r == '-' })
	if lead < 0 {
		return segment{}, false
	}
	pre := col[0][:lead]
	trail := strings.LastIndexFunc(col[0], func(r rune) bool { return r >= 128 || isAlnum(byte(r)) })
	suf := col[0][trail+1:]
	for _, w := range col {
		if !strings.HasPrefix(w, pre) || !strings.HasSuffix(w, suf) || len(w) <= len(pre)+len(suf) {
			return segment{}, false
		}
		if _, ok := ParseTime(w[len(pre):len(w)-len(suf)], timeNow()); !ok {
			return segment{}, false
		}
	}
	t := segment{name: "time", multi: multi}
	if multi {
		t.regex = `\S+\s+\S+`
	}
	if pre == "" && suf == "" {
		return t, true
	}
	var parts []segment
	if pre != "" {
		parts = append(parts, segment{lit: pre})
	}
	t.regex = ""
	parts = append(parts, t)
	if suf != "" {
		parts = append(parts, segment{lit: suf})
	}
	return segment{parts: parts}, true
}

// segment is one aligned word: literal text, a placeholder, or a mix such as
// user={user}. A word is a list of parts; parts within a word are not
// separated by spaces.
type segment struct {
	lit   string // literal word (when name == "")
	name  string // placeholder name
	regex string // custom regex for the placeholder, if needed
	multi bool   // spans several words (message)
	parts []segment
}

var (
	wordRe  = regexp.MustCompile(`^[A-Za-z]+$`)
	levelRe = regexp.MustCompile(`^(?i)(trace|debug|info|notice|warn|warning|error|err|crit|critical|alert|emerg|fatal|panic)$`)
	methods = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true, "PATCH": true, "OPTIONS": true, "CONNECT": true}
	dateRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}([.,]\d+)?(Z|[+-]\d{2}:?\d{2})?)?$`)
	clockRe = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}([.,]\d+)?(Z|[+-]\d{2}:?\d{2})?$`)
	alnum   = regexp.MustCompile(`[A-Za-z0-9_]+`)
)

// compatible reports whether a column of words can be lined up: the same
// word everywhere, the same punctuation shape, the same bracket wrapping,
// or all plain words.
func compatible(col []string) bool {
	allSame, allWords, sameShape, sameWrap := true, true, true, true
	shape := alnum.ReplaceAllString(col[0], "w")
	for _, w := range col {
		allSame = allSame && w == col[0]
		allWords = allWords && wordRe.MatchString(w)
		sameShape = sameShape && alnum.ReplaceAllString(w, "w") == shape
		sameWrap = sameWrap && len(w) > 2 && len(col[0]) > 2 && w[0] == col[0][0] && w[len(w)-1] == col[0][len(col[0])-1] &&
			!isAlnum(w[0]) && !isAlnum(w[len(w)-1])
	}
	return allSame || allWords || sameShape || sameWrap
}

func isAlnum(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// describe turns one aligned column into segments.
func describe(col []string) []segment {
	same := true
	for _, w := range col {
		same = same && w == col[0]
	}
	// Values that vary by nature are fields even if the samples agree.
	switch {
	case all(col, isIP):
		return []segment{{name: "ip"}}
	case all(col, isIPPort):
		return []segment{{parts: []segment{{name: "ip"}, {lit: ":"}, {name: "port"}}}}
	case all(col, dateRe.MatchString):
		return []segment{{name: "date"}}
	case all(col, clockRe.MatchString):
		return []segment{{name: "clock"}}
	}
	if seg, ok := timeWord(col, false); ok && !all(col, func(v string) bool { _, err := strconv.Atoi(v); return err == nil }) {
		return []segment{seg}
	}
	if same {
		return []segment{{lit: col[0]}}
	}
	// Whole-word types first.
	switch {
	case all(col, isIP):
		return []segment{{name: "ip"}}
	case all(col, isIPPort):
		return []segment{{parts: []segment{{name: "ip"}, {lit: ":"}, {name: "port"}}}}
	case all(col, dateRe.MatchString):
		return []segment{{name: "date"}}
	case all(col, clockRe.MatchString):
		return []segment{{name: "clock"}}
	}
	// Shared leading and trailing punctuation-delimited text stays literal:
	// user=bob / user=alice -> user={user}; [auth] / [billing] -> [{...}].
	pre, suf := commonEdges(col)
	inner := make([]string, len(col))
	for i, w := range col {
		inner[i] = w[len(pre) : len(w)-len(suf)]
	}
	name := nameFor(inner, pre)
	var parts []segment
	if pre != "" {
		parts = append(parts, segment{lit: pre})
	}
	if all(inner, isIPPort) {
		parts = append(parts, segment{name: "ip"}, segment{lit: ":"}, segment{name: "port"})
	} else {
		parts = append(parts, segment{name: name})
	}
	if suf != "" {
		parts = append(parts, segment{lit: suf})
	}
	if len(parts) == 1 {
		return parts
	}
	return []segment{{parts: parts}}
}

func commonEdges(col []string) (string, string) {
	pre := col[0]
	for _, w := range col[1:] {
		for !strings.HasPrefix(w, pre) {
			pre = pre[:len(pre)-1]
		}
	}
	// Keep the prefix only up to its last punctuation character.
	cut := strings.LastIndexFunc(pre, func(r rune) bool { return r < 128 && !isAlnum(byte(r)) })
	pre = pre[:cut+1]
	for _, w := range col {
		if len(w) == len(pre) {
			pre = "" // the field would be empty in this word
		}
	}
	suf := col[0][len(pre):]
	for _, w := range col {
		w = w[len(pre):]
		for !strings.HasSuffix(w, suf) {
			suf = suf[1:]
		}
	}
	idx := strings.IndexFunc(suf, func(r rune) bool { return r < 128 && !isAlnum(byte(r)) })
	if idx < 0 {
		suf = ""
	} else {
		suf = suf[idx:]
	}
	for _, w := range col {
		if len(w) < len(pre)+len(suf)+1 {
			return pre, ""
		}
	}
	return pre, suf
}

func nameFor(vals []string, prefix string) string {
	key := strings.ToLower(strings.TrimRight(prefix, "=:\"' "))
	if i := strings.LastIndexAny(key, " [(\"'"); i >= 0 {
		key = key[i+1:]
	}
	switch {
	case all(vals, isIP):
		if key == "dst" || key == "dest" || key == "to" || key == "dst_ip" {
			return "dst_ip"
		}
		return "ip"
	case key != "" && fieldName.MatchString(key) && (strings.HasSuffix(prefix, "=") || strings.HasSuffix(prefix, ":")):
		return key
	case all(vals, func(v string) bool { return levelRe.MatchString(v) }):
		return "level"
	case all(vals, func(v string) bool { return methods[strings.ToUpper(v)] }):
		return "method"
	case all(vals, func(v string) bool {
		n, err := strconv.Atoi(v)
		return err == nil && n >= 100 && n <= 599 && len(v) == 3
	}):
		return "status"
	case all(vals, func(v string) bool { _, err := strconv.Atoi(v); return err == nil }):
		return "number"
	case strings.HasSuffix(prefix, "["):
		return "component"
	}
	return "word"
}

// timeNow is the reference time for yearless timestamps.
var timeNow = time.Now

func all(vals []string, f func(string) bool) bool {
	for _, v := range vals {
		if !f(v) {
			return false
		}
	}
	return true
}

func isIP(v string) bool { _, err := netip.ParseAddr(strings.Trim(v, "[]")); return err == nil }
func isIPPort(v string) bool {
	_, err := netip.ParseAddrPort(v)
	return err == nil
}

// mergeWords joins neighbouring plain-word placeholders into one message,
// and a date followed by a clock into one time.
func mergeWords(segs []segment) []segment {
	var out []segment
	for _, s := range segs {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			if (prev.name == "word" || prev.name == "message") && (s.name == "word" || s.name == "message") {
				prev.name, prev.multi = "message", true
				continue
			}
			if prev.name == "date" && s.name == "clock" {
				prev.name, prev.regex = "time", `\S+\s+\S+`
				continue
			}
		}
		out = append(out, s)
	}
	for i := range out {
		switch out[i].name {
		case "date", "clock":
			out[i].name = "time"
		case "word":
			out[i].name = "value"
		}
	}
	return out
}

// render writes segments as a pattern, naming IPs src/dst in order, making
// names unique, and using \S+ where a placeholder is followed directly by
// another so the boundary is unambiguous.
func render(segs []segment, trailing bool) string {
	var flat []segment // parts with word boundaries marked by a lit " "
	for i, s := range segs {
		if i > 0 {
			flat = append(flat, segment{lit: " "})
		}
		if s.parts != nil {
			flat = append(flat, s.parts...)
		} else {
			flat = append(flat, s)
		}
	}
	ips, ports, used := 0, 0, map[string]int{}
	for i := range flat {
		switch flat[i].name {
		case "ip":
			flat[i].name = []string{"src_ip", "dst_ip"}[min(ips, 1)]
			ips++
		case "port":
			flat[i].name = []string{"src_port", "dst_port"}[min(ports, 1)]
			ports++
		}
		if flat[i].name == "word" {
			flat[i].name = "value"
		}
		if n := flat[i].name; n != "" {
			used[n]++
			if used[n] > 1 {
				flat[i].name = fmt.Sprintf("%s%d", n, used[n])
			}
		}
	}
	var sb strings.Builder
	for i, s := range flat {
		if s.name == "" {
			sb.WriteString(braces.Replace(s.lit))
			continue
		}
		next := func(k int) *segment {
			if k < len(flat) {
				return &flat[k]
			}
			return nil
		}
		re := s.regex
		if re == "" && !s.multi {
			// Followed by a placeholder (directly or after a space), or by the
			// optional trailing text: match one word.
			n1, n2 := next(i+1), next(i+2)
			if (n1 != nil && n1.name != "") || (n1 != nil && n1.lit == " " && n2 != nil && n2.name != "") || (n1 == nil && trailing) {
				re = `\S+`
			}
		}
		if re != "" {
			fmt.Fprintf(&sb, "{%s:%s}", s.name, re)
		} else {
			fmt.Fprintf(&sb, "{%s}", s.name)
		}
	}
	if trailing {
		sb.WriteString(`{details:(?:\s.*)?}`)
	}
	return sb.String()
}
