package search

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"siemlite/pkg/storage"
)

// The search box takes field terms beside words: src_ip=10.0.0.1,10.0.0.2
// (commas mean "any of these") or user="Jonathan Martinez". Terms are separated
// by spaces and all apply, together with the words. A name that isn't one of the
// fields below is an extra field a parser found, such as action=login.
//
//	ip         either address       src_ip, dst_ip   one address
//	user       user name            host             reporting device
//	program    program or product   source           the source's name (or id)
//	severity   1-6 or info, low, medium, high, critical, fatal
//	category   1-6                  country          two-letter code
//	asn        15169 or AS15169     threat           true: only threat intel matches
var termRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.\-]*)=(.*)$`)

// maxTermValues bounds how long one field's list can be.
const maxTermValues = 200

var severityNames = map[string]string{
	"unknown": "0", "info": "1", "informational": "1", "low": "2", "medium": "3", "high": "4", "critical": "5", "fatal": "6",
}

// splitTokens splits s on spaces that are outside double quotes.
func splitTokens(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// splitValues splits a field term's value on commas outside double quotes and
// takes the quotes off.
func splitValues(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("a quote isn't closed")
	}
	out = append(out, strings.TrimSpace(cur.String()))
	kept := out[:0]
	for _, v := range out {
		if v != "" {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("it needs a value")
	}
	if len(kept) > maxTermValues {
		return nil, fmt.Errorf("it has more than %d values", maxTermValues)
	}
	return kept, nil
}

// parseTerms takes the field terms out of a search box's text and returns the
// words that are left (for the full-text search), the conditions, and whether
// only threat intel matches were asked for. Words inside quotes are never read as terms.
func (e *Engine) parseTerms(ctx context.Context, text string) (words string, conds []storage.Cond, threat bool, err error) {
	tokens := splitTokens(text)
	drop := make([]bool, len(tokens))
	isTerm := make([]bool, len(tokens))
	for i, tok := range tokens {
		isTerm[i] = termRe.MatchString(tok)
	}
	for i, tok := range tokens {
		if !isTerm[i] {
			continue
		}
		m := termRe.FindStringSubmatch(tok)
		name, rest := m[1], m[2]
		bad := func(why string) error { return &InvalidQueryError{fmt.Sprintf("%s=: %s", name, why)} }
		key := strings.ToLower(name)
		vals, verr := splitValues(rest)
		if verr != nil {
			return "", nil, false, bad(verr.Error())
		}
		// AND next to a term just joins it to the words; OR and NOT can't apply to a term.
		for _, j := range []int{i - 1, i + 1} {
			if j < 0 || j >= len(tokens) || isTerm[j] {
				continue
			}
			switch tokens[j] {
			case "OR", "NOT":
				return "", nil, false, &InvalidQueryError{fmt.Sprintf("%s=... can't be used with %s: put a space between terms, and they all apply", name, tokens[j])}
			}
		}
		if i > 0 && tokens[i-1] == "AND" && !drop[i-1] {
			drop[i-1] = true
		} else if i+1 < len(tokens) && tokens[i+1] == "AND" {
			drop[i+1] = true
		}
		drop[i] = true

		switch key {
		case "threat":
			switch strings.ToLower(vals[0]) {
			case "true", "1", "yes":
				threat = true
			case "false", "0", "no":
			default:
				return "", nil, false, bad("use true or false")
			}
			continue
		case "ip", "src_ip", "dst_ip", "user", "host", "program", "country", "asn", "severity", "category":
			// checked below
		case "source":
			ids, serr := e.sourceIDs(ctx, vals)
			if serr != nil {
				return "", nil, false, bad(serr.Error())
			}
			conds = append(conds, storage.Cond{Field: "source_id", Values: ids})
			continue
		default:
			if strings.Contains(name, `"`) {
				return "", nil, false, bad("the field name has a quote in it")
			}
			conds = append(conds, storage.Cond{Field: name, Values: vals})
			continue
		}
		norm := make([]string, 0, len(vals))
		for _, v := range vals {
			switch key {
			case "severity":
				if n, ok := severityNames[strings.ToLower(v)]; ok {
					v = n
				} else if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 6 {
					return "", nil, false, bad("use 1-6 or info, low, medium, high, critical, fatal")
				}
			case "category":
				if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 9 {
					return "", nil, false, bad("use a category number such as 3")
				}
			case "asn":
				n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(v), "AS"))
				if err != nil || n <= 0 {
					return "", nil, false, bad("use a number like 15169 or AS15169")
				}
				v = strconv.Itoa(n)
			case "country":
				v = strings.ToUpper(v)
				if len(v) != 2 {
					return "", nil, false, bad("use a two-letter country code such as NL")
				}
			}
			norm = append(norm, v)
		}
		conds = append(conds, storage.Cond{Field: key, Values: norm})
	}
	var rest []string
	for i, tok := range tokens {
		if !drop[i] {
			rest = append(rest, tok)
		}
	}
	return strings.Join(rest, " "), conds, threat, nil
}

// sourceIDs turns source names (or ids) into ids.
func (e *Engine) sourceIDs(ctx context.Context, vals []string) ([]string, error) {
	list, err := e.repo.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range vals {
		found := false
		for _, s := range list {
			if strings.EqualFold(s.Name, v) || strconv.FormatInt(s.ID, 10) == v {
				out = append(out, strconv.FormatInt(s.ID, 10))
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("there is no source called %q", v)
		}
	}
	return out, nil
}
