// Package intel matches events against threat intel indicators (IP
// addresses, CIDR ranges, domains and file hashes) loaded from feeds or
// imported by hand.
package intel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"siemlite/pkg/storage"
)

// Indicator types.
const (
	TypeIP     = "ip"
	TypeCIDR   = "cidr"
	TypeDomain = "domain"
	TypeHash   = "hash"
)

var (
	domainRe = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	hashRe   = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$`)
)

// Normalize validates value and returns it in canonical form with its type.
// typ may be empty to detect the type. URLs are reduced to their host.
func Normalize(typ, value string) (string, string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.Trim(v, `"'`)
	if v == "" {
		return "", "", errors.New("empty indicator")
	}
	if typ == "" || typ == TypeDomain {
		if host, ok := urlHost(v); ok {
			v = host
		}
	}
	if typ == "" {
		switch {
		case strings.Contains(v, "/"):
			typ = TypeCIDR
		case isIP(v):
			typ = TypeIP
		case hashRe.MatchString(v):
			typ = TypeHash
		default:
			typ = TypeDomain
		}
	}
	switch typ {
	case TypeIP:
		a, err := netip.ParseAddr(v)
		if err != nil {
			return "", "", fmt.Errorf("%q is not an IP address", value)
		}
		return TypeIP, a.Unmap().String(), nil
	case TypeCIDR:
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", "", fmt.Errorf("%q is not a CIDR range", value)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if p.IsSingleIP() {
			return TypeIP, p.Addr().String(), nil
		}
		return TypeCIDR, p.String(), nil
	case TypeDomain:
		v = strings.TrimSuffix(strings.TrimPrefix(v, "*."), ".")
		if !domainRe.MatchString(v) || len(v) > 253 {
			return "", "", fmt.Errorf("%q is not a domain name", value)
		}
		return TypeDomain, v, nil
	case TypeHash:
		if !hashRe.MatchString(v) {
			return "", "", fmt.Errorf("%q is not an MD5, SHA-1 or SHA-256 hash", value)
		}
		return TypeHash, v, nil
	}
	return "", "", fmt.Errorf("unknown indicator type %q (want ip, cidr, domain or hash)", typ)
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// urlHost extracts the host from "scheme://host[:port]/path".
func urlHost(v string) (string, bool) {
	_, rest, ok := strings.Cut(v, "://")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") { // [v6]:port
		if end := strings.Index(rest, "]"); end > 0 {
			return rest[1:end], true
		}
	}
	if h, _, ok := strings.Cut(rest, ":"); ok {
		rest = h
	}
	return rest, rest != ""
}

// ParseFeed reads one indicator per line in the common blocklist formats:
// plain lists, CSV (first column), "1.2.3.0/24 ; comment" (Spamhaus DROP),
// hosts files ("0.0.0.0 evil.example") and URL lists. Blank lines and
// comments (#, ;, //) are skipped, as is a CSV header. typ forces a type;
// empty detects it per line. Lines that are not valid indicators are
// counted in skipped rather than failing the whole feed.
func ParseFeed(r io.Reader, typ, source, description string) (inds []storage.Indicator, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '|'
		})
		if len(fields) == 0 {
			continue
		}
		v := fields[0]
		// hosts-file format: the blocked name is the second field.
		if (v == "0.0.0.0" || v == "127.0.0.1" || v == "::" || v == "::1") && len(fields) > 1 {
			v = fields[1]
		}
		t, norm, err := Normalize(typ, v)
		if err != nil {
			skipped++
			continue
		}
		if key := t + "\x00" + norm; !seen[key] {
			seen[key] = true
			inds = append(inds, storage.Indicator{Type: t, Value: norm, Source: source, Description: description})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, fmt.Errorf("read feed: %w", err)
	}
	return inds, skipped, nil
}
