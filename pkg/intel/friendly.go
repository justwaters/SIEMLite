package intel

import (
	"net/netip"
	"strings"
)

// Limits on friendly lists.
const (
	MaxFriendlyLists   = 50
	MaxFriendlyEntries = 5000 // in one list
	MaxFriendlyAdd     = 1000 // in one request
)

// ParseFriendly reads addresses and ranges from text, separated by newlines,
// spaces, commas or semicolons, with # starting a comment to the end of a
// line. Addresses come back normalized (a single-address range is an
// address, a range has its host bits cleared) and without repeats; what
// couldn't be read comes back in bad.
func ParseFriendly(text string) (values, bad []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' }) {
			v, ok := normalizeFriendly(tok)
			if !ok {
				bad = append(bad, tok)
				continue
			}
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	return values, bad
}

func normalizeFriendly(tok string) (string, bool) {
	if p, err := netip.ParsePrefix(tok); err == nil {
		bits := p.Bits()
		if p.Addr().Is4In6() {
			if bits < 96 {
				return "", false // a range that wide, written as IPv4-mapped, is not something anyone means
			}
			bits -= 96
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits).Masked()
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), true
		}
		return p.String(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil && a.Zone() == "" {
		return a.Unmap().String(), true
	}
	return "", false
}
