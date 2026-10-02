package intel

import (
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// maxMatches caps how many indicator hits are recorded per event.
const maxMatches = 10

var (
	textIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	textDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\b`)
	textHash   = regexp.MustCompile(`(?i)\b[a-f0-9]{32,64}\b`)
)

type entry struct {
	typ, value, source, description string
}

// set is an immutable index of indicators.
type set struct {
	ips      map[netip.Addr][]entry
	prefixes map[int]map[netip.Prefix][]entry // keyed by prefix length
	bits     []int                            // prefix lengths present, longest first
	domains  map[string][]entry
	hashes   map[string][]entry
	size     int
}

func newSet(inds []storage.Indicator) *set {
	s := &set{
		ips:      map[netip.Addr][]entry{},
		prefixes: map[int]map[netip.Prefix][]entry{},
		domains:  map[string][]entry{},
		hashes:   map[string][]entry{},
	}
	for _, in := range inds {
		e := entry{in.Type, in.Value, in.Source, in.Description}
		switch in.Type {
		case TypeIP:
			if a, err := netip.ParseAddr(in.Value); err == nil {
				s.ips[a] = append(s.ips[a], e)
				s.size++
			}
		case TypeCIDR:
			if p, err := netip.ParsePrefix(in.Value); err == nil {
				p = p.Masked()
				m := s.prefixes[p.Bits()]
				if m == nil {
					m = map[netip.Prefix][]entry{}
					s.prefixes[p.Bits()] = m
					s.bits = append(s.bits, p.Bits())
				}
				m[p] = append(m[p], e)
				s.size++
			}
		case TypeDomain:
			s.domains[in.Value] = append(s.domains[in.Value], e)
			s.size++
		case TypeHash:
			s.hashes[in.Value] = append(s.hashes[in.Value], e)
			s.size++
		}
	}
	return s
}

// Matcher checks events against the loaded indicators. Load swaps in a new
// set atomically, so matching never blocks on a reload.
type Matcher struct {
	cur atomic.Pointer[set]
}

// NewMatcher returns a matcher with no indicators.
func NewMatcher() *Matcher {
	m := &Matcher{}
	m.cur.Store(newSet(nil))
	return m
}

// Load replaces the indicators.
func (m *Matcher) Load(inds []storage.Indicator) { m.cur.Store(newSet(inds)) }

// Size returns the number of loaded indicators.
func (m *Matcher) Size() int { return m.cur.Load().size }

// Enrich implements enrich.Enricher. It checks the source and destination
// IPs, then IPv4 addresses, domain names and hashes found in the raw log.
func (m *Matcher) Enrich(ev *ocsf.Event, d *enrich.Data) {
	s := m.cur.Load()
	if s.size == 0 {
		return
	}
	seen := map[string]bool{}
	add := func(field, matched string, es []entry) {
		for _, e := range es {
			key := e.source + "\x00" + e.value
			if seen[key] || len(d.ThreatIntel) >= maxMatches {
				continue
			}
			seen[key] = true
			mt := enrich.IntelMatch{Type: e.typ, Value: e.value, Field: field, Source: e.source, Description: e.description}
			if matched != e.value {
				mt.Matched = matched
			}
			d.ThreatIntel = append(d.ThreatIntel, mt)
		}
	}

	checkIP := func(field, ip string) {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return
		}
		a = a.Unmap()
		add(field, a.String(), s.ips[a])
		for _, bits := range s.bits {
			if bits > a.BitLen() {
				continue
			}
			p, err := a.Prefix(bits)
			if err != nil {
				continue
			}
			add(field, a.String(), s.prefixes[bits][p])
		}
	}
	checkIP("src_endpoint.ip", ev.SrcIP())
	checkIP("dst_endpoint.ip", ev.DstIP())

	raw := ev.RawData
	if len(raw) > 64<<10 {
		raw = raw[:64<<10]
	}
	if len(s.ips) > 0 || len(s.bits) > 0 {
		for _, ip := range textIPv4.FindAllString(raw, 20) {
			checkIP("raw_data", ip)
		}
	}
	if len(s.domains) > 0 {
		for _, host := range textDomain.FindAllString(raw, 50) {
			host = strings.ToLower(host)
			// evil.example also matches www.evil.example.
			for h := host; ; {
				add("raw_data", host, s.domains[h])
				i := strings.IndexByte(h, '.')
				if i < 0 || !strings.Contains(h[i+1:], ".") {
					break
				}
				h = h[i+1:]
			}
		}
	}
	if len(s.hashes) > 0 {
		for _, h := range textHash.FindAllString(raw, 20) {
			if n := len(h); n == 32 || n == 40 || n == 64 {
				add("raw_data", strings.ToLower(h), s.hashes[strings.ToLower(h)])
			}
		}
	}
}
