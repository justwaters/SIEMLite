package enrich

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"siemlite/pkg/ocsf"
)

// GeoIP looks up location and autonomous system for public IP addresses in
// MaxMind-format (.mmdb) databases: GeoLite2/GeoIP2 City or Country and ASN,
// or the free DB-IP "lite" equivalents. Either database may be omitted.
type GeoIP struct {
	log *slog.Logger

	mu   sync.RWMutex // held for reading during lookups, so Close never unmaps under one
	city *mmdb
	asn  *mmdb
}

type mmdb struct {
	path    string
	modTime time.Time
	r       *maxminddb.Reader
}

// OpenGeoIP opens the given databases. An empty path skips that database.
func OpenGeoIP(cityPath, asnPath string, log *slog.Logger) (*GeoIP, error) {
	if log == nil {
		log = slog.Default()
	}
	g := &GeoIP{log: log}
	var err error
	if cityPath != "" {
		if g.city, err = openMMDB(cityPath); err != nil {
			return nil, err
		}
	}
	if asnPath != "" {
		if g.asn, err = openMMDB(asnPath); err != nil {
			g.Close()
			return nil, err
		}
	}
	return g, nil
}

func openMMDB(path string) (*mmdb, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &mmdb{path: path, modTime: st.ModTime(), r: r}, nil
}

// Close releases the databases.
func (g *GeoIP) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var errs []error
	for _, db := range []*mmdb{g.city, g.asn} {
		if db != nil {
			errs = append(errs, db.r.Close())
		}
	}
	g.city, g.asn = nil, nil
	return errors.Join(errs...)
}

// Run reopens a database whenever its file changes (e.g. after geoipupdate
// replaces it), checking every interval, until ctx is done.
func (g *GeoIP) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.reloadChanged()
		}
	}
}

func (g *GeoIP) reloadChanged() {
	for _, slot := range []**mmdb{&g.city, &g.asn} {
		g.mu.RLock()
		cur := *slot
		g.mu.RUnlock()
		if cur == nil {
			continue
		}
		st, err := os.Stat(cur.path)
		if err != nil || st.ModTime().Equal(cur.modTime) {
			continue
		}
		next, err := openMMDB(cur.path)
		if err != nil {
			g.log.Warn("geoip reload failed; keeping the loaded database", "path", cur.path, "err", err)
			continue
		}
		g.mu.Lock()
		old := *slot
		*slot = next
		g.mu.Unlock()
		if old != nil {
			old.r.Close()
		}
		g.log.Info("geoip database reloaded", "path", cur.path)
	}
}

type cityRecord struct {
	City struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRecord struct {
	Number       uint   `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
}

// Enrich implements Enricher.
func (g *GeoIP) Enrich(ev *ocsf.Event, d *Data) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if e := g.lookup(ev.SrcIP()); e != nil {
		if d.Src == nil {
			d.Src = &Endpoint{}
		}
		d.Src.Location, d.Src.AutonomousSystem = e.Location, e.AutonomousSystem
	}
	if e := g.lookup(ev.DstIP()); e != nil {
		if d.Dst == nil {
			d.Dst = &Endpoint{}
		}
		d.Dst.Location, d.Dst.AutonomousSystem = e.Location, e.AutonomousSystem
	}
}

// Lookup returns what the databases know about ip, or nil.
func (g *GeoIP) Lookup(ip string) *Endpoint {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lookup(ip)
}

func (g *GeoIP) lookup(ip string) *Endpoint {
	if ip == "" {
		return nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	// Private, loopback, link-local etc. are never in the databases.
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return nil
	}

	var out Endpoint
	if g.city != nil {
		var rec cityRecord
		if res := g.city.r.Lookup(addr); res.Found() && res.Decode(&rec) == nil && rec.Country.ISOCode != "" {
			loc := &Location{City: rec.City.Names.EN, Country: rec.Country.ISOCode, Continent: rec.Continent.Code}
			if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
				loc.Coordinates = []float64{rec.Location.Longitude, rec.Location.Latitude}
			}
			out.Location = loc
		}
	}
	if g.asn != nil {
		var rec asnRecord
		if res := g.asn.r.Lookup(addr); res.Found() && res.Decode(&rec) == nil && rec.Number != 0 {
			out.AutonomousSystem = &AutonomousSystem{Number: int(rec.Number), Name: rec.Organization}
		}
	}
	if out.Location == nil && out.AutonomousSystem == nil {
		return nil
	}
	return &out
}
