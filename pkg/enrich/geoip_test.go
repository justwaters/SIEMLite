package enrich

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"siemlite/pkg/ocsf"
)

func writeMMDB(t *testing.T, dbType, cidr string, rec mmdbtype.Map) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	_, n, _ := net.ParseCIDR(cidr)
	if err := tree.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), dbType+".mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGeoIP(t *testing.T) {
	city := writeMMDB(t, "GeoLite2-City", "8.8.8.0/24", mmdbtype.Map{
		"city":      mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Mountain View")}},
		"country":   mmdbtype.Map{"iso_code": mmdbtype.String("US")},
		"continent": mmdbtype.Map{"code": mmdbtype.String("NA")},
		"location":  mmdbtype.Map{"latitude": mmdbtype.Float64(37.4), "longitude": mmdbtype.Float64(-122.1)},
	})
	asn := writeMMDB(t, "GeoLite2-ASN", "8.8.8.0/24", mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(15169),
		"autonomous_system_organization": mmdbtype.String("GOOGLE"),
	})
	g, err := OpenGeoIP(city, asn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	ev := &ocsf.Event{SrcEndpoint: &ocsf.Endpoint{IP: "10.0.0.5"}, DstEndpoint: &ocsf.Endpoint{IP: "8.8.8.8"}}
	var d Data
	g.Enrich(ev, &d)
	if d.Src != nil {
		t.Errorf("private IP enriched: %+v", d.Src)
	}
	if d.Dst.Country() != "US" || d.Dst.ASN() != 15169 || d.Dst.AutonomousSystem.Name != "GOOGLE" ||
		d.Dst.Location.City != "Mountain View" || d.Dst.Location.Coordinates[0] != -122.1 {
		t.Errorf("dst = %+v / %+v", d.Dst.Location, d.Dst.AutonomousSystem)
	}
	if e := g.Lookup("1.1.1.1"); e != nil {
		t.Errorf("unknown IP enriched: %+v", e)
	}

	// Only an ASN database.
	g2, err := OpenGeoIP("", asn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if e := g2.Lookup("8.8.8.8"); e == nil || e.Location != nil || e.ASN() != 15169 {
		t.Errorf("asn-only lookup = %+v", e)
	}
}
