package api_test

import (
	"bytes"
	"compress/gzip"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"siemlite/api"
	"siemlite/pkg/auth"
	"siemlite/pkg/enrich"
	"siemlite/pkg/geoipdb"
)

func gzMMDB(t *testing.T, dbType string, rec mmdbtype.Map) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, BuildEpoch: time.Now().AddDate(0, 0, -3).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_, n, _ := net.ParseCIDR("8.8.8.0/24")
	if err := tree.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	var raw, out bytes.Buffer
	tree.WriteTo(&raw)
	w := gzip.NewWriter(&out)
	w.Write(raw.Bytes())
	w.Close()
	return out.Bytes()
}

func TestGeoIPSettings(t *testing.T) {
	city := gzMMDB(t, "DBIP-City-Lite", mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("US")}})
	asn := gzMMDB(t, "DBIP-ASN-Lite", mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(15169), "autonomous_system_organization": mmdbtype.String("GOOGLE")})
	dl := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path)[:9] {
		case "dbip-city":
			w.Write(city)
		case "dbip-asn-":
			w.Write(asn)
		default:
			http.NotFound(w, r)
		}
	}))
	defer dl.Close()
	geo, _ := enrich.OpenGeoIP("", "", nil)
	defer geo.Close()
	e := newEnvWith(t, func(d *api.Deps) {
		d.GeoIP = &geoipdb.Service{Dir: filepath.Join(t.TempDir(), "geoip"), Store: d.Repo, Target: geo, Base: dl.URL + "/free/", Client: dl.Client()}
	})
	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root, sam := e.client(), e.client()
	e.login(root, "root", password)
	e.login(sam, "sam", password)

	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/system/geoip", nil, &v, nil); got != 200 || v["enabled"] != true || v["source"] != "none" || v["attribution"] == "" {
		t.Fatalf("get = %d %v", got, v)
	}
	for _, c := range [][2]string{{"GET", "/api/v1/system/geoip"}, {"PUT", "/api/v1/system/geoip"}, {"POST", "/api/v1/system/geoip/check"}} {
		if got := e.call(sam, c[0], c[1], map[string]bool{"enabled": false}, nil, nil); got != 403 {
			t.Errorf("standard user %s = %d", c[0], got)
		}
	}
	// A page for everyone learns where locations come from, via the session.
	var me map[string]any
	if got := e.call(sam, "GET", "/api/v1/me", nil, &me, nil); got != 200 || me["geoip"] != "none" {
		t.Errorf("me = %d %v", got, me)
	}

	if got := e.call(root, "POST", "/api/v1/system/geoip/check", nil, &v, nil); got != 200 || v["source"] != "dbip" || v["last_error"] != "" {
		t.Fatalf("check = %d %v", got, v)
	}
	if c, _ := v["city"].(map[string]any); c["edition"] == "" || c["built"] == "" {
		t.Errorf("city = %v", v["city"])
	}
	if e := geo.Lookup("8.8.8.8"); e == nil || e.ASN() != 15169 {
		t.Errorf("not loaded without a restart: %+v", e)
	}
	if got := e.call(sam, "GET", "/api/v1/me", nil, &me, nil); got != 200 || me["geoip"] != "dbip" {
		t.Errorf("me after the download = %d %v", got, me)
	}

	if got := e.call(root, "PUT", "/api/v1/system/geoip", map[string]any{}, nil, nil); got != 400 {
		t.Errorf("empty put = %d", got)
	}
	if got := e.call(root, "PUT", "/api/v1/system/geoip", map[string]bool{"enabled": false}, &v, nil); got != 200 || v["enabled"] != false || v["source"] != "none" {
		t.Fatalf("turn off = %d %v", got, v)
	}
	if geo.Lookup("8.8.8.8") != nil {
		t.Error("still locating addresses while off")
	}
	if got := e.call(root, "PUT", "/api/v1/system/geoip", map[string]bool{"enabled": true}, &v, nil); got != 200 || v["enabled"] != true || v["source"] != "dbip" {
		t.Fatalf("turn on = %d %v", got, v)
	}
}
