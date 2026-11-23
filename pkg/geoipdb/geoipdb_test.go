package geoipdb

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"siemlite/pkg/enrich"
)

var testNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// mmdbBytes builds a tiny database with one network, 8.8.8.0/24.
func mmdbBytes(t *testing.T, dbType string, rec mmdbtype.Map, epoch time.Time) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, BuildEpoch: epoch.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	_, n, _ := net.ParseCIDR("8.8.8.0/24")
	if err := tree.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := tree.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func cityDB(t *testing.T) []byte {
	return mmdbBytes(t, "DBIP-City-Lite", mmdbtype.Map{
		"city":      mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Mountain View")}},
		"country":   mmdbtype.Map{"iso_code": mmdbtype.String("US")},
		"continent": mmdbtype.Map{"code": mmdbtype.String("NA")},
		"location":  mmdbtype.Map{"latitude": mmdbtype.Float64(37.4), "longitude": mmdbtype.Float64(-122.1)},
	}, testNow.AddDate(0, 0, -20))
}

func asnDB(t *testing.T) []byte {
	return mmdbBytes(t, "DBIP-ASN-Lite", mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(15169),
		"autonomous_system_organization": mmdbtype.String("GOOGLE"),
	}, testNow.AddDate(0, 0, -20))
}

func gz(t *testing.T, b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return def, nil
}
func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

type swaps struct {
	mu        sync.Mutex
	city, asn string
	n         int
}

func (s *swaps) Swap(c, a string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.city, s.asn = c, a
	s.n++
	return nil
}
func (s *swaps) get() (string, string) { s.mu.Lock(); defer s.mu.Unlock(); return s.city, s.asn }

// fake serves files by path and records the requests.
type fake struct {
	mu    sync.Mutex
	files map[string][]byte // "/free/dbip-city-lite-2026-11.mmdb.gz" -> body
	reqs  []string
	srv   *httptest.Server
}

func newFake(t *testing.T, files map[string][]byte) *fake {
	f := &fake{files: files}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.URL.Path)
		body, ok := f.files[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }

func newSvc(t *testing.T, f *fake) (*Service, *swaps, *memStore) {
	ap, st := &swaps{}, &memStore{}
	return &Service{Dir: filepath.Join(t.TempDir(), "geoip"), Store: st, Target: ap, Base: f.srv.URL + "/free/", Client: f.srv.Client(),
		Now: func() time.Time { return testNow }}, ap, st
}

func names(t *testing.T, dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestEditionFallsBackToPreviousMonth(t *testing.T) {
	f := newFake(t, map[string][]byte{}) // filled below
	f.files["/free/dbip-city-lite-2026-10.mmdb.gz"] = gz(t, cityDB(t))
	f.files["/free/dbip-asn-lite-2026-10.mmdb.gz"] = gz(t, asnDB(t))
	s, ap, st := newSvc(t, f)
	got := s.Check(context.Background())
	if got.LastError != "" || got.Source != "dbip" || got.City.Edition != "2026-10" || got.ASN.Edition != "2026-10" || got.City.Built == "" || got.LastChecked == 0 {
		t.Fatalf("status = %+v", got)
	}
	want := []string{"/free/dbip-city-lite-2026-11.mmdb.gz", "/free/dbip-city-lite-2026-10.mmdb.gz", "/free/dbip-asn-lite-2026-11.mmdb.gz", "/free/dbip-asn-lite-2026-10.mmdb.gz"}
	if strings.Join(f.reqs, " ") != strings.Join(want, " ") {
		t.Errorf("requests = %v", f.reqs)
	}
	if c, a := ap.get(); filepath.Base(c) != "dbip-city-lite-2026-10.mmdb" || filepath.Base(a) != "dbip-asn-lite-2026-10.mmdb" {
		t.Errorf("loaded %q %q", c, a)
	}
	if n := names(t, s.Dir); len(n) != 2 {
		t.Errorf("files = %v", n)
	}
	if st.m[SettingState] == "" {
		t.Error("state not saved")
	}

	// Already have the newest there can be: nothing is requested.
	before := f.count()
	s.Check(context.Background())
	if f.count() != before+2 { // this month's only (it is still missing); last month's is what we have
		t.Errorf("requests after a second check = %d, want %d", f.count(), before+2)
	}
}

func TestSkipsWhenCurrentMonthHave(t *testing.T) {
	f := newFake(t, map[string][]byte{
		"/free/dbip-city-lite-2026-11.mmdb.gz": gz(t, cityDB(t)),
		"/free/dbip-asn-lite-2026-11.mmdb.gz":  gz(t, asnDB(t)),
	})
	s, _, _ := newSvc(t, f)
	s.Check(context.Background())
	if f.count() != 2 {
		t.Fatalf("first check made %d requests", f.count())
	}
	s.Check(context.Background())
	if f.count() != 2 {
		t.Errorf("second check downloaded again: %v", f.reqs)
	}
	// A restart (fresh service, same folder) knows what is on disk too.
	s2 := &Service{Dir: s.Dir, Store: s.Store, Target: &swaps{}, Base: s.Base, Client: s.Client, Now: s.Now}
	s2.Load(context.Background())
	if st := s2.Status(context.Background()); st.City.Edition != "2026-11" || st.Source != "dbip" {
		t.Errorf("after restart: %+v", st)
	}
	s2.Check(context.Background())
	if f.count() != 2 {
		t.Errorf("a restart downloaded again: %v", f.reqs)
	}
}

func TestNewerEditionReplacesAndCleansUp(t *testing.T) {
	f := newFake(t, map[string][]byte{
		"/free/dbip-city-lite-2026-10.mmdb.gz": gz(t, cityDB(t)),
		"/free/dbip-asn-lite-2026-10.mmdb.gz":  gz(t, asnDB(t)),
	})
	s, ap, _ := newSvc(t, f)
	s.Check(context.Background())
	os.WriteFile(filepath.Join(s.Dir, "dbip-city-lite-2026-08.mmdb"), []byte("old"), 0o600)
	os.WriteFile(filepath.Join(s.Dir, "notes.txt"), []byte("mine"), 0o600)

	f.mu.Lock()
	f.files["/free/dbip-city-lite-2026-11.mmdb.gz"] = gz(t, cityDB(t))
	f.mu.Unlock()
	st := s.Check(context.Background())
	if st.City.Edition != "2026-11" || st.ASN.Edition != "2026-10" || st.LastError != "" {
		t.Fatalf("status = %+v", st)
	}
	if c, _ := ap.get(); filepath.Base(c) != "dbip-city-lite-2026-11.mmdb" {
		t.Errorf("loaded %q", c)
	}
	got := strings.Join(names(t, s.Dir), " ")
	if got != "dbip-asn-lite-2026-10.mmdb dbip-city-lite-2026-11.mmdb notes.txt" {
		t.Errorf("files = %s", got)
	}
}

func TestBadDownloadsKeepThePreviousDatabase(t *testing.T) {
	good := map[string][]byte{
		"/free/dbip-city-lite-2026-10.mmdb.gz": gz(t, cityDB(t)),
		"/free/dbip-asn-lite-2026-10.mmdb.gz":  gz(t, asnDB(t)),
	}
	f := newFake(t, good)
	s, ap, _ := newSvc(t, f)
	s.Check(context.Background())
	city0, asn0 := ap.get()
	before, _ := os.ReadFile(city0)

	bomb := gz(t, make([]byte, 3<<20)) // 3 MiB of zeros in a few KiB
	cases := map[string][]byte{
		"corrupt gzip":       []byte("this is not gzip at all"),
		"truncated gzip":     gz(t, cityDB(t))[:40],
		"not an mmdb":        gz(t, []byte("hello, I am not a database")),
		"wrong kind":         gz(t, asnDB(t)), // an ASN database served as the City one
		"too large to unzip": bomb,
		"old build date":     gz(t, mmdbBytes(t, "DBIP-City-Lite", mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("US")}}, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))),
	}
	s.MaxDecompressed = 1 << 20
	for name, body := range cases {
		f.mu.Lock()
		f.files["/free/dbip-city-lite-2026-11.mmdb.gz"] = body
		f.mu.Unlock()
		st := s.Check(context.Background())
		if st.LastError == "" || !strings.Contains(st.LastError, "City") {
			t.Errorf("%s: no error: %+v", name, st)
		}
		if c, a := ap.get(); c != city0 || a != asn0 {
			t.Errorf("%s: loaded databases changed to %q %q", name, c, a)
		}
		if got, _ := os.ReadFile(city0); !bytes.Equal(got, before) {
			t.Errorf("%s: the stored database changed", name)
		}
		if n := names(t, s.Dir); len(n) != 2 {
			t.Errorf("%s: files left: %v", name, n)
		}
		if st.City.Edition != "2026-10" {
			t.Errorf("%s: edition = %q", name, st.City.Edition)
		}
	}
	// The other database was still checked each time, and a server error is reported too.
	f.mu.Lock()
	delete(f.files, "/free/dbip-city-lite-2026-11.mmdb.gz")
	f.mu.Unlock()
	if st := s.Check(context.Background()); st.LastError != "" {
		t.Errorf("a clean check kept an error: %q", st.LastError)
	}
}

func TestCompressedSizeCap(t *testing.T) {
	f := newFake(t, map[string][]byte{"/free/dbip-asn-lite-2026-11.mmdb.gz": gz(t, asnDB(t))})
	s, ap, _ := newSvc(t, f)
	s.MaxCompressed = 50 // far smaller than the file
	st := s.Check(context.Background())
	if st.LastError == "" || st.Source != "none" {
		t.Errorf("status = %+v", st)
	}
	if c, a := ap.get(); c != "" || a != "" {
		t.Errorf("loaded %q %q", c, a)
	}
	if n := names(t, s.Dir); len(n) != 0 {
		t.Errorf("files left: %v", n)
	}
}

func TestServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }))
	defer srv.Close()
	s := &Service{Dir: filepath.Join(t.TempDir(), "g"), Store: &memStore{}, Target: &swaps{}, Base: srv.URL, Client: srv.Client(), Now: func() time.Time { return testNow }}
	st := s.Check(context.Background())
	if !strings.Contains(st.LastError, "500") {
		t.Errorf("error = %q", st.LastError)
	}
}

func TestRedirectsToOtherHostsRefused(t *testing.T) {
	other := newFake(t, map[string][]byte{
		"/free/dbip-asn-lite-2026-11.mmdb.gz":  gz(t, asnDB(t)),
		"/free/dbip-city-lite-2026-11.mmdb.gz": gz(t, cityDB(t)),
	})
	for name, target := range map[string]string{"other host": other.srv.URL, "plain http": "http://" + strings.TrimPrefix(other.srv.URL, "https://")} {
		front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target+r.URL.Path, http.StatusFound)
		}))
		ap := &swaps{}
		s := &Service{Dir: filepath.Join(t.TempDir(), "g"), Store: &memStore{}, Target: ap, Base: front.URL + "/free/", Client: front.Client(), Now: func() time.Time { return testNow }}
		st := s.Check(context.Background())
		front.Close()
		if !strings.Contains(st.LastError, "redirect") || st.Source != "none" {
			t.Errorf("%s: status = %+v", name, st)
		}
	}
	if other.count() != 0 {
		t.Errorf("the other host was reached: %v", other.reqs)
	}
}

func TestOwnFilesWin(t *testing.T) {
	f := newFake(t, map[string][]byte{"/free/dbip-asn-lite-2026-11.mmdb.gz": gz(t, asnDB(t))})
	s, ap, _ := newSvc(t, f)
	s.Own = true
	s.Load(context.Background())
	st := s.Check(context.Background())
	if st.Source != "own" || f.count() != 0 || ap.n != 0 {
		t.Errorf("status %+v, requests %v, swaps %d", st, f.reqs, ap.n)
	}
	if err := s.SetEnabled(context.Background(), true); err != nil || ap.n != 0 {
		t.Errorf("enabling changed things: %v %d", err, ap.n)
	}
}

func TestDisableAndEnable(t *testing.T) {
	f := newFake(t, map[string][]byte{
		"/free/dbip-city-lite-2026-11.mmdb.gz": gz(t, cityDB(t)),
		"/free/dbip-asn-lite-2026-11.mmdb.gz":  gz(t, asnDB(t)),
	})
	s, ap, _ := newSvc(t, f)
	ctx := context.Background()
	if !s.Status(ctx).Enabled {
		t.Fatal("should be on by default")
	}
	s.Check(ctx)
	if err := s.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if c, a := ap.get(); c != "" || a != "" {
		t.Errorf("still loaded %q %q", c, a)
	}
	n := f.count()
	if st := s.Check(ctx); st.Enabled || st.Source != "none" || f.count() != n {
		t.Errorf("a disabled check did something: %+v", st)
	}
	if err := s.SetEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c, a := ap.get(); c == "" || a == "" {
		t.Errorf("not reloaded from disk: %q %q", c, a)
	}
	if f.count() != n {
		t.Error("re-enabling downloaded again")
	}
}

func TestHotSwapIntoGeoIP(t *testing.T) {
	f := newFake(t, map[string][]byte{
		"/free/dbip-city-lite-2026-11.mmdb.gz": gz(t, cityDB(t)),
		"/free/dbip-asn-lite-2026-11.mmdb.gz":  gz(t, asnDB(t)),
	})
	s, _, _ := newSvc(t, f)
	g, err := enrich.OpenGeoIP("", "", nil) // starts with no database
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	s.Target = g
	if g.Lookup("8.8.8.8") != nil {
		t.Fatal("found something before any database")
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // lookups run throughout, as events do
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					g.Lookup("8.8.8.8")
				}
			}
		}()
	}
	s.Check(context.Background())
	close(stop)
	wg.Wait()
	e := g.Lookup("8.8.8.8")
	if e == nil || e.Country() != "US" || e.ASN() != 15169 {
		t.Fatalf("lookup after the download = %+v", e)
	}
	// And a newer edition swaps in again.
	f.mu.Lock()
	s.Now = func() time.Time { return testNow.AddDate(0, 1, 0) }
	f.files["/free/dbip-city-lite-2026-12.mmdb.gz"] = gz(t, cityDB(t))
	f.mu.Unlock()
	s.Check(context.Background())
	if e := g.Lookup("8.8.8.8"); e == nil || e.Country() != "US" {
		t.Errorf("after the second edition: %+v", e)
	}
}

func TestLoadDoesNotBlock(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	s := &Service{Dir: filepath.Join(t.TempDir(), "g"), Store: &memStore{}, Target: &swaps{}, Base: srv.URL, Client: srv.Client()}
	start := time.Now()
	s.Load(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Status)
	go func() { done <- s.Check(ctx) }()
	if time.Since(start) > time.Second {
		t.Fatal("startup waited for the network")
	}
	time.Sleep(100 * time.Millisecond)
	if !s.Status(context.Background()).Checking {
		t.Error("not reported as checking")
	}
	cancel() // shutting down ends the download
	select {
	case st := <-done:
		if st.LastError == "" {
			t.Error("a cancelled check reported no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Check ignored cancellation")
	}
}

func TestPlainHTTPBaseRefused(t *testing.T) {
	s := &Service{Dir: t.TempDir(), Store: &memStore{}, Target: &swaps{}, Base: "http://download.db-ip.com/free/"}
	if st := s.Check(context.Background()); !strings.Contains(st.LastError, "https") {
		t.Errorf("error = %q", st.LastError)
	}
}

func TestLoadIgnoresBrokenFilesOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "geoip")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "dbip-city-lite-2026-11.mmdb"), []byte("garbage"), 0o600)
	os.WriteFile(filepath.Join(dir, "dbip-city-lite-2026-10.mmdb"), cityDB(t), 0o600)
	os.WriteFile(filepath.Join(dir, ".dbip-city-123.tmp"), []byte("half"), 0o600)
	ap := &swaps{}
	s := &Service{Dir: dir, Store: &memStore{}, Target: ap, Now: func() time.Time { return testNow }}
	s.Load(context.Background())
	if st := s.Status(context.Background()); st.City.Edition != "2026-10" {
		t.Errorf("status = %+v", st)
	}
	if n := names(t, dir); strings.Contains(strings.Join(n, " "), ".tmp") {
		t.Errorf("temp file left: %v", n)
	}
}

func TestParseName(t *testing.T) {
	for in, want := range map[string]string{
		"dbip-city-lite-2026-11.mmdb": "city 2026-11", "dbip-asn-lite-2025-01.mmdb": "asn 2025-01",
		"dbip-city-lite-2026-13.mmdb": "", "dbip-city-lite-2026-11.mmdb.gz": "", "../dbip-city-lite-2026-11.mmdb": "", "": "",
		"dbip-country-lite-2026-11.mmdb": "",
	} {
		k, ed, ok := ParseName(in)
		got := ""
		if ok {
			got = string(k) + " " + ed
		}
		if got != want {
			t.Errorf("ParseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzParseName(f *testing.F) {
	for _, s := range []string{"dbip-city-lite-2026-11.mmdb", "dbip-asn-lite-2025-01.mmdb", "", "dbip-", "dbip-city-lite-0000-00.mmdb", "x/../dbip-asn-lite-2026-11.mmdb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		k, ed, ok := ParseName(name)
		if !ok {
			return
		}
		if FileName(k, ed) != name {
			t.Fatalf("%q parsed to %s %s, which is %q", name, k, ed, FileName(k, ed))
		}
		if strings.ContainsAny(name, "/\\") {
			t.Fatalf("%q accepted with a path separator", name)
		}
	})
}

// TestRealDownload fetches the real ASN edition from download.db-ip.com. It needs the network, so it
// only runs with SIEMLITE_REAL_GEOIP=1 (SIEMLITE_REAL_GEOIP=all adds the larger City database).
func TestRealDownload(t *testing.T) {
	mode := os.Getenv("SIEMLITE_REAL_GEOIP")
	if mode == "" {
		t.Skip("set SIEMLITE_REAL_GEOIP=1 to download from the real server")
	}
	g, _ := enrich.OpenGeoIP("", "", nil)
	defer g.Close()
	s := &Service{Dir: filepath.Join(t.TempDir(), "geoip"), Store: &memStore{}, Target: g}
	s.info, s.paths = map[Kind]DBInfo{}, map[Kind]string{}
	for _, k := range kinds {
		if k == City && mode != "all" {
			continue
		}
		start := time.Now()
		ok, err := s.checkOne(context.Background(), k)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", k, ok, err)
		}
		fi, _ := os.Stat(s.paths[k])
		t.Logf("%s: edition %s, %d bytes unpacked, %v", k, s.info[k].Edition, fi.Size(), time.Since(start).Round(time.Millisecond))
	}
	if e := g.Lookup("8.8.8.8"); e == nil || e.ASN() != 15169 {
		t.Errorf("lookup = %+v", e)
	}
}
