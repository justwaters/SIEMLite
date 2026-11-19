package intel

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

type fakeNet map[string]string // url -> body ("" means 500)

func (f fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := f[r.URL.String()]
	code := 200
	if !ok || body == "" {
		code = 500
	}
	return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

// Choosing a feed downloads it; taking it off the list removes its indicators; a feed that fails keeps its error for the card.
func TestThreatFeedsCard(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := storage.NewRepository(db)
	feodo, _ := PresetByID("feodo")
	ipsum, _ := PresetByID("ipsum3")
	net := fakeNet{feodo.URL: "# c2\n203.0.113.7\n198.51.100.9\n", ipsum.URL: ""}
	svc := NewService(repo, Config{HTTPClient: &http.Client{Transport: net}})

	if err := svc.SetFeeds(ctx, []string{"nope"}); err == nil {
		t.Error("an unknown feed was accepted")
	}
	if err := svc.SetFeeds(ctx, []string{"feodo", "ipsum3", "feodo"}); err != nil {
		t.Fatal(err)
	}
	for svc.refreshing.Load() { // SetFeeds started a download in the background
	}
	svc.refreshFeeds(ctx, false)
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	v, _ := svc.Feeds(ctx)
	got := map[string]FeedState{}
	for _, f := range v.Feeds {
		got[f.ID] = f
	}
	if f := got["feodo"]; !f.Selected || f.Indicators != 2 || f.Error != "" {
		t.Errorf("feodo = %+v", f)
	}
	if f := got["ipsum3"]; !f.Selected || f.Indicators != 0 || f.Error == "" {
		t.Errorf("a failing feed should show its error: %+v", f)
	}
	if got["c2intel"].Selected {
		t.Error("an unchosen feed is selected")
	}
	if svc.Matcher.Size() != 2 {
		t.Errorf("matcher has %d indicators, want 2", svc.Matcher.Size())
	}
	// Removing a feed from the list removes its indicators.
	if err := svc.SetFeeds(ctx, []string{"ipsum3"}); err != nil {
		t.Fatal(err)
	}
	srcs, _ := repo.ListIntelSources(ctx)
	for _, s := range srcs {
		if s.Source == feodo.Name {
			t.Error("a feed that was taken off still has indicators")
		}
	}
}

func TestParseFriendly(t *testing.T) {
	got, bad := ParseFriendly("203.0.113.7, 198.51.100.77/24\n# the office\n10.0.0.1/32 ::ffff:192.0.2.9\n2001:db8::/32;203.0.113.7\nnot-an-ip 300.1.1.1")
	want := []string{"203.0.113.7", "198.51.100.0/24", "10.0.0.1", "192.0.2.9", "2001:db8::/32"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("values = %v, want %v", got, want)
	}
	if strings.Join(bad, " ") != "not-an-ip 300.1.1.1" {
		t.Errorf("bad = %v", bad)
	}
}

// A friendly address or range is never flagged, however it is listed; other addresses still are.
func TestFriendlyAddressesAreNotFlagged(t *testing.T) {
	m := NewMatcher()
	m.Load([]storage.Indicator{
		{Type: TypeCIDR, Value: "198.51.100.0/24", Source: "feed"},
		{Type: TypeIP, Value: "203.0.113.7", Source: "feed"},
		{Type: TypeDomain, Value: "evil.example", Source: "feed"},
	}, []string{"198.51.100.0/25", "203.0.113.7"})
	check := func(src, raw string) int {
		ev := &ocsf.Event{RawData: raw}
		if src != "" {
			ev.SrcEndpoint = &ocsf.Endpoint{IP: src}
		}
		var d enrich.Data
		m.Enrich(ev, &d)
		return len(d.ThreatIntel)
	}
	if n := check("198.51.100.5", "x"); n != 0 {
		t.Errorf("an address in a friendly range matched %d", n)
	}
	if n := check("198.51.100.200", "x"); n != 1 {
		t.Errorf("an address outside it matched %d, want 1", n)
	}
	if n := check("203.0.113.7", "from 203.0.113.7"); n != 0 {
		t.Errorf("a friendly address matched %d (also in the raw line)", n)
	}
	if n := check("", "saw 203.0.113.7 and evil.example"); n != 1 {
		t.Errorf("only the domain should match, got %d", n)
	}
}

// Tor exit nodes are labelled, so a match says what kind of address it is.
func TestTorExitFeedIsLabelled(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tor, ok := PresetByID("tor-exit")
	if !ok {
		t.Fatal("no Tor exit preset")
	}
	svc := NewService(storage.NewRepository(db), Config{HTTPClient: &http.Client{Transport: fakeNet{tor.URL: "171.25.193.25\n80.67.167.81\n"}}})
	if err := svc.SetFeeds(ctx, []string{"tor-exit"}); err != nil {
		t.Fatal(err)
	}
	for svc.refreshing.Load() {
	}
	svc.refreshFeeds(ctx, false)
	if err := svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	ev := &ocsf.Event{SrcEndpoint: &ocsf.Endpoint{IP: "171.25.193.25"}}
	var d enrich.Data
	svc.Matcher.Enrich(ev, &d)
	if len(d.ThreatIntel) != 1 || d.ThreatIntel[0].Description != "Tor exit node" || d.ThreatIntel[0].Source != "Tor exit nodes" {
		t.Errorf("match = %+v", d.ThreatIntel)
	}
}

type slowNet struct{ release chan struct{} }

func (n slowNet) RoundTrip(r *http.Request) (*http.Response, error) {
	<-n.release
	return &http.Response{StatusCode: 200, Status: "OK", Body: io.NopCloser(strings.NewReader("203.0.113.7\n")), Header: http.Header{}}, nil
}

// While feeds download, the service says which one and how far along; afterwards it says nothing.
func TestFeedDownloadsReportProgress(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	net := slowNet{release: make(chan struct{})}
	svc := NewService(storage.NewRepository(db), Config{HTTPClient: &http.Client{Transport: net}})
	if err := svc.SetFeeds(ctx, []string{"feodo", "ipsum3"}); err != nil { // starts the downloads in the background
		t.Fatal(err)
	}
	var now string
	var done, total int
	for i := 0; i < 200 && total == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		now, done, total = svc.Activity()
	}
	if total != 2 || done != 0 || now == "" {
		t.Errorf("during the first download: %q %d of %d", now, done, total)
	}
	close(net.release)
	for i := 0; i < 300; i++ {
		if _, _, total = svc.Activity(); total == 0 && !svc.refreshing.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, total := svc.Activity(); total != 0 {
		t.Error("still reporting a download after it finished")
	}
}
