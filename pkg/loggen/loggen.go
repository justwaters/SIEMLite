// Package loggen makes realistic, random test logs for a small fictional
// company: its firewall, web servers, SSH bastion, VPN, DNS, database, mail
// and endpoint antivirus, with attacks mixed in (SSH brute force, port scans,
// malware, password spraying against the VPN) so alert rules have something
// to find.
//
// Lines are pipe-separated, in a layout of their own (not syslog, JSON or
// key=value), so a SIEM needs a parser to read them:
//
//	time|host|app|level|action|src_ip|src_port|dst_ip|dst_port|user|message
//	2026-10-04T13:42:07.123Z|bastion-01|sshd|warning|auth.failure|203.0.113.7|51234|10.0.4.12|22|root|Failed password for root from 203.0.113.7
//
// A field with no value is "-". Times are UTC (RFC 3339 with milliseconds).
// Addresses outside the company are from the documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so nothing here points at
// a real network.
//
// Only the standard library is used, so the package (and cmd/loggen) can be
// copied into other projects.
package loggen

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"
)

// Header names the fields of every line, in order.
const Header = "time|host|app|level|action|src_ip|src_port|dst_ip|dst_port|user|message"

// Generator makes lines. It is not safe for concurrent use; give each
// goroutine its own (with a different seed).
type Generator struct {
	rng      *rand.Rand
	queue    [][]byte // scenario lines waiting to go out
	nextPlan int      // lines until the next attack scenario starts
	buf      []byte
}

// New returns a generator. The same seed gives the same lines (apart from
// their times).
func New(seed uint64) *Generator {
	g := &Generator{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	g.nextPlan = 20 // the first attack comes early, so a short run shows one
	return g
}

var (
	users     = []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"}
	services  = []string{"svc-backup", "svc-deploy", "svc-monitor"}
	webPaths  = []string{"/", "/login", "/cart", "/checkout", "/api/orders", "/api/products", "/search?q=boots", "/static/app.js", "/static/site.css", "/account"}
	agents    = []string{"Mozilla/5.0", "curl/8.5", "Go-http-client/1.1", "python-requests/2.32"}
	domains   = []string{"updates.example.com", "mail.example.net", "cdn.example.org", "api.example.com", "time.example.net", "intranet.example"}
	malware   = []string{"Trojan.GenericKD", "Ransom.Lockbit", "Backdoor.Cobalt", "Coinminer.XMRig", "PUA.Toolbar"}
	scanPorts = []int{21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443}
)

func (g *Generator) pick(xs []string) string { return xs[g.rng.IntN(len(xs))] }

func (g *Generator) internal() string {
	return fmt.Sprintf("10.0.%d.%d", 1+g.rng.IntN(8), 2+g.rng.IntN(250))
}

func (g *Generator) external() string {
	nets := []string{"192.0.2.", "198.51.100.", "203.0.113."}
	return nets[g.rng.IntN(3)] + strconv.Itoa(1+g.rng.IntN(254))
}

func (g *Generator) port() int { return 1024 + g.rng.IntN(64000) }

// line builds one line; port 0 and "" are written as "-".
func (g *Generator) line(at time.Time, host, app, level, action, src string, sport int, dst string, dport int, user, msg string) []byte {
	b := g.buf[:0]
	b = at.UTC().AppendFormat(b, "2006-01-02T15:04:05.000Z07:00")
	field := func(s string) {
		b = append(b, '|')
		if s == "" {
			s = "-"
		}
		b = append(b, s...)
	}
	num := func(n int) {
		b = append(b, '|')
		if n == 0 {
			b = append(b, '-')
		} else {
			b = strconv.AppendInt(b, int64(n), 10)
		}
	}
	field(host)
	field(app)
	field(level)
	field(action)
	field(src)
	num(sport)
	field(dst)
	num(dport)
	field(user)
	field(msg)
	g.buf = b
	return append([]byte(nil), b...)
}

// Next returns the next line (without a newline), timed at.
func (g *Generator) Next(at time.Time) []byte {
	if len(g.queue) > 0 {
		l := g.queue[0]
		g.queue = g.queue[1:]
		// Scenario lines carry their own relative order; stamp them now.
		return append(at.UTC().AppendFormat(nil, "2006-01-02T15:04:05.000Z07:00"), l...)
	}
	g.nextPlan--
	if g.nextPlan <= 0 {
		g.plan()
		g.nextPlan = 150 + g.rng.IntN(250)
		return g.Next(at)
	}
	return g.background(at)
}

// background is ordinary traffic.
func (g *Generator) background(at time.Time) []byte {
	switch n := g.rng.IntN(100); {
	case n < 30: // web
		client := g.external()
		if g.rng.IntN(4) == 0 {
			client = g.internal()
		}
		status := []int{200, 200, 200, 200, 200, 304, 301, 404, 403, 500}[g.rng.IntN(10)]
		level := "info"
		switch {
		case status >= 500:
			level = "error"
		case status >= 400:
			level = "notice"
		}
		method := "GET"
		path := g.pick(webPaths)
		if path == "/login" || path == "/checkout" || path == "/api/orders" {
			method = "POST"
		}
		user := ""
		if path == "/account" || path == "/checkout" {
			user = g.pick(users)
		}
		host := []string{"web-01", "web-02"}[g.rng.IntN(2)]
		return g.line(at, host, "nginx", level, "http.request", client, g.port(), "10.0.2.10", 443, user,
			fmt.Sprintf("%s %s %d %db %dms %q", method, path, status, 200+g.rng.IntN(40000), 2+g.rng.IntN(400), g.pick(agents)))
	case n < 55: // firewall
		src, dst, dport := g.internal(), g.external(), []int{443, 443, 443, 80, 53, 123, 25}[g.rng.IntN(7)]
		action, level, verb := "allow", "info", "Allowed"
		if g.rng.IntN(6) == 0 {
			src, dst, dport = g.external(), "10.0.0.1", scanPorts[g.rng.IntN(len(scanPorts))]
			action, level, verb = "deny", "notice", "Blocked"
		}
		proto := "TCP"
		if dport == 53 || dport == 123 {
			proto = "UDP"
		}
		return g.line(at, "gw-edge-01", "firewall", level, action, src, g.port(), dst, dport, "",
			fmt.Sprintf("%s %s %s -> %s:%d", verb, proto, src, dst, dport))
	case n < 67: // dns
		client := g.internal()
		return g.line(at, "dns-01", "named", "info", "dns.query", client, g.port(), "10.0.0.53", 53, "",
			fmt.Sprintf("query %s A from %s", g.pick(domains), client))
	case n < 77: // ssh, mostly people and services that belong there
		user, src := g.pick(append(users[:4:4], services...)), g.internal()
		if g.rng.IntN(10) == 0 {
			return g.line(at, "bastion-01", "sshd", "warning", "auth.failure", src, g.port(), "10.0.4.12", 22, user,
				"Failed password for "+user+" from "+src)
		}
		return g.line(at, "bastion-01", "sshd", "info", "auth.success", src, g.port(), "10.0.4.12", 22, user,
			"Accepted publickey for "+user+" from "+src)
	case n < 84: // vpn
		user, src := g.pick(users), g.external()
		if g.rng.IntN(12) == 0 {
			return g.line(at, "vpn-01", "openvpn", "warning", "vpn.login.failure", src, g.port(), "10.0.0.2", 1194, user,
				"Authentication failed for "+user)
		}
		return g.line(at, "vpn-01", "openvpn", "info", "vpn.login", src, g.port(), "10.0.0.2", 1194, user,
			fmt.Sprintf("%s connected, assigned 10.8.0.%d", user, 2+g.rng.IntN(250)))
	case n < 90: // database
		if g.rng.IntN(5) == 0 {
			return g.line(at, "db-01", "postgres", "warning", "db.slow_query", "10.0.2.10", g.port(), "10.0.3.5", 5432, "shop",
				fmt.Sprintf("duration: %d ms statement: SELECT * FROM orders WHERE customer_id = %d", 1000+g.rng.IntN(9000), g.rng.IntN(90000)))
		}
		return g.line(at, "db-01", "postgres", "info", "db.connect", "10.0.2.10", g.port(), "10.0.3.5", 5432, "shop",
			"connection authorized: user=shop database=shop")
	case n < 95: // mail
		return g.line(at, "mail-01", "postfix", "info", "mail.delivered", g.external(), g.port(), "10.0.5.25", 25, g.pick(users),
			fmt.Sprintf("message delivered to %s@corp.example (%d bytes)", g.pick(users), 2000+g.rng.IntN(90000)))
	case n < 98: // backups and housekeeping
		return g.line(at, "backup-01", "restic", "info", "backup.completed", "", 0, "", 0, "svc-backup",
			fmt.Sprintf("snapshot saved: %d files, %d MiB added", 100+g.rng.IntN(5000), g.rng.IntN(800)))
	default: // endpoint antivirus, mostly quiet
		host := fmt.Sprintf("ws-%03d", 1+g.rng.IntN(60))
		return g.line(at, host, "defender", "info", "av.scan", "", 0, "", 0, g.pick(users),
			"Scheduled scan finished, no threats found")
	}
}

// plan queues an attack: a few lines that belong together, which rules such
// as SSH brute force or a critical event should catch. Their times are
// stamped as they go out.
func (g *Generator) plan() {
	add := func(host, app, level, action, src string, sport int, dst string, dport int, user, msg string) {
		l := g.line(time.Time{}, host, app, level, action, src, sport, dst, dport, user, msg)
		// Drop the placeholder time; Next puts the real one in front.
		for i, c := range l {
			if c == '|' {
				l = l[i:]
				break
			}
		}
		g.queue = append(g.queue, l)
	}
	attacker := g.external()
	switch g.rng.IntN(4) {
	case 0: // SSH brute force, sometimes ending in a login
		for i := 0; i < 12+g.rng.IntN(10); i++ {
			user := []string{"root", "admin", "ubuntu", "oracle", "test"}[g.rng.IntN(5)]
			add("bastion-01", "sshd", "warning", "auth.failure", attacker, g.port(), "10.0.4.12", 22, user,
				"Failed password for "+user+" from "+attacker)
		}
		if g.rng.IntN(3) == 0 {
			add("bastion-01", "sshd", "warning", "auth.success", attacker, g.port(), "10.0.4.12", 22, "admin",
				"Accepted password for admin from "+attacker)
		}
	case 1: // port scan against the edge
		for _, p := range scanPorts {
			add("gw-edge-01", "firewall", "notice", "deny", attacker, g.port(), "10.0.0.1", p, "",
				fmt.Sprintf("Blocked TCP %s -> 10.0.0.1:%d", attacker, p))
		}
	case 2: // malware on a workstation, then it calls home
		host, user := fmt.Sprintf("ws-%03d", 1+g.rng.IntN(60)), g.pick(users)
		name := g.pick(malware)
		add(host, "defender", "critical", "av.detection", "", 0, "", 0, user,
			fmt.Sprintf("Threat detected: %s in C:\\Users\\%s\\Downloads\\invoice.pdf.exe; quarantine failed", name, user))
		for i := 0; i < 3; i++ {
			add("gw-edge-01", "firewall", "warning", "deny", g.internal(), g.port(), attacker, 443, "",
				fmt.Sprintf("Blocked TCP outbound to %s:443 (known command and control)", attacker))
		}
	default: // password spraying against the VPN
		for _, u := range users {
			add("vpn-01", "openvpn", "warning", "vpn.login.failure", attacker, g.port(), "10.0.0.2", 1194, u,
				"Authentication failed for "+u)
		}
	}
}
