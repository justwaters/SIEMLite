package secaudit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

func networkChecks() []Check {
	return []Check{
		{ID: "net.tls", Category: CatNetwork, Title: "The HTTPS certificate is valid and trusted", Severity: Medium, Run: checkCert},
		{ID: "net.http", Category: CatNetwork, Title: "Plain HTTP is reachable only by the reverse proxy", Severity: High, Run: checkPlainHTTP},
		{ID: "net.syslog", Category: CatNetwork, Title: "Syslog accepts only trusted networks", Severity: High, Run: checkSyslog},
		{ID: "net.ports", Category: CatNetwork, Title: "No unexpected services are listening", Severity: High, Run: checkPorts},
	}
}

func checkCert(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	if c.CertNotAfter.IsZero() {
		return Outcome{Status: Skip, Detail: "The certificate's details aren't available."}
	}
	left := c.CertNotAfter.Sub(e.Now())
	switch {
	case left < 0:
		return Outcome{Status: Fail, Detail: "The HTTPS certificate expired " + c.CertNotAfter.Format("2006-01-02") + "; browsers refuse it.",
			Fix: "On the System page, under HTTPS certificate, switch to Let's Encrypt, or replace the files given by -tls-cert and -tls-key and restart."}
	case left < 14*24*time.Hour:
		return Outcome{Status: Fail, Detail: fmt.Sprintf("The HTTPS certificate expires in %d days.", int(left.Hours()/24)),
			Fix: "Renew it: Let's Encrypt renews itself when it can reach this server on port 443; otherwise replace the certificate files and restart."}
	case left < 30*24*time.Hour:
		return Outcome{Status: Warn, Detail: fmt.Sprintf("The HTTPS certificate expires in %d days.", int(left.Hours()/24)),
			Fix: "Make sure it will renew, or replace it before then."}
	case c.CertSelfSigned && !onlyLocal(c.Addr):
		return Outcome{Status: Warn, Detail: "SIEMLite is reachable from the network with a self-signed certificate, so people learn to click through certificate warnings and can't tell a man-in-the-middle from the real server.",
			Fix: "On the System page, under HTTPS certificate, choose Let's Encrypt and enter this server's domain, or install a certificate from your own CA."}
	case c.CertSelfSigned:
		return Outcome{Status: Pass, Detail: "The certificate is self-signed, but SIEMLite only listens on this machine."}
	}
	return Outcome{Status: Pass, Detail: "The certificate is trusted and valid until " + c.CertNotAfter.Format("2006-01-02") + "."}
}

func checkPlainHTTP(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	switch {
	case c.HTTPAddr == "":
		return Outcome{Status: Pass, Detail: "Plain HTTP is off."}
	case onlyLocal(c.HTTPAddr) && c.TrustedProxies:
		return Outcome{Status: Pass, Detail: "Plain HTTP listens on " + c.HTTPAddr + ", this machine only, for a trusted reverse proxy."}
	case onlyLocal(c.HTTPAddr) && !c.TrustedProxies:
		return Outcome{Status: Warn, Detail: "Plain HTTP listens on " + c.HTTPAddr + " (this machine only) but no reverse proxy is trusted, so every request appears to come from the proxy's address. Sign-in lockouts and the audit log then can't tell people apart.",
			Fix: "Set -trusted-proxies to your reverse proxy's address, or turn -http-addr off if you don't use one."}
	case !c.TrustedProxies:
		return Outcome{Status: Fail, Detail: "Plain HTTP is listening on " + c.HTTPAddr + " with no trusted proxy configured: sign-ins and logs cross the network unencrypted, and every request appears to come from the proxy.",
			Fix: "Set -trusted-proxies to your reverse proxy's address, bind -http-addr to 127.0.0.1 (or a private interface only the proxy can reach), or turn -http-addr off."}
	}
	return Outcome{Status: Warn, Detail: "Plain HTTP listens on " + c.HTTPAddr + ", which other machines can reach, not only the proxy.",
		Fix: "Bind -http-addr to 127.0.0.1 or to an interface only the proxy can reach, and firewall the port to the proxy's address."}
}

func checkSyslog(_ context.Context, e *Env) Outcome {
	c := e.Cfg
	var on []string
	for _, l := range []struct{ name, addr string }{{"UDP", c.SyslogUDP}, {"TCP", c.SyslogTCP}, {"TLS", c.SyslogTLS}} {
		if l.addr != "" {
			on = append(on, l.name+" "+l.addr)
		}
	}
	if len(on) == 0 {
		return Outcome{Status: Pass, Detail: "Syslog is off."}
	}
	var open, wide []string
	for _, s := range c.SyslogAllow {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			a, aerr := netip.ParseAddr(strings.TrimSpace(s))
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		switch {
		case p.Bits() == 0:
			wide = append(wide, s)
		case !slices.ContainsFunc(privateRanges, func(r netip.Prefix) bool { return r.Contains(p.Addr()) && r.Bits() <= p.Bits() }):
			open = append(open, s)
		}
	}
	switch {
	case len(wide) > 0:
		return Outcome{Status: Fail, Detail: "Syslog (" + strings.Join(on, ", ") + ") accepts messages from anywhere (" + strings.Join(wide, ", ") + "). Syslog has no sign-in, so anyone can inject fake events or flood the database.",
			Fix: "Set -syslog-allow to only the networks that send logs, or drop it to use the default private ranges."}
	case len(open) > 0:
		return Outcome{Status: Warn, Detail: "Syslog (" + strings.Join(on, ", ") + ") accepts messages from public networks: " + strings.Join(open, ", ") + ". Syslog has no sign-in.",
			Fix: "Narrow -syslog-allow to the exact addresses of your devices, and prefer syslog over TLS for anything crossing the internet."}
	}
	return Outcome{Status: Pass, Detail: "Syslog (" + strings.Join(on, ", ") + ") only accepts messages from loopback and private networks, or the networks you listed."}
}

// riskyPorts are services that shouldn't face a network without a reason.
var riskyPorts = map[int]string{
	21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "RPC", 139: "NetBIOS", 445: "SMB",
	2375: "Docker API", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}

type listener struct {
	proto string
	addr  netip.Addr
	port  int
}

func (l listener) wildcard() bool { return l.addr.IsUnspecified() }

func checkPorts(_ context.Context, e *Env) Outcome {
	if e.GOOS != "linux" {
		return Outcome{Status: Skip, Detail: "Listening ports are read from /proc, which only Linux has."}
	}
	ls, ok := e.listeners()
	if !ok {
		return Outcome{Status: Skip, Detail: "The list of listening ports couldn't be read."}
	}
	expected := map[int]bool{22: true}
	for _, a := range []string{e.Cfg.Addr, e.Cfg.HTTPAddr, e.Cfg.SyslogUDP, e.Cfg.SyslogTCP, e.Cfg.SyslogTLS} {
		if _, p, err := net.SplitHostPort(a); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				expected[n] = true
			}
		}
	}
	var risky, other []string
	seen := map[string]bool{}
	for _, l := range ls {
		if !l.wildcard() {
			continue
		}
		key := l.proto + strconv.Itoa(l.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		label := fmt.Sprintf("%s/%d", l.proto, l.port)
		switch {
		case riskyPorts[l.port] != "":
			risky = append(risky, label+" ("+riskyPorts[l.port]+")")
		case !expected[l.port]:
			other = append(other, label)
		}
	}
	slices.Sort(risky)
	slices.Sort(other)
	fix := "Find the program with ss -tulpn, stop or reconfigure it to listen on 127.0.0.1, and block the port in the firewall."
	switch {
	case len(risky) > 0:
		d := "Services that are usually kept private are listening on every interface: " + strings.Join(risky, ", ") + "."
		if len(other) > 0 {
			d += " Also listening: " + capList(other, 12) + "."
		}
		return Outcome{Status: Fail, Detail: d, Fix: fix}
	case len(other) > 0:
		return Outcome{Status: Warn, Detail: "Besides SIEMLite and SSH, these ports listen on every interface: " + capList(other, 12) + ". They may be fine, but each is reachable by anything that can reach this server.",
			Fix: fix + " Then use Accept risk for any you meant to expose."}
	}
	return Outcome{Status: Pass, Detail: "Only SIEMLite's own ports (and SSH) listen on every interface."}
}

func capList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" and %d more", len(l)-n)
}

// listeners reads the sockets in the LISTEN state (TCP) or bound (UDP) from
// /proc/net, for the network namespace SIEMLite is in.
func (e *Env) listeners() ([]listener, bool) {
	var out []listener
	read := false
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"},
	} {
		text, err := e.read(f.file)
		if err != nil {
			continue
		}
		read = true
		for i, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if i == 0 || len(fields) < 4 || fields[3] != f.state {
				continue
			}
			addr, port, ok := parseProcAddr(fields[1])
			if ok {
				out = append(out, listener{f.proto, addr, port})
			}
		}
	}
	return out, read
}

// parseProcAddr reads "0100007F:1F90" or the 32-digit IPv6 form. The kernel
// prints each 32-bit word in host (little-endian) order.
func parseProcAddr(s string) (netip.Addr, int, bool) {
	host, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil || (len(host) != 8 && len(host) != 32) {
		return netip.Addr{}, 0, false
	}
	var b []byte
	for i := 0; i < len(host); i += 8 {
		w, err := strconv.ParseUint(host[i:i+8], 16, 32)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap(), int(port), true
}
