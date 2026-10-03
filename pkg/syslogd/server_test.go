package syslogd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"siemlite/pkg/ocsf"
)

type sink struct {
	mu  sync.Mutex
	evs []*ocsf.Event
}

func (s *sink) submit(_ context.Context, ev *ocsf.Event, _ map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
	return nil
}

func (s *sink) wait(t *testing.T, n int) []*ocsf.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.evs) >= n {
			out := append([]*ocsf.Event(nil), s.evs...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("got %d events, want %d", len(s.evs), n)
	return nil
}

func TestUDPAndTCP(t *testing.T) {
	var got sink
	srv, err := Start(Config{UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0", Submit: got.submit})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	u, err := net.Dial("udp", srv.UDPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(u, "<38>Oct  2 11:58:01 web1 sshd[311]: Failed password for root from 203.0.113.7 port 22 ssh2")
	u.Close()
	evs := got.wait(t, 1)
	if ev := evs[0]; ev.DeviceName() != "web1" || ev.Device.IP != "127.0.0.1" || ev.ProductName() != "sshd" || ev.SrcIP() != "203.0.113.7" {
		t.Errorf("udp event: device=%+v product=%q src=%q", ev.Device, ev.ProductName(), ev.SrcIP())
	}

	c, err := net.Dial("tcp", srv.StreamAddrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	m1 := "<34>1 2026-10-02T11:00:00Z fw01 pf - - - block from 198.51.100.9"
	// Octet-counted, newline-delimited, a line starting with digits, and a
	// final line with no newline.
	fmt.Fprintf(c, "%d %s", len(m1), m1)
	fmt.Fprint(c, "<13>Oct  2 12:00:00 app1 cron[1]: job ran\n")
	fmt.Fprint(c, "2026-10-02 12:00:01 plain line\n")
	fmt.Fprint(c, "last line")
	c.Close()
	evs = got.wait(t, 5)
	want := []string{"pf", "cron", "syslog", "syslog"}
	for i, w := range want {
		if p := evs[i+1].ProductName(); p != w {
			t.Errorf("tcp event %d product = %q, want %q (raw %q)", i, p, w, evs[i+1].RawData)
		}
	}
	if evs[1].RawData != m1 {
		t.Errorf("octet-counted raw = %q", evs[1].RawData)
	}
	if evs[4].RawData != "last line" {
		t.Errorf("final raw = %q", evs[4].RawData)
	}
	if st := srv.Stats(); st.Received != 5 || st.Denied != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestAllowlist(t *testing.T) {
	var got sink
	srv, err := Start(Config{
		UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0", Submit: got.submit,
		Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	u, _ := net.Dial("udp", srv.UDPAddr().String())
	fmt.Fprint(u, "<13>hello")
	u.Close()
	c, _ := net.Dial("tcp", srv.StreamAddrs()[0].String())
	fmt.Fprint(c, "<13>hello\n")
	// The server closes a denied connection without reading.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(make([]byte, 1))
	c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for srv.Stats().Denied < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := srv.Stats(); st.Denied != 2 || st.Received != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestTLS(t *testing.T) {
	// httptest's built-in certificate is enough for a TLS round trip.
	ts := httptest.NewTLSServer(nil)
	cert := ts.TLS.Certificates[0]
	ts.Close()

	var got sink
	srv, err := Start(Config{TLSAddr: "127.0.0.1:0", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Submit: got.submit})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := tls.Dial("tcp", srv.StreamAddrs()[0].String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	msg := "<86>Oct  2 12:00:00 vpn1 sudo: alice : COMMAND=/bin/sh"
	fmt.Fprintf(c, "%d %s", len(msg), msg)
	c.Close()
	if ev := got.wait(t, 1)[0]; ev.RawData != msg || ev.ProductName() != "sudo" {
		t.Errorf("tls event raw=%q product=%q", ev.RawData, ev.ProductName())
	}
}

func TestOversizedLineSkipped(t *testing.T) {
	var got sink
	srv, err := Start(Config{TCPAddr: "127.0.0.1:0", Submit: got.submit})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, _ := net.Dial("tcp", srv.StreamAddrs()[0].String())
	big := make([]byte, MaxMessageSize+100)
	for i := range big {
		big[i] = 'x'
	}
	c.Write(append(big, '\n'))
	fmt.Fprint(c, "<13>after the big one\n")
	c.Close()
	evs := got.wait(t, 1)
	if evs[0].RawData != "<13>after the big one" {
		t.Errorf("raw = %q", evs[0].RawData)
	}
	if srv.Stats().Rejected != 1 {
		t.Errorf("stats = %+v", srv.Stats())
	}
}
