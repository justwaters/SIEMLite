// Package syslogd receives syslog over UDP, TCP and TLS (RFC 5426, 6587 and
// 5425) and feeds each message through the same parser as /api/v1/logs.
//
// Syslog has no authentication, so senders are restricted to an allowlist
// of networks (by default loopback and private ranges).
package syslogd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
)

const (
	// MaxMessageSize is the largest message accepted; longer ones are dropped.
	MaxMessageSize = 64 << 10
	maxConns       = 512
	idleTimeout    = 10 * time.Minute
	udpSubmitWait  = 200 * time.Millisecond
	tcpSubmitWait  = 5 * time.Second
)

// DefaultAllow is the allowlist used when Config.Allow is empty: loopback,
// RFC 1918, CGNAT, IPv6 unique-local and link-local.
var DefaultAllow = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// SubmitFunc queues one event with any extra fields its parser extracted.
type SubmitFunc func(ctx context.Context, ev *ocsf.Event, fields map[string]string) error

// ParseFunc turns one message into an event (nil for blank lines). The
// default is the automatic parser.
type ParseFunc func(ctx context.Context, line string) (*ocsf.Event, map[string]string, error)

// Config selects listeners. An empty address disables that listener.
type Config struct {
	UDPAddr   string
	TCPAddr   string
	TLSAddr   string
	TLSConfig *tls.Config // required with TLSAddr
	Allow     []netip.Prefix
	Parse     ParseFunc
	Submit    SubmitFunc
	Logger    *slog.Logger
}

// Stats counts messages since start.
type Stats struct {
	Received    uint64 `json:"received"`
	Rejected    uint64 `json:"rejected"` // invalid or oversized
	Dropped     uint64 `json:"dropped"`  // ingest queue full
	Denied      uint64 `json:"denied"`   // sender not in the allowlist
	Connections int64  `json:"connections"`
}

// Server is a running set of syslog listeners.
type Server struct {
	cfg Config

	udp       net.PacketConn
	listeners []net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
	slots  chan struct{}

	received, rejected, dropped, denied atomic.Uint64
	active                              atomic.Int64
	lastDenyLog                         atomic.Int64
}

// Start binds the configured listeners and starts serving. It fails without
// leaving anything running if any address cannot be bound.
func Start(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.Allow) == 0 {
		cfg.Allow = DefaultAllow
	}
	if cfg.Submit == nil {
		return nil, errors.New("syslogd: Submit is required")
	}
	if cfg.Parse == nil {
		cfg.Parse = func(_ context.Context, line string) (*ocsf.Event, map[string]string, error) {
			return parser.ParseLine(line, parser.Defaults{}), nil, nil
		}
	}
	s := &Server{cfg: cfg, conns: map[net.Conn]struct{}{}, slots: make(chan struct{}, maxConns)}

	fail := func(err error) (*Server, error) {
		s.Close()
		return nil, err
	}
	if cfg.UDPAddr != "" {
		pc, err := net.ListenPacket("udp", cfg.UDPAddr)
		if err != nil {
			return fail(err)
		}
		s.udp = pc
	}
	if cfg.TCPAddr != "" {
		ln, err := net.Listen("tcp", cfg.TCPAddr)
		if err != nil {
			return fail(err)
		}
		s.listeners = append(s.listeners, ln)
	}
	if cfg.TLSAddr != "" {
		if cfg.TLSConfig == nil {
			return fail(errors.New("syslogd: TLSConfig is required for a TLS listener"))
		}
		ln, err := tls.Listen("tcp", cfg.TLSAddr, cfg.TLSConfig)
		if err != nil {
			return fail(err)
		}
		s.listeners = append(s.listeners, ln)
	}

	if s.udp != nil {
		s.wg.Add(1)
		go s.serveUDP()
	}
	for _, ln := range s.listeners {
		s.wg.Add(1)
		go s.serveStream(ln)
	}
	return s, nil
}

// UDPAddr returns the bound UDP address, or nil.
func (s *Server) UDPAddr() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

// StreamAddrs returns the bound TCP and TLS addresses, in that order.
func (s *Server) StreamAddrs() []net.Addr {
	out := make([]net.Addr, len(s.listeners))
	for i, ln := range s.listeners {
		out[i] = ln.Addr()
	}
	return out
}

// Close stops all listeners, disconnects senders and waits for in-flight
// messages to be submitted.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.udp != nil {
		s.udp.Close()
	}
	for _, ln := range s.listeners {
		ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// Stats returns current counters.
func (s *Server) Stats() Stats {
	return Stats{
		Received:    s.received.Load(),
		Rejected:    s.rejected.Load(),
		Dropped:     s.dropped.Load(),
		Denied:      s.denied.Load(),
		Connections: s.active.Load(),
	}
}

func (s *Server) allowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range s.cfg.Allow {
		if p.Contains(addr) {
			return true
		}
	}
	s.denied.Add(1)
	// Log at most once a minute so a flood cannot fill the log.
	now := time.Now().Unix()
	if last := s.lastDenyLog.Load(); now-last >= 60 && s.lastDenyLog.CompareAndSwap(last, now) {
		s.cfg.Logger.Warn("syslog sender not in allowlist; dropping (see -syslog-allow)", "sender", addr)
	}
	return false
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, MaxMessageSize)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.cfg.Logger.Warn("syslog udp read failed", "err", err)
			continue
		}
		addr, ok := addrOf(from)
		if !ok || !s.allowed(addr) {
			continue
		}
		// One message per datagram (RFC 5426), but tolerate senders that
		// batch several newline-separated lines.
		for _, msg := range bytes.Split(buf[:n], []byte("\n")) {
			s.handle(msg, addr, udpSubmitWait)
		}
	}
}

func (s *Server) serveStream(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.cfg.Logger.Warn("syslog accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		addr, ok := addrOf(conn.RemoteAddr())
		if !ok || !s.allowed(addr) {
			conn.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.cfg.Logger.Warn("syslog connection limit reached; refusing", "sender", addr, "limit", maxConns)
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			<-s.slots
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveConn(conn, addr)
	}
}

func (s *Server) serveConn(conn net.Conn, addr netip.Addr) {
	s.active.Add(1)
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		s.active.Add(-1)
		<-s.slots
		s.wg.Done()
	}()
	r := bufio.NewReaderSize(conn, MaxMessageSize+16)
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		msg, err := readFrame(r)
		if errors.Is(err, errTooLong) {
			s.rejected.Add(1)
			continue
		}
		if err != nil {
			if len(msg) > 0 { // final line without a trailing newline
				s.handle(msg, addr, tcpSubmitWait)
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				var ne net.Error
				if !errors.As(err, &ne) || !ne.Timeout() {
					s.cfg.Logger.Debug("syslog connection ended", "sender", addr, "err", err)
				}
			}
			return
		}
		s.handle(msg, addr, tcpSubmitWait)
	}
}

var errTooLong = errors.New("syslog message too long")

// readFrame reads one message using octet-counting ("LEN SP MSG", RFC 6587
// 3.4.1 and RFC 5425) when the frame starts with a length, otherwise
// newline-delimited framing. Each frame is detected separately, so senders
// may mix them.
func readFrame(r *bufio.Reader) ([]byte, error) {
	for i := 1; i <= 7; i++ {
		b, err := r.Peek(i)
		if err != nil {
			if len(b) == 0 {
				return nil, err
			}
			break
		}
		c := b[i-1]
		if c == ' ' && i > 1 {
			n, _ := strconv.Atoi(string(b[:i-1]))
			if n <= 0 {
				break
			}
			r.Discard(i)
			if n > MaxMessageSize {
				_, err := r.Discard(n)
				if err != nil {
					return nil, err
				}
				return nil, errTooLong
			}
			msg := make([]byte, n)
			if _, err := io.ReadFull(r, msg); err != nil {
				return nil, err
			}
			return msg, nil
		}
		if c < '0' || c > '9' || (i == 1 && c == '0') {
			break
		}
	}

	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// Skip the rest of the oversized line.
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('\n')
		}
		if err != nil {
			return nil, err
		}
		return nil, errTooLong
	}
	return bytes.Clone(line), err
}

// handle parses one message and submits it.
func (s *Server) handle(msg []byte, from netip.Addr, wait time.Duration) {
	msg = bytes.TrimRight(msg, "\r\n\x00")
	if len(bytes.TrimSpace(msg)) == 0 {
		return
	}
	s.received.Add(1)
	if len(msg) > MaxMessageSize {
		s.rejected.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	ev, fields, err := s.cfg.Parse(ctx, string(msg))
	if err != nil {
		s.dropped.Add(1)
		return
	}
	if ev == nil {
		return
	}
	if ev.Metadata.Product == nil {
		ev.Metadata.Product = &ocsf.Product{Name: "syslog"}
	}
	if ev.Device == nil {
		ev.Device = &ocsf.Endpoint{}
	}
	ev.Device.IP = from.Unmap().String()

	err = s.cfg.Submit(ctx, ev, fields)
	var verr *ocsf.ValidationError
	switch {
	case err == nil:
	case errors.As(err, &verr):
		s.rejected.Add(1)
	default:
		s.dropped.Add(1)
	}
}

func addrOf(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		return ap.Addr(), ap.Addr().IsValid()
	case *net.TCPAddr:
		ap := v.AddrPort()
		return ap.Addr(), ap.Addr().IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap.Addr(), err == nil
}
