package email

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a tiny SMTP server that records what it is sent.
type fakeServer struct {
	ln       net.Listener
	cert     tls.Certificate
	implicit bool   // TLS from the first byte
	starttls bool   // offers STARTTLS
	auth     string // "", "PLAIN", "LOGIN" or "PLAIN LOGIN"
	user     string // accepted login
	pass     string
	mu       sync.Mutex
	from     string
	rcpts    []string
	data     string
	loggedIn string // the credentials the client used
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startServer(t *testing.T, f *fakeServer) (host string, port int) {
	t.Helper()
	f.cert = selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if f.implicit {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	rd := bufio.NewReader(c)
	send := func(s string) { c.Write([]byte(s + "\r\n")) }
	line := func() string { l, _ := rd.ReadString('\n'); return strings.TrimRight(l, "\r\n") }
	send("220 fake ESMTP")
	for {
		l := line()
		if l == "" {
			return
		}
		up := strings.ToUpper(l)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			ext := []string{"250-fake"}
			if f.starttls {
				ext = append(ext, "250-STARTTLS")
			}
			if f.auth != "" {
				ext = append(ext, "250-AUTH "+f.auth)
			}
			ext = append(ext, "250 8BITMIME")
			send(strings.Join(ext, "\r\n"))
		case up == "STARTTLS":
			send("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tc.Handshake() != nil {
				return
			}
			c, rd = tc, bufio.NewReader(tc)
			send = func(s string) { tc.Write([]byte(s + "\r\n")) }
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(l[len("AUTH PLAIN"):]))
			parts := strings.Split(string(raw), "\x00")
			f.finishAuth(send, parts[len(parts)-2], parts[len(parts)-1])
		case up == "AUTH LOGIN":
			send("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			u, _ := base64.StdEncoding.DecodeString(line())
			send("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			p, _ := base64.StdEncoding.DecodeString(line())
			f.finishAuth(send, string(u), string(p))
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.Trim(strings.SplitN(l[len("MAIL FROM:"):], ">", 2)[0], "< ")
			f.mu.Unlock()
			send("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			addr := strings.Trim(strings.SplitN(l[len("RCPT TO:"):], ">", 2)[0], "< ")
			if strings.HasPrefix(addr, "refused@") {
				send("550 no such user")
				continue
			}
			f.mu.Lock()
			f.rcpts = append(f.rcpts, addr)
			f.mu.Unlock()
			send("250 ok")
		case up == "DATA":
			send("354 go")
			var b strings.Builder
			for {
				d := line()
				if d == "." {
					break
				}
				b.WriteString(d + "\n")
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			send("250 queued")
		case up == "QUIT":
			send("221 bye")
			return
		default:
			send("250 ok")
		}
	}
}

func (f *fakeServer) finishAuth(send func(string), u, p string) {
	f.mu.Lock()
	f.loggedIn = u + ":" + p
	f.mu.Unlock()
	if u == f.user && p == f.pass {
		send("235 welcome")
	} else {
		send("535 bad credentials")
	}
}

func cfgFor(host string, port int, security string) Config {
	return Config{Host: host, Port: port, Security: security, FromAddress: "siem@example.com", FromName: "SIEM Lite", SkipVerify: true}
}

func TestSendModes(t *testing.T) {
	msg := Message{To: []string{"Ann <ann@example.com>"}, Subject: "Hello", Body: "line one\nline two"}
	for _, tc := range []struct {
		name     string
		srv      *fakeServer
		security string
		user     string
	}{
		{"no encryption, no login", &fakeServer{}, SecurityNone, ""},
		{"STARTTLS with PLAIN login", &fakeServer{starttls: true, auth: "PLAIN", user: "u", pass: "p@ss word"}, SecuritySTARTTLS, "u"},
		{"STARTTLS with LOGIN only", &fakeServer{starttls: true, auth: "LOGIN", user: "u", pass: "p@ss word"}, SecuritySTARTTLS, "u"},
		{"implicit TLS with login", &fakeServer{implicit: true, auth: "PLAIN LOGIN", user: "u", pass: "p@ss word"}, SecurityTLS, "u"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port := startServer(t, tc.srv)
			cfg := cfgFor(host, port, tc.security)
			cfg.Username = tc.user
			if err := Send(context.Background(), cfg, "p@ss word", msg); err != nil {
				t.Fatal(err)
			}
			if tc.srv.from != "siem@example.com" || len(tc.srv.rcpts) != 1 || tc.srv.rcpts[0] != "ann@example.com" {
				t.Errorf("envelope from=%q rcpts=%v", tc.srv.from, tc.srv.rcpts)
			}
			for _, want := range []string{"From: \"SIEM Lite\" <siem@example.com>", "To: \"Ann\" <ann@example.com>", "Subject: Hello",
				"MIME-Version: 1.0", "Content-Type: text/plain; charset=\"utf-8\"", "line one", "line two"} {
				if !strings.Contains(tc.srv.data, want) {
					t.Errorf("message lacks %q:\n%s", want, tc.srv.data)
				}
			}
			if tc.user != "" && tc.srv.loggedIn != "u:p@ss word" {
				t.Errorf("logged in as %q", tc.srv.loggedIn)
			}
		})
	}
}

func TestSendFailures(t *testing.T) {
	msg := Message{To: []string{"ann@example.com"}, Subject: "x", Body: "y"}
	ctx := context.Background()

	// Wrong password.
	f := &fakeServer{starttls: true, auth: "PLAIN", user: "u", pass: "right"}
	host, port := startServer(t, f)
	cfg := cfgFor(host, port, SecuritySTARTTLS)
	cfg.Username = "u"
	if err := Send(ctx, cfg, "wrong", msg); err == nil || !strings.Contains(err.Error(), "rejected the login") {
		t.Errorf("wrong password: %v", err)
	}

	// STARTTLS wanted, not offered.
	f = &fakeServer{}
	host, port = startServer(t, f)
	if err := Send(ctx, cfgFor(host, port, SecuritySTARTTLS), "", msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("no STARTTLS: %v", err)
	}

	// A certificate that doesn't verify, unless that's switched off.
	f = &fakeServer{implicit: true}
	host, port = startServer(t, f)
	strict := cfgFor(host, port, SecurityTLS)
	strict.SkipVerify = false
	if err := Send(ctx, strict, "", msg); err == nil || !strings.Contains(err.Error(), "secure connection") {
		t.Errorf("self-signed cert accepted: %v", err)
	}

	// A refused recipient names the address.
	f = &fakeServer{}
	host, port = startServer(t, f)
	bad := Message{To: []string{"refused@example.com"}, Subject: "x", Body: "y"}
	if err := Send(ctx, cfgFor(host, port, SecurityNone), "", bad); err == nil || !strings.Contains(err.Error(), "refused@example.com") {
		t.Errorf("refused recipient: %v", err)
	}

	// Nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := Send(ctx, cfgFor("127.0.0.1", closed, SecurityNone), "", msg); err == nil || !strings.Contains(err.Error(), "Couldn't connect") {
		t.Errorf("closed port: %v", err)
	}

	// A username with a server that has no login.
	f = &fakeServer{}
	host, port = startServer(t, f)
	cfg = cfgFor(host, port, SecurityNone)
	cfg.Username = "u"
	if err := Send(ctx, cfg, "p", msg); err == nil || !strings.Contains(err.Error(), "doesn't offer a login") {
		t.Errorf("login not offered: %v", err)
	}
}

func TestMessageCannotInjectHeadersOrRecipients(t *testing.T) {
	f := &fakeServer{}
	host, port := startServer(t, f)
	cfg := cfgFor(host, port, SecurityNone)
	cfg.FromName = "Evil"
	err := Send(context.Background(), cfg, "", Message{
		To:      []string{"ann@example.com"},
		Subject: "Hi\r\nBcc: attacker@example.com\r\nX-Evil: 1",
		Body:    "body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.data, "\nBcc:") || strings.Contains(f.data, "\nX-Evil:") || len(f.rcpts) != 1 {
		t.Errorf("injected: rcpts=%v\n%s", f.rcpts, f.data)
	}
	// An address that tries to add a second recipient is refused outright.
	if err := Send(context.Background(), cfg, "", Message{To: []string{"ann@example.com>\r\nRCPT TO:<x@y.z"}, Subject: "s", Body: "b"}); err == nil {
		t.Error("a recipient with a line break was accepted")
	}
	cfg.FromAddress = "a@example.com\r\nBcc: x@y.z"
	if err := cfg.Validate(); err == nil {
		t.Error("a sender address with a line break was accepted")
	}
	// Non-ASCII subjects and bodies are encoded, not sent raw.
	f2 := &fakeServer{}
	host, port = startServer(t, f2)
	if err := Send(context.Background(), cfgFor(host, port, SecurityNone), "", Message{To: []string{"ann@example.com"}, Subject: "Alerte critique ⚠", Body: "événement"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f2.data, "Subject: =?utf-8?q?") || strings.Contains(f2.data, "é") {
		t.Errorf("non-ASCII not encoded:\n%s", f2.data)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Host: "smtp.example.com", Port: 587, Security: SecuritySTARTTLS, FromAddress: "siem@example.com"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"no host":       func(c *Config) { c.Host = "" },
		"host with url": func(c *Config) { c.Host = "smtp://example.com" },
		"port 0":        func(c *Config) { c.Port = 0 },
		"port 70000":    func(c *Config) { c.Port = 70000 },
		"security":      func(c *Config) { c.Security = "ssl" },
		"no from":       func(c *Config) { c.FromAddress = "" },
		"bad from":      func(c *Config) { c.FromAddress = "not an address" },
		"named from":    func(c *Config) { c.FromAddress = "Siem <siem@example.com>" },
	} {
		c := ok
		mod(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// memStore is Service's settings store.
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
	s.m[k] = v
	return nil
}

func TestServiceKeepsThePasswordSecret(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := &memStore{m: map[string]string{}}
	svc := NewService(st, filepath.Join(dir, "siemlite-secret.key"))

	if v, err := svc.Get(ctx); err != nil || v.Configured || v.Port != 587 || v.Security != SecuritySTARTTLS {
		t.Fatalf("empty: %+v %v", v, err)
	}
	f := &fakeServer{starttls: true, auth: "PLAIN", user: "u", pass: "hunter2 secret"}
	host, port := startServer(t, f)
	cfg := cfgFor(host, port, SecuritySTARTTLS)
	cfg.Username = "u"
	pw := "hunter2 secret"
	if err := svc.Save(ctx, cfg, &pw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.m[settingKey], "hunter2") {
		t.Fatalf("the password is stored in the clear: %s", st.m[settingKey])
	}
	v, _ := svc.Get(ctx)
	if !v.Configured || !v.HasPassword || v.PasswordUnreadable || v.Username != "u" {
		t.Errorf("view = %+v", v)
	}
	if fi, err := os.Stat(svc.box.Path()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", fi, err)
	}

	// Saved settings send mail, and a save without a password keeps it.
	cfg.FromName = "Renamed"
	if err := svc.Save(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.Send(ctx, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("send with the saved password: %v", err)
	}
	if !strings.Contains(f.data, `"Renamed"`) {
		t.Errorf("new sender name not used:\n%s", f.data)
	}

	// Testing the form before saving: its own password if given, else the saved one.
	if err := svc.SendWith(ctx, cfg, nil, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}); err != nil {
		t.Errorf("SendWith saved password: %v", err)
	}
	wrong := "nope"
	if err := svc.SendWith(ctx, cfg, &wrong, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}); err == nil {
		t.Error("SendWith used the saved password instead of the one given")
	}

	// The saved password is never used to log in anywhere else: a test aimed at
	// a different host, port, login or security needs its own password.
	for name, mod := range map[string]func(*Config){
		"host":     func(c *Config) { c.Host = "localhost" },
		"port":     func(c *Config) { c.Port++ },
		"username": func(c *Config) { c.Username = "someone-else" },
		"security": func(c *Config) { c.Security = SecurityNone },
		"verify":   func(c *Config) { c.SkipVerify = false },
	} {
		moved := cfg
		mod(&moved)
		err := svc.SendWith(ctx, moved, nil, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"})
		var bad InputError
		if !errors.As(err, &bad) || !strings.Contains(err.Error(), "enter its password") {
			t.Errorf("%s changed, saved password reused: %v", name, err)
		}
	}
	// With its own password the same test is allowed; nothing was sent to the changed hosts.
	renamed := cfg
	renamed.FromName = "Only the sender name changed"
	if err := svc.SendWith(ctx, renamed, nil, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}); err != nil {
		t.Errorf("a change that doesn't affect where the password goes was refused: %v", err)
	}

	// Saving the settings pointed at another server doesn't carry the saved password along.
	elsewhere := cfg
	elsewhere.Host = "localhost"
	var bad InputError
	if err := svc.Save(ctx, elsewhere, nil); !errors.As(err, &bad) || !strings.Contains(err.Error(), "enter the password again") {
		t.Errorf("saved password kept for another host: %v", err)
	}
	if v, _ := svc.Get(ctx); v.Host != "127.0.0.1" || !v.HasPassword {
		t.Errorf("a refused save changed the settings: %+v", v)
	}
	newPw := "another-password"
	if err := svc.Save(ctx, elsewhere, &newPw); err != nil {
		t.Errorf("moving to another server with its own password: %v", err)
	}
	if err := svc.Save(ctx, cfg, &pw); err != nil { // back to the test server for what follows
		t.Fatal(err)
	}

	// A server with a different key can't read it, and says so instead of failing oddly.
	other := NewService(st, filepath.Join(t.TempDir(), "other.key"))
	if v, _ := other.Get(ctx); !v.HasPassword || !v.PasswordUnreadable {
		t.Errorf("other key: %+v", v)
	}
	if err := other.Send(ctx, Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}); err == nil || !strings.Contains(err.Error(), "Enter the password again") {
		t.Errorf("other key send: %v", err)
	}

	// An empty password removes it; no host clears everything.
	empty := ""
	if err := svc.Save(ctx, cfg, &empty); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(ctx); v.HasPassword {
		t.Error("password not removed")
	}
	if err := svc.Save(ctx, Config{}, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(ctx); v.Configured || v.Host != "" {
		t.Errorf("not cleared: %+v", v)
	}
	if err := svc.Send(ctx, Message{To: []string{"a@b.co"}}); err == nil || !strings.Contains(err.Error(), "isn't set up") {
		t.Errorf("send when unset: %v", err)
	}
}

func TestEnabledSwitchKeepsTheSettings(t *testing.T) {
	ctx := context.Background()
	st := &memStore{m: map[string]string{}}
	svc := NewService(st, filepath.Join(t.TempDir(), "k.key"))
	f := &fakeServer{}
	host, port := startServer(t, f)
	msg := Message{To: []string{"ann@example.com"}, Subject: "s", Body: "b"}

	// Nothing saved: not configured, and there's nothing to turn on.
	if info, err := svc.Info(ctx); err != nil || info.Configured || info.Enabled {
		t.Fatalf("empty info = %+v %v", info, err)
	}
	var bad InputError
	if err := svc.SetEnabled(ctx, true); !errors.As(err, &bad) {
		t.Errorf("turning on with nothing saved: %v", err)
	}
	if svc.ID() != "email" || svc.Name() != "Email" || svc.Description() == "" {
		t.Error("integration details")
	}

	cfg := cfgFor(host, port, SecurityNone)
	if err := svc.Save(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if info, _ := svc.Info(ctx); !info.Configured || !info.Enabled || !strings.Contains(info.Summary, "siem@example.com") {
		t.Errorf("saved info = %+v", info)
	}
	if err := svc.Send(ctx, msg); err != nil {
		t.Fatalf("send while on: %v", err)
	}

	// Off: settings kept, sending refused, a test of the form still works.
	if err := svc.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(ctx); !v.Configured || v.Enabled || v.Host != host {
		t.Errorf("off view = %+v", v)
	}
	if info, _ := svc.Info(ctx); !info.Configured || info.Enabled {
		t.Errorf("off info = %+v", info)
	}
	if svc.Configured(ctx) {
		t.Error("Configured should be false while email is off")
	}
	if err := svc.Send(ctx, msg); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Errorf("send while off: %v", err)
	}
	if err := svc.SendWith(ctx, cfg, nil, msg); err != nil {
		t.Errorf("testing the form while off: %v", err)
	}
	// Saving other changes while off keeps it off.
	cfg.FromName = "Changed"
	if err := svc.Save(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Get(ctx); v.Enabled || v.FromName != "Changed" {
		t.Errorf("save while off turned it on or lost the change: %+v", v)
	}
	if err := svc.SetEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := svc.Send(ctx, msg); err != nil {
		t.Errorf("send after turning on: %v", err)
	}

	// Settings saved before the switch existed (no "disabled" key) are on.
	st.m[settingKey] = `{"host":"` + host + `","port":` + strconv.Itoa(port) + `,"security":"none","from_address":"siem@example.com"}`
	if v, _ := svc.Get(ctx); !v.Enabled {
		t.Error("an older saved configuration should be on")
	}
}

// A message can carry a file; the file name can't add headers, and the file comes back intact.
func TestAttachments(t *testing.T) {
	cfg := Config{Host: "smtp.example", Port: 587, FromAddress: "siem@example.com", Security: SecuritySTARTTLS}
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	raw, _, err := build(cfg, Message{To: []string{"a@example.com"}, Subject: "Report", Body: "See attached.\n",
		Attachments: []Attachment{{Name: "week\r\nBcc: evil@example.com \"x\"/..\\report.pdf", ContentType: "application/pdf", Data: data}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" {
		t.Error("a file name added a header")
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("content type %q: %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var gotText string
	var gotFile []byte
	var fileName string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p)
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain") {
			gotText = string(b)
			continue
		}
		fileName = p.FileName()
		if dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b), "\r\n", "")); err == nil {
			gotFile = dec
		}
	}
	if !strings.Contains(gotText, "See attached") {
		t.Errorf("text part = %q", gotText)
	}
	if !bytes.Equal(gotFile, data) {
		t.Errorf("the attachment came back different (%d bytes)", len(gotFile))
	}
	if strings.ContainsAny(fileName, "\r\n/\\\"") {
		t.Errorf("file name = %q", fileName)
	}
	if _, _, err := build(cfg, Message{To: []string{"a@example.com"}, Attachments: []Attachment{{Name: "big", Data: make([]byte, MaxAttachmentBytes+1)}}}, time.Now()); err == nil {
		t.Error("an oversized attachment was accepted")
	}
}

func TestAttachmentContentTypeIsCheckedAndBare(t *testing.T) {
	cfg := Config{Host: "smtp.example.com", Port: 587, Security: SecuritySTARTTLS, FromAddress: "siemlite@example.com"}
	for ct, want := range map[string]string{"application/pdf": "application/pdf", "": "application/octet-stream", "\x06": "application/octet-stream",
		"text/html\r\nX-Evil: 1": "application/octet-stream", "text/plain; boundary=zzz": "text/plain", "Application/PDF": "application/pdf"} {
		raw, _, err := build(cfg, Message{To: []string{"a@example.com"}, Attachments: []Attachment{{Name: "a.bin", ContentType: ct, Data: []byte("x")}}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "\r\nContent-Type: "+want+"; name=\"a.bin\"\r\n") || strings.Contains(string(raw), "X-Evil") || strings.Contains(string(raw), "zzz") {
			t.Errorf("content type %q: want %q in\n%s", ct, want, raw)
		}
	}
}
