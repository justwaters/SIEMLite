// Package email holds the SMTP settings SIEMLite sends mail with, and sends it.
//
// The settings are saved in the database's settings table. The password is
// encrypted with a key kept in a file beside the database (see secret.go), so
// it isn't readable from a backup or a copy of the database alone.
package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/integrations"
)

// Connection security.
const (
	SecuritySTARTTLS = "starttls" // connect in the clear, then upgrade (usually port 587)
	SecurityTLS      = "tls"      // TLS from the first byte (usually port 465)
	SecurityNone     = "none"     // no encryption (usually port 25)
)

const (
	dialTimeout = 15 * time.Second
	sendTimeout = 60 * time.Second
)

// InputError is a mistake in what a person entered, worded for them.
type InputError = integrations.InputError

// Config is the server and sender, without the password.
type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Security    string `json:"security"`
	Username    string `json:"username"`
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name"`
	// SkipVerify accepts any certificate from the server, for relays with a
	// self-signed one. The connection is still encrypted.
	SkipVerify bool `json:"skip_verify"`
}

// sameServer reports whether o connects to the same server, with the same
// login, so a password saved for c is safe to use with it.
func (c Config) sameServer(o Config) bool {
	return strings.EqualFold(strings.TrimSpace(c.Host), strings.TrimSpace(o.Host)) && c.Port == o.Port &&
		c.Security == o.Security && c.Username == strings.TrimSpace(o.Username) && c.SkipVerify == o.SkipVerify
}

// DefaultPort is the usual port for a security mode.
func DefaultPort(security string) int {
	switch security {
	case SecurityTLS:
		return 465
	case SecurityNone:
		return 25
	}
	return 587
}

// Validate checks a Config the way a person filling it in would want to be told.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return InputError("Enter the mail server's address.")
	}
	if strings.ContainsAny(c.Host, " /\\@\r\n") {
		return InputError("The mail server's address should be a name or IP address only, such as smtp.example.com.")
	}
	if c.Port < 1 || c.Port > 65535 {
		return InputError("The port must be between 1 and 65535.")
	}
	switch c.Security {
	case SecuritySTARTTLS, SecurityTLS, SecurityNone:
	default:
		return InputError("Choose STARTTLS, TLS or no encryption.")
	}
	if strings.ContainsAny(c.Username, "\r\n") {
		return InputError("The username can't contain a line break.")
	}
	a, err := netmail.ParseAddress(c.FromAddress)
	if err != nil || a.Address != strings.TrimSpace(c.FromAddress) {
		return InputError("Enter the address mail is sent from, such as siemlite@example.com.")
	}
	if strings.ContainsAny(c.FromName, "\r\n") {
		return InputError("The sender name can't contain a line break.")
	}
	return nil
}

// Message is a plain-text email, with files attached if there are any.
type Message struct {
	To          []string
	Subject     string
	Body        string
	Attachments []Attachment
}

// Attachment is a file sent with a message.
type Attachment struct {
	Name        string // shown to the reader; path separators, quotes and control characters are dropped
	ContentType string // e.g. application/pdf
	Data        []byte
}

// MaxAttachmentBytes is the most a message may carry; mail servers refuse much more than this.
const MaxAttachmentBytes = 20 << 20

func safeFileName(n string) string {
	n = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '"' || r == '\\' || r == '/' || r == ';' {
			return -1
		}
		return r
	}, n)
	if n = strings.TrimSpace(n); n == "" {
		return "attachment"
	}
	return n
}

// build returns the message as it goes on the wire, and the bare envelope
// addresses. Every header value is checked or encoded, so nothing in a subject
// or an address can add headers or recipients.
func build(cfg Config, m Message, now time.Time) (msg []byte, rcpts []string, err error) {
	if len(m.To) == 0 {
		return nil, nil, InputError("Enter an address to send to.")
	}
	from := netmail.Address{Name: strings.TrimSpace(cfg.FromName), Address: strings.TrimSpace(cfg.FromAddress)}
	var to []string
	for _, t := range m.To {
		a, err := netmail.ParseAddress(strings.TrimSpace(t))
		if err != nil {
			return nil, nil, InputError(fmt.Sprintf("%q isn't a valid email address.", t))
		}
		to = append(to, a.String())
		rcpts = append(rcpts, a.Address)
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Subject)

	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, err
	}
	domain := "siemlite.invalid"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}

	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", strings.Join(to, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("X-Mailer", "SIEMLite")
	// Quoted-printable wants CRLF line ends.
	body := strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n")
	text := func(w *strings.Builder) error {
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(body)); err != nil {
			return err
		}
		return qp.Close()
	}
	if len(m.Attachments) == 0 {
		h("Content-Type", `text/plain; charset="utf-8"`)
		h("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := text(&b); err != nil {
			return nil, nil, err
		}
		return []byte(b.String()), rcpts, nil
	}
	total := 0
	for _, a := range m.Attachments {
		total += len(a.Data)
	}
	if total > MaxAttachmentBytes {
		return nil, nil, InputError(fmt.Sprintf("The attachment is %d MB; mail servers won't take more than %d MB.", total>>20, MaxAttachmentBytes>>20))
	}
	bnd := make([]byte, 16)
	if _, err := rand.Read(bnd); err != nil {
		return nil, nil, err
	}
	boundary := "siemlite-" + hex.EncodeToString(bnd)
	h("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	if err := text(&b); err != nil {
		return nil, nil, err
	}
	for _, a := range m.Attachments {
		name := mime.QEncoding.Encode("utf-8", safeFileName(a.Name))
		ct := strings.NewReplacer("\r", "", "\n", "").Replace(strings.TrimSpace(a.ContentType))
		if ct == "" {
			ct = "application/octet-stream"
		}
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", ct, name))
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", name))
		enc := base64.StdEncoding.EncodeToString(a.Data)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String()), rcpts, nil
}

// Send delivers m through the server in cfg, logging in with password when cfg
// has a username. Errors are worded for the person who set the server up.
func Send(ctx context.Context, cfg Config, password string, m Message) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, rcpts, err := build(cfg, m, time.Now())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.SkipVerify}
	dialer := &net.Dialer{Timeout: dialTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("Couldn't connect to %s: %s", addr, trimErr(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if cfg.Security == SecurityTLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("The secure connection to %s failed: %s", addr, trimErr(err))
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("%s didn't answer like a mail server: %s", addr, trimErr(err))
	}
	defer c.Close()

	if err := c.Hello(helloName()); err != nil {
		return fmt.Errorf("The server refused the greeting: %s", trimErr(err))
	}
	if cfg.Security == SecuritySTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("The server doesn't offer STARTTLS. Choose TLS or no encryption, or check the port.")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("The secure connection to %s failed: %s", addr, trimErr(err))
		}
	}
	if cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("The server doesn't offer a login, but a username is set. Clear the username, or check the server and security.")
		}
		if err := authenticate(c, cfg.Username, password); err != nil {
			return fmt.Errorf("The server rejected the login: %s", trimErr(err))
		}
	}
	if err := c.Mail(strings.TrimSpace(cfg.FromAddress)); err != nil {
		return fmt.Errorf("The server refused the sender address: %s", trimErr(err))
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("The server refused %s: %s", r, trimErr(err))
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("The server refused the message: %s", trimErr(err))
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("Sending failed: %s", trimErr(err))
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("The server refused the message: %s", trimErr(err))
	}
	_ = c.Quit()
	return nil
}

func helloName() string {
	if h, err := os.Hostname(); err == nil && h != "" && !strings.ContainsAny(h, " \r\n") {
		return h
	}
	return "localhost"
}

func trimErr(err error) string {
	s := err.Error()
	// "dial tcp 10.0.0.1:25: connect: connection refused" -> the part that helps.
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.HasPrefix(s, "dial ") {
		s = s[i+2:]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// authenticate logs in with whichever of PLAIN and LOGIN the server offers
// (Microsoft 365 and many relays only offer LOGIN).
func authenticate(c *smtp.Client, user, pass string) error {
	_, mechs := c.Extension("AUTH")
	has := func(m string) bool {
		for _, f := range strings.Fields(strings.ToUpper(mechs)) {
			if f == m {
				return true
			}
		}
		return false
	}
	switch {
	case has("PLAIN"):
		return c.Auth(plainAuth{user, pass})
	case has("LOGIN"):
		return c.Auth(loginAuth{user, pass})
	}
	return fmt.Errorf("it offers %q, and SIEMLite supports PLAIN and LOGIN", strings.TrimSpace(mechs))
}

// plainAuth and loginAuth don't refuse an unencrypted connection the way
// net/smtp's PlainAuth does: choosing "no encryption" is the person's decision,
// and the settings page says what it means.
type plainAuth struct{ user, pass string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}
func (plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type loginAuth struct{ user, pass string }

func (loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }
func (a loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(from))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.pass), nil
	}
	return nil, errors.New("unexpected server challenge")
}
