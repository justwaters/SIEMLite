package email

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	netmail "net/mail"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzSafeFileName: whatever goes in, the name has no path separator, quote, semicolon,
// backslash, control character or edge space, is never empty, and cleaning it twice changes nothing.
func FuzzSafeFileName(f *testing.F) {
	for _, s := range []string{"siemlite-report-2026-11-18.pdf", "../../etc/passwd", "a\r\nBcc: evil@example.com", "x\"; filename=\"y.exe", "C:\\Windows\\a.exe",
		"", "   ", "\x00\x01", "\u202egpj.exe", "r\u00e9sum\u00e9.pdf", "\xff\xfe", "a;b", "=?utf-8?b?QQ==?=", strings.Repeat("a", 100000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := safeFileName(name)
		if got == "" || strings.TrimSpace(got) != got {
			t.Fatalf("safeFileName(%q) = %q", name, got)
		}
		for _, r := range got {
			if r < 32 || r == 127 || strings.ContainsRune("\"\\/;", r) {
				t.Fatalf("safeFileName(%q) = %q keeps %q", name, got, r)
			}
		}
		if again := safeFileName(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", name, got, again)
		}
	})
}

// FuzzBuildMessage builds messages from arbitrary subjects, bodies, names, content types and file
// bytes, and reads them back the way a mail server and mail program would.
func FuzzBuildMessage(f *testing.F) {
	f.Add("Weekly report", "See attached.\n", "report.pdf", "application/pdf", []byte("%PDF-1.4\n%%EOF"), "a@example.com", "SIEMLite")
	f.Add("hi\r\nBcc: evil@example.com", "body\r\n.\r\nQUIT\r\n", "a\r\nContent-Type: text/html\r\n\r\n<script>", "text/html\r\nX-Evil: 1", []byte("--\r\n--siemlite-"), "a@example.com", "Evil\r\nBcc: x@y.z")
	f.Add("\u00e9\u20ac\U0001F600", "--siemlite-0000\r\n", "\"; filename=\"../../x\"", "a/b; boundary=zzz", []byte{0, 255, '\r', '\n'}, "\"a b\" <c@example.com>", "\u202e")
	f.Add(strings.Repeat("s", 5000), strings.Repeat("=", 5000), strings.Repeat("\u00e9", 3000), "", []byte(nil), "x@y.z", "")
	f.Add("=?utf-8?q?x?=", "", "=?utf-8?b?QQ==?=", "text/plain;", []byte("data"), "a@example.com, b@example.com", "N")
	f.Fuzz(func(t *testing.T, subject, body, fname, ctype string, data []byte, to, fromName string) {
		cfg := Config{Host: "smtp.example.com", Port: 587, Security: SecuritySTARTTLS, FromAddress: "siemlite@example.com", FromName: fromName}
		if cfg.Validate() != nil {
			cfg.FromName = ""
		}
		m := Message{To: []string{to}, Subject: subject, Body: body, Attachments: []Attachment{{Name: fname, ContentType: ctype, Data: data}, {Name: "second.txt", Data: []byte("two")}}}
		now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
		raw, rcpts, err := build(cfg, m, now)
		if err != nil {
			if len(raw) != 0 {
				t.Fatal("bytes returned with an error")
			}
			return
		}
		for _, r := range rcpts {
			if strings.ContainsAny(r, "\r\n,<>") {
				t.Fatalf("envelope address %q", r)
			}
		}
		msg, err := netmail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("net/mail can't read it: %v\n%q", err, raw[:min(len(raw), 600)])
		}
		// Headers: exactly the ones we write, none with a line break inside a value.
		want := map[string]bool{"From": true, "To": true, "Subject": true, "Date": true, "Message-Id": true, "Mime-Version": true, "X-Mailer": true, "Content-Type": true}
		for k, vs := range msg.Header {
			if !want[k] {
				t.Fatalf("injected header %q: %q", k, vs)
			}
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n") {
					t.Fatalf("header %s has a line break: %q", k, v)
				}
			}
			delete(want, k)
		}
		if len(want) != 0 {
			t.Fatalf("missing headers %v", want)
		}
		if bytes.Contains(raw, []byte("\n\n")) && !bytes.Contains(raw, []byte("\r\n\r\n")) {
			t.Fatal("bare line feeds")
		}
		// The recipients survive.
		if got, err := msg.Header.AddressList("To"); err != nil || len(got) != len(rcpts) {
			t.Fatalf("To: %v %v vs %v", got, err, rcpts)
		}
		if utf8.ValidString(subject) {
			dec, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			want := strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(subject))
			if err != nil || strings.TrimSpace(dec) != want {
				if !strings.Contains(subject, "=?") && !strings.ContainsAny(subject, "\t\x00\v\f") {
					t.Fatalf("subject %q came back as %q (%v)", subject, dec, err)
				}
			}
		}
		mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		if err != nil || mt != "multipart/mixed" {
			t.Fatalf("content type %q: %v", msg.Header.Get("Content-Type"), err)
		}
		boundary := params["boundary"]
		if boundary == "" || strings.ContainsAny(boundary, "\r\n \"") {
			t.Fatalf("boundary %q", boundary)
		}
		// The boundary appears only as delimiters: three parts means four delimiter lines.
		if n := strings.Count(string(raw), "--"+boundary); n != 4 {
			t.Fatalf("boundary appears %d times", n)
		}
		mr := multipart.NewReader(msg.Body, boundary)
		var got [][]byte
		var names []string
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("multipart: %v", err)
			}
			for k, vs := range p.Header {
				for _, v := range vs {
					if strings.ContainsAny(v, "\r\n") {
						t.Fatalf("part header %s: %q", k, v)
					}
				}
			}
			var b []byte
			switch enc := p.Header.Get("Content-Transfer-Encoding"); enc {
			case "base64":
				name, err := new(mime.WordDecoder).DecodeHeader(p.FileName()) // as a mail program does
				if err != nil {
					t.Fatalf("file name %q: %v", p.FileName(), err)
				}
				names = append(names, name)
				if cd, _, err := mime.ParseMediaType(p.Header.Get("Content-Disposition")); err != nil || cd != "attachment" {
					t.Fatalf("disposition %q (%v)", p.Header.Get("Content-Disposition"), err)
				}
				b, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
			default:
				b, err = io.ReadAll(p) // the text part, quoted-printable (NextPart decodes it)
			}
			if err != nil {
				t.Fatalf("part: %v", err)
			}
			got = append(got, b)
		}
		if len(got) != 3 || len(names) != 2 {
			t.Fatalf("%d parts, %d attachments", len(got), len(names))
		}
		if !bytes.Equal(got[1], data) || string(got[2]) != "two" {
			t.Fatalf("attachment bytes changed: %q vs %q", got[1], data)
		}
		if wantName := safeFileName(fname); utf8.ValidString(fname) && !strings.Contains(fname, "=?") && names[0] != wantName {
			t.Fatalf("file name %q came back as %q, want %q", fname, names[0], wantName)
		}
		if got[0] == nil {
			t.Fatal("no text part")
		}
		if utf8.ValidString(body) {
			// (the quoted-printable writer turns a lone CR into a line break; that is fine for text)
			nl := strings.NewReplacer("\r\n", "\n", "\r", "\n")
			if g, w := nl.Replace(string(got[0])), nl.Replace(body); g != w {
				t.Fatalf("body %q came back as %q", w, g)
			}
		}
	})
}
