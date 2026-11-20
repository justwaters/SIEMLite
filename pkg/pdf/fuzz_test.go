package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// checkStructure verifies a finished file: header, trailer, a correct xref table and
// startxref, well-formed text strings, and page streams that inflate to well-formed text.
func checkStructure(t *testing.T, b []byte, pages int) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		t.Fatalf("no header: %q", b[:min(len(b), 20)])
	}
	if !bytes.HasSuffix(bytes.TrimRight(b, "\r\n"), []byte("%%EOF")) {
		t.Fatalf("no %%%%EOF: %q", b[max(0, len(b)-40):])
	}
	i := bytes.LastIndex(b, []byte("startxref\n"))
	if i < 0 {
		t.Fatal("no startxref")
	}
	var xrefAt int
	if _, err := fmt.Sscanf(string(b[i+len("startxref\n"):]), "%d", &xrefAt); err != nil {
		t.Fatalf("startxref: %v", err)
	}
	if xrefAt <= 0 || xrefAt >= len(b) || !bytes.HasPrefix(b[xrefAt:], []byte("xref\n")) {
		t.Fatalf("startxref %d does not point at xref", xrefAt)
	}
	lines := strings.Split(string(b[xrefAt:]), "\n")
	var count int
	if _, err := fmt.Sscanf(lines[1], "0 %d", &count); err != nil {
		t.Fatalf("xref header %q", lines[1])
	}
	if count != 5+2*pages+1 {
		t.Fatalf("xref has %d entries for %d pages", count, pages)
	}
	if lines[2] != "0000000000 65535 f " {
		t.Fatalf("xref free entry %q", lines[2])
	}
	for n := 1; n < count; n++ {
		e := lines[2+n]
		if len(e) != 19 || !strings.HasSuffix(e, " 00000 n ") {
			t.Fatalf("xref entry %d: %q", n, e)
		}
		off, err := strconv.Atoi(e[:10])
		if err != nil || off <= 0 || off >= xrefAt {
			t.Fatalf("xref entry %d offset %q", n, e)
		}
		if want := fmt.Sprintf("%d 0 obj\n", n); !bytes.HasPrefix(b[off:], []byte(want)) {
			t.Fatalf("object %d is not at offset %d: %q", n, off, b[off:min(len(b), off+20)])
		}
	}
	if !strings.Contains(lines[3+count], fmt.Sprintf("/Size %d", count)) {
		t.Fatalf("trailer %q", lines[3+count])
	}
	// The title literal must close where we expect.
	m := regexp.MustCompile(`/Title \(`).FindIndex(b)
	if m == nil {
		t.Fatal("no title")
	}
	end, ok := literalEnd(b[m[1]:])
	if !ok || !bytes.HasPrefix(b[m[1]+end:], []byte(") /Producer (SIEMLite)")) {
		t.Fatalf("title literal is not well formed: %q", b[m[0]:min(len(b), m[1]+end+30)])
	}
	// Each page stream inflates, and every text string in it is well formed.
	streams := 0
	rest := b
	for {
		s := bytes.Index(rest, []byte("stream\n"))
		if s < 0 {
			break
		}
		rest = rest[s+len("stream\n"):]
		e := bytes.Index(rest, []byte("\nendstream"))
		if e < 0 {
			t.Fatal("stream not closed")
		}
		zr, err := zlib.NewReader(bytes.NewReader(rest[:e]))
		if err != nil {
			t.Fatalf("stream %d: %v", streams, err)
		}
		raw, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("stream %d inflate: %v", streams, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "BT ") {
				continue
			}
			k := strings.Index(line, "Td (")
			if k < 0 {
				t.Fatalf("text line %q", line)
			}
			lit := line[k+4:]
			end, ok := literalEnd([]byte(lit))
			if !ok || lit[end:] != ") Tj ET" {
				t.Fatalf("text literal not well formed: %q", line[:min(len(line), 120)])
			}
		}
		streams++
		rest = rest[e+len("\nendstream"):]
	}
	if streams != pages {
		t.Fatalf("%d streams for %d pages", streams, pages)
	}
}

// literalEnd scans a PDF literal string body (after the opening paren) and returns the index of
// the closing paren. Output must be printable ASCII with only escaped parens and backslashes.
func literalEnd(b []byte) (int, bool) {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 32 || c > 126 {
			return 0, false
		}
		switch c {
		case '(':
			return 0, false // must have been escaped
		case ')':
			return i, true
		case '\\':
			i++
			if i >= len(b) {
				return 0, false
			}
			switch b[i] {
			case '(', ')', '\\':
			case '0', '1', '2', '3':
				if i+2 >= len(b) || b[i+1] < '0' || b[i+1] > '7' || b[i+2] < '0' || b[i+2] > '7' {
					return 0, false
				}
				i += 2
			default:
				return 0, false
			}
		}
	}
	return 0, false
}

// FuzzDocument builds documents out of arbitrary text and checks the file is well formed.
func FuzzDocument(f *testing.F) {
	f.Add("SIEMLite security report", "10.0.0.1 (admin) logged in", "C:\\path\\to\\file", uint8(0), 10.0, uint8(0))
	f.Add("", "", "", uint8(1), 0.0, uint8(2))
	f.Add("\xff\xfe\x00\x01", "tab\there\r\nnewline\x7f\x1b[31m", "\u00e9\u20ac\u2603\U0001F600\u0301", uint8(1), 8.5, uint8(1))
	f.Add(strings.Repeat("(", 5000), strings.Repeat(")", 5000), strings.Repeat("\\", 5000), uint8(0), 12.0, uint8(2))
	f.Add("endstream endobj ) Tj ET\n1 0 obj\nxref", "BT /F1 12 Tf (x) Tj ET %%EOF startxref 0", ") >> /Producer (evil) /Title (", uint8(0), 11.0, uint8(0))
	f.Add(strings.Repeat("W", 100000), strings.Repeat("\u00e9 ", 30000), strings.Repeat("\x00", 10000), uint8(1), 6.0, uint8(1))
	f.Fuzz(func(t *testing.T, title, a, c string, font uint8, size float64, align uint8) {
		if !(size >= 1 && size <= 200) {
			size = 10
		}
		fnt, al := Font(font%2), Align(align%3)
		created := time.Unix(1_700_000_000, 0)
		build := func() []byte {
			d := New(title, created)
			p := d.AddPage()
			p.Text(100, 100, fnt, size, Hex(0x336699), al, a)
			p.Text(-1e6, 1e6, fnt, size, Color{2, -1, 0.5}, al, c)
			p.Text(0, 0, HelveticaBold, size, Color{}, Left, a+c)
			for _, line := range Wrap(fnt, size, 200, a) {
				p.Text(10, 10, fnt, size, Color{}, Left, line)
			}
			p.Text(10, 10, fnt, size, Color{}, Right, Ellipsize(fnt, size, 100, c))
			p.FillRect(1, 2, 3, 4, Hex(0xffffff))
			p.StrokeRect(1, 2, 3, 4, 1, Hex(0))
			p.Line(1, 2, 3, 4, 1, Hex(0))
			d.AddPage()
			d.Page(1).Text(10, 10, fnt, size, Color{}, Center, title)
			b, err := d.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			checkStructure(t, b, 2)
			return b
		}
		b1, b2 := build(), build()
		if !bytes.Equal(b1, b2) {
			t.Fatal("same input gave different output")
		}
	})
}

// FuzzLayoutHelpers: Wrap, Ellipsize and TextWidth never panic, always make progress, and keep
// every non-space rune.
func FuzzLayoutHelpers(f *testing.F) {
	f.Add("The quick brown fox", 10.0, 50.0, uint8(0))
	f.Add("", 10.0, 0.0, uint8(1))
	f.Add(strings.Repeat("W", 3000), 12.0, 1.0, uint8(0))
	f.Add("\xff\xfe\u00e9 \u3042\u3044\u3046 \x00", 9.0, 5.0, uint8(1))
	f.Add("a b c d e f g", 1.0, -5.0, uint8(0))
	f.Fuzz(func(t *testing.T, s string, size, maxW float64, font uint8) {
		if !(size >= 1 && size <= 200) {
			size = 10
		}
		if !(maxW >= -10 && maxW <= 2000) {
			maxW = 100
		}
		fnt := Font(font % 2)
		lines := Wrap(fnt, size, maxW, s)
		if len(lines) == 0 {
			t.Fatal("no lines")
		}
		if utf8.ValidString(s) {
			if got, want := strings.Join(strings.Fields(strings.Join(lines, "")), ""), strings.Join(strings.Fields(s), ""); got != want {
				t.Fatalf("Wrap lost text: %q != %q", got, want)
			}
		}
		e := Ellipsize(fnt, size, maxW, s)
		if maxW >= TextWidth(fnt, size, "...") && TextWidth(fnt, size, e) > maxW+1e-6 {
			t.Fatalf("Ellipsize(%q) = %q is wider than %v", s, e, maxW)
		}
		if w := TextWidth(fnt, size, s); w < 0 {
			t.Fatalf("negative width %v", w)
		}
	})
}
