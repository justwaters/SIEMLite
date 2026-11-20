// Package pdf is a tiny PDF 1.4 writer: A4 pages, the two standard Helvetica fonts, rectangles,
// lines and text. Coordinates are in points with the origin at the top left of the page.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
)

// A4 page size in points.
const (
	PageW = 595.28
	PageH = 841.89
)

// Font is one of the two built-in fonts.
type Font int

const (
	Helvetica Font = iota
	HelveticaBold
)

// Align says which point of the text sits at x.
type Align int

const (
	Left Align = iota
	Right
	Center
)

// Color is an RGB colour, each channel 0..1.
type Color struct{ R, G, B float64 }

// Hex makes a colour from 0xRRGGBB.
func Hex(v uint32) Color {
	return Color{float64(v>>16&0xff) / 255, float64(v>>8&0xff) / 255, float64(v&0xff) / 255}
}

var helvWidths = [95]int{278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584}

var boldWidths = [95]int{278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 556, 556, 778, 556, 556, 500, 389, 280, 389, 584}

func (f Font) baseName() string {
	if f == HelveticaBold {
		return "Helvetica-Bold"
	}
	return "Helvetica"
}

func (f Font) width(b byte) int {
	if b >= 32 && b <= 126 {
		if f == HelveticaBold {
			return boldWidths[b-32]
		}
		return helvWidths[b-32]
	}
	return 556
}

// encode turns s into Windows-1252 bytes; what cannot be encoded becomes '?' and control
// characters become spaces.
func encode(s string) []byte {
	out := make([]byte, 0, len(s))
	enc := charmap.Windows1252.NewEncoder()
	for _, r := range s {
		switch {
		case r < 32 || r == 127:
			out = append(out, ' ')
		case r < 127:
			out = append(out, byte(r))
		default:
			b, err := enc.Bytes([]byte(string(r)))
			if err != nil || len(b) != 1 {
				out = append(out, '?')
			} else {
				out = append(out, b[0])
			}
		}
	}
	return out
}

// TextWidth is the width of s in points.
func TextWidth(f Font, size float64, s string) float64 {
	w := 0
	for _, b := range encode(s) {
		w += f.width(b)
	}
	return float64(w) * size / 1000
}

// runeWidth is the width of one character in thousandths of the font size.
func runeWidth(f Font, r rune) int {
	w := 0
	for _, b := range encode(string(r)) {
		w += f.width(b)
	}
	return w
}

// Wrap breaks s into lines no wider than maxWidth, at spaces; a word wider than a line is broken
// hard. It always returns at least one line.
func Wrap(f Font, size, maxWidth float64, s string) []string {
	var lines []string
	cur := ""
	flush := func() {
		lines = append(lines, cur)
		cur = ""
	}
	for _, word := range strings.Fields(s) {
		if cur != "" {
			if TextWidth(f, size, cur+" "+word) <= maxWidth {
				cur += " " + word
				continue
			}
			flush()
		}
		// Break a word wider than a line hard, a run of characters at a time. Widths are added up as
		// we go, so a very long word costs time in proportion to its length.
		rs := []rune(word)
		for len(rs) > 0 {
			w, n := runeWidth(f, rs[0]), 1
			for n < len(rs) {
				next := w + runeWidth(f, rs[n])
				if float64(next)*size/1000 > maxWidth {
					break
				}
				w, n = next, n+1
			}
			if n >= len(rs) {
				break
			}
			lines = append(lines, string(rs[:n]))
			rs = rs[n:]
		}
		word = string(rs)
		cur = word
	}
	if cur != "" || len(lines) == 0 {
		flush()
	}
	return lines
}

// Ellipsize shortens s with "..." so it is no wider than maxWidth.
func Ellipsize(f Font, size, maxWidth float64, s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if TextWidth(f, size, s) <= maxWidth {
		return s
	}
	const dots = "..."
	rs := []rune(s)
	// No character is narrower than 0.19 em, so nothing past this many can fit.
	if lim := max(0, int(maxWidth*1000/(190*size))+2); size > 0 && lim < len(rs) { // (a negative width must not slice backwards)
		rs = rs[:lim]
	}
	for n := len(rs) - 1; n > 0; n-- {
		t := strings.TrimRight(string(rs[:n]), " ") + dots
		if TextWidth(f, size, t) <= maxWidth {
			return t
		}
	}
	return dots
}

// Doc is a document being built.
type Doc struct {
	Title   string
	Created time.Time
	pages   []*Page
}

// New starts a document. created is written into the file, so equal input gives equal output.
func New(title string, created time.Time) *Doc { return &Doc{Title: title, Created: created} }

// Pages is how many pages there are.
func (d *Doc) Pages() int { return len(d.pages) }

// Page returns the i'th page (0-based), to add more to it.
func (d *Doc) Page(i int) *Page { return d.pages[i] }

// AddPage appends a blank A4 page.
func (d *Doc) AddPage() *Page {
	p := &Page{}
	d.pages = append(d.pages, p)
	return p
}

// Page is one page's drawing commands.
type Page struct{ buf bytes.Buffer }

func (p *Page) color(c Color, stroke bool) {
	op := "rg"
	if stroke {
		op = "RG"
	}
	fmt.Fprintf(&p.buf, "%.3f %.3f %.3f %s\n", c.R, c.G, c.B, op)
}

// FillRect fills the rectangle with top-left corner (x, y).
func (p *Page) FillRect(x, y, w, h float64, c Color) {
	p.color(c, false)
	fmt.Fprintf(&p.buf, "%.2f %.2f %.2f %.2f re f\n", x, PageH-y-h, w, h)
}

// StrokeRect outlines the rectangle.
func (p *Page) StrokeRect(x, y, w, h, lw float64, c Color) {
	p.color(c, true)
	fmt.Fprintf(&p.buf, "%.2f w %.2f %.2f %.2f %.2f re S\n", lw, x, PageH-y-h, w, h)
}

// Line draws a straight line.
func (p *Page) Line(x1, y1, x2, y2, lw float64, c Color) {
	p.color(c, true)
	fmt.Fprintf(&p.buf, "%.2f w %.2f %.2f m %.2f %.2f l S\n", lw, x1, PageH-y1, x2, PageH-y2)
}

// Text draws s with the top of its line at y (the baseline sits a little below), aligned at x.
func (p *Page) Text(x, y float64, f Font, size float64, c Color, a Align, s string) {
	if s == "" {
		return
	}
	w := TextWidth(f, size, s)
	switch a {
	case Right:
		x -= w
	case Center:
		x -= w / 2
	}
	base := PageH - (y + size*0.8)
	p.color(c, false)
	fmt.Fprintf(&p.buf, "BT /F%d %.2f Tf %.2f %.2f Td (", int(f)+1, size, x, base)
	for _, b := range encode(s) {
		switch {
		case b == '(' || b == ')' || b == '\\':
			p.buf.WriteByte('\\')
			p.buf.WriteByte(b)
		case b > 126:
			fmt.Fprintf(&p.buf, "\\%03o", b)
		default:
			p.buf.WriteByte(b)
		}
	}
	p.buf.WriteString(") Tj ET\n")
}

// Bytes writes the finished file.
func (d *Doc) Bytes() ([]byte, error) {
	var out bytes.Buffer
	var offs []int // offs[i] is the offset of object i+1
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	obj := func(body string) {
		offs = append(offs, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offs), body)
	}
	n := len(d.pages)
	kids := make([]string, n)
	for i := range d.pages {
		kids[i] = fmt.Sprintf("%d 0 R", 6+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", n, strings.Join(kids, " ")))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	created := d.Created.UTC().Format("20060102150405")
	obj(fmt.Sprintf("<< /Title (%s) /Producer (SIEMLite) /CreationDate (D:%s) >>", escape(d.Title), created))
	for i, p := range d.pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", PageW, PageH, 7+2*i))
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		if _, err := zw.Write(p.buf.Bytes()); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		offs = append(offs, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(offs), z.Len())
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offs)+1)
	for _, o := range offs {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offs)+1, xref)
	return out.Bytes(), nil
}

// escape makes s safe inside a PDF literal string (as Windows-1252).
func escape(s string) string {
	var b strings.Builder
	for _, c := range encode(s) {
		switch {
		case c == '(' || c == ')' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c > 126:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
