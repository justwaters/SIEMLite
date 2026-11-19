package pdf

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sample() *Doc {
	d := New("T (x)", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	for i := 0; i < 3; i++ {
		p := d.AddPage()
		p.FillRect(10, 10, 100, 20, Hex(0x336699))
		p.StrokeRect(10, 10, 100, 20, 1, Hex(0))
		p.Line(0, 0, 50, 50, 0.5, Hex(0x999999))
		p.Text(10, 40, Helvetica, 12, Hex(0), Left, "Hello (world) \\ café 中")
		p.Text(500, 60, HelveticaBold, 12, Hex(0), Right, "Right")
		p.Text(300, 80, Helvetica, 12, Hex(0), Center, "Mid")
	}
	return d
}

func TestStructure(t *testing.T) {
	b, err := sample().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "%PDF-1.4") || !strings.HasSuffix(s, "%%EOF\n") {
		t.Fatal("bad header/trailer")
	}
	i := strings.LastIndex(s, "startxref\n")
	off, _ := strconv.Atoi(strings.Fields(s[i+10:])[0])
	if !strings.HasPrefix(s[off:], "xref\n0 ") {
		t.Fatal("startxref wrong")
	}
	lines := strings.Split(s[off:], "\n")
	cnt, _ := strconv.Atoi(strings.Fields(lines[1])[1])
	for n := 1; n < cnt; n++ {
		o, _ := strconv.Atoi(strings.Fields(lines[2+n])[0])
		if !strings.HasPrefix(s[o:], strconv.Itoa(n)+" 0 obj") {
			t.Fatalf("object %d offset wrong", n)
		}
	}
	if !strings.Contains(s, "/Size "+strconv.Itoa(cnt)) || cnt != 6+6 {
		t.Fatalf("size %d", cnt)
	}
	if !strings.Contains(s, "/Count 3") || !strings.Contains(s, "D:20260102030405") || !strings.Contains(s, "/Producer (SIEMLite)") {
		t.Fatal("missing pages count/info")
	}
	b2, _ := sample().Bytes()
	if !bytes.Equal(b, b2) {
		t.Fatal("not deterministic")
	}
}

func TestContentStream(t *testing.T) {
	b, _ := sample().Bytes()
	re := regexp.MustCompile(`(?s)stream\n(.*?)\nendstream`)
	m := re.FindAllSubmatch(b, -1)
	if len(m) != 3 {
		t.Fatalf("streams %d", len(m))
	}
	r, err := zlib.NewReader(bytes.NewReader(m[0][1]))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(r)
	for _, want := range []string{`(Hello \(world\) \\ caf\351 ?)`, "(Right)", "re f"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %q in %s", want, raw)
		}
	}
}

func TestTextWidth(t *testing.T) {
	if w := TextWidth(Helvetica, 10, "AB"); w != 13.34 {
		t.Fatalf("got %v", w)
	}
	if TextWidth(HelveticaBold, 10, "abc") <= TextWidth(Helvetica, 10, "abc") {
		t.Fatal("bold should be wider")
	}
	if TextWidth(Helvetica, 10, "abcd") <= TextWidth(Helvetica, 10, "abc") {
		t.Fatal("not monotonic")
	}
}

func TestWrap(t *testing.T) {
	s := "the quick brown fox jumps over the lazy dog " + strings.Repeat("x", 300)
	lines := Wrap(Helvetica, 10, 100, s)
	if len(lines) < 4 {
		t.Fatal(lines)
	}
	for _, l := range lines {
		if TextWidth(Helvetica, 10, l) > 100 {
			t.Fatalf("too wide: %q", l)
		}
	}
	if got := strings.Join(lines, " "); !strings.Contains(strings.ReplaceAll(got, " ", ""), strings.Repeat("x", 300)) {
		t.Fatal("lost text")
	}
	if l := Wrap(Helvetica, 10, 100, ""); len(l) != 1 {
		t.Fatal(l)
	}
}

func TestEllipsize(t *testing.T) {
	s := strings.Repeat("hello ", 50)
	prev := 0
	for w := 20.0; w < 200; w += 20 {
		e := Ellipsize(Helvetica, 10, w, s)
		if TextWidth(Helvetica, 10, e) > w && e != "..." {
			t.Fatalf("too wide at %v: %q", w, e)
		}
		if len(e) < prev {
			t.Fatal("not monotonic")
		}
		prev = len(e)
	}
	if Ellipsize(Helvetica, 10, 500, "short") != "short" {
		t.Fatal("changed short")
	}
}

func TestEncodeUnencodable(t *testing.T) {
	if string(encode("a中b\n")) != "a?b " {
		t.Fatal(string(encode("a中b\n")))
	}
}
