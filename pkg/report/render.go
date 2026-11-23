package report

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"siemlite/pkg/pdf"
	"siemlite/pkg/storage"
)

// Page geometry and the report's colours.
const (
	marginX = 40.0
	topY    = 40.0
	bottomY = pdf.PageH - 62 // content never goes below this; the footer lives under it
	contW   = pdf.PageW - 2*marginX
)

var (
	colText   = pdf.Hex(0x2b2f36)
	colGrey   = pdf.Hex(0x6b7280)
	colRule   = pdf.Hex(0xdfe3e8)
	colPanel  = pdf.Hex(0xf4f6f8)
	colAccent = pdf.Hex(0x2a5d9f)
	colTint   = pdf.Hex(0xa9c4e4)
	colTrack  = pdf.Hex(0xeceff2)
	sevColors = map[int]pdf.Color{
		0: pdf.Hex(0x8a94a0), 1: pdf.Hex(0x8a94a0), 2: pdf.Hex(0x2fa36b), 3: pdf.Hex(0xd9a21a),
		4: pdf.Hex(0xe8742a), 5: pdf.Hex(0xd93b3b), 6: pdf.Hex(0xa31515),
	}
)

const maxRanked = 10

type layout struct {
	doc *pdf.Doc
	p   *pdf.Page
	y   float64
}

func (l *layout) newPage() {
	l.p = l.doc.AddPage()
	l.y = topY
}

// ensure starts a new page unless h more points fit on this one.
func (l *layout) ensure(h float64) {
	if l.p == nil || l.y+h > bottomY {
		l.newPage()
	}
}

// section starts a titled block; need is the height of what must stay with the heading.
func (l *layout) section(title string, need float64) {
	if l.p != nil && l.y > topY+0.1 {
		l.y += 18
	}
	l.ensure(24 + need)
	l.p.Text(marginX, l.y, pdf.HelveticaBold, 11.5, colText, pdf.Left, title)
	l.y += 17
	l.p.Line(marginX, l.y, marginX+contW, l.y, 0.5, colRule)
	l.y += 9
}

func (l *layout) none() {
	l.ensure(14)
	l.p.Text(marginX, l.y, pdf.Helvetica, 9.5, colGrey, pdf.Left, "None in this period.")
	l.y += 14
}

func num(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func stamp(ms int64) string { return time.UnixMilli(ms).In(time.Local).Format("Jan 2, 2006 15:04") }

func capital(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func sevColor(n int) pdf.Color {
	if c, ok := sevColors[n]; ok {
		return c
	}
	return sevColors[0]
}

// PDF lays the report out as a PDF file.
func (d *Data) PDF() ([]byte, error) {
	created := time.UnixMilli(d.Generated)
	title := d.Title
	if strings.TrimSpace(title) == "" {
		title = "SIEMLite security report"
	}
	l := &layout{doc: pdf.New(title, created)}
	l.newPage()

	l.header(d, title)
	l.stats(d)
	l.timeline(d)
	l.severities(d)
	l.sourcesAndCountries(d)
	l.threats(d)
	l.alerts(d)
	l.feeds(d)

	n := l.doc.Pages()
	ver := "SIEMLite"
	if d.Version != "" {
		ver += " " + d.Version
	}
	ver = pdf.Ellipsize(pdf.Helvetica, 8, contW-90, ver)
	for i := 0; i < n; i++ {
		p := l.page(i)
		p.Line(marginX, pdf.PageH-46, marginX+contW, pdf.PageH-46, 0.5, colRule)
		p.Text(marginX, pdf.PageH-38, pdf.Helvetica, 8, colGrey, pdf.Left, ver)
		p.Text(marginX+contW, pdf.PageH-38, pdf.Helvetica, 8, colGrey, pdf.Right, fmt.Sprintf("Page %d of %d", i+1, n))
	}
	return l.doc.Bytes()
}

func (l *layout) page(i int) *pdf.Page { return l.doc.Page(i) }

func (l *layout) header(d *Data, title string) {
	p := l.p
	p.FillRect(marginX, l.y+1, 4, 26, colAccent)
	p.Text(marginX+14, l.y, pdf.HelveticaBold, 22, colText, pdf.Left, pdf.Ellipsize(pdf.HelveticaBold, 22, contW-14, title))
	l.y += 34
	period := stamp(d.Start) + " to " + stamp(d.End)
	p.Text(marginX, l.y, pdf.Helvetica, 10.5, colText, pdf.Left, pdf.Ellipsize(pdf.Helvetica, 10.5, contW, period))
	l.y += 16
	gen := "Generated " + stamp(d.Generated) + " by SIEMLite"
	if d.Version != "" {
		gen += " " + d.Version
	}
	if d.Host != "" {
		gen += " on " + d.Host
	}
	p.Text(marginX, l.y, pdf.Helvetica, 8.5, colGrey, pdf.Left, pdf.Ellipsize(pdf.Helvetica, 8.5, contW, gen))
	l.y += 18
	p.Line(marginX, l.y, marginX+contW, l.y, 0.8, colRule)
	l.y += 16
}

func (l *layout) stats(d *Data) {
	high := d.BySeverity[4] + d.BySeverity[5] + d.BySeverity[6]
	items := []struct {
		n     int64
		label string
	}{{d.Total, "Events"}, {high, "High or worse"}, {d.Threats, "Threat intel matches"}, {d.Alerts.Opened, "Alerts opened"}}
	const gap, h = 10.0, 56.0
	w := (contW - 3*gap) / 4
	l.ensure(h)
	for i, it := range items {
		x := marginX + float64(i)*(w+gap)
		l.p.FillRect(x, l.y, w, h, colPanel)
		l.p.FillRect(x, l.y, w, 2.5, colAccent)
		l.p.Text(x+12, l.y+13, pdf.HelveticaBold, 20, colText, pdf.Left, pdf.Ellipsize(pdf.HelveticaBold, 20, w-20, num(it.n)))
		l.p.Text(x+12, l.y+39, pdf.Helvetica, 8.5, colGrey, pdf.Left, it.label)
	}
	l.y += h
}

func (l *layout) timeline(d *Data) {
	const plotH = 100.0
	l.section("Events over time", plotH+40)
	p := l.p
	// Legend, top right of the heading row.
	lx := marginX + contW
	lx -= pdf.TextWidth(pdf.Helvetica, 8, "Threat intel matches")
	p.Text(lx, l.y-24, pdf.Helvetica, 8, colGrey, pdf.Left, "Threat intel matches")
	p.FillRect(lx-12, l.y-22.5, 8, 8, colAccent)
	lx -= 12 + pdf.TextWidth(pdf.Helvetica, 8, "Events") + 8 + 14
	p.Text(lx+12, l.y-24, pdf.Helvetica, 8, colGrey, pdf.Left, "Events")
	p.FillRect(lx, l.y-22.5, 8, 8, colTint)

	bs := d.Buckets
	var maxC int64
	for _, b := range bs {
		maxC = max(maxC, b.Count)
	}
	top := l.y + 10
	base := top + plotH
	p.Line(marginX, top, marginX+contW, top, 0.4, colRule)
	p.Text(marginX, top-10, pdf.Helvetica, 7.5, colGrey, pdf.Left, "max "+num(maxC))
	p.Line(marginX, base, marginX+contW, base, 0.8, colGrey)
	if len(bs) == 0 || maxC == 0 {
		p.Text(marginX+contW/2, top+plotH/2-5, pdf.Helvetica, 9.5, colGrey, pdf.Center, "No events in this period.")
	}
	if len(bs) > 0 {
		slot := contW / float64(len(bs))
		bw := math.Min(slot*0.72, 44)
		daily := d.BucketMs >= 24*3600_000
		labelW := 34.0
		if daily {
			labelW = 30
		}
		step := int(math.Ceil((labelW + 6) / slot))
		step = max(step, 1)
		for i, b := range bs {
			cx := marginX + slot*(float64(i)+0.5)
			if maxC > 0 {
				h := float64(b.Count) / float64(maxC) * plotH
				if b.Count > 0 {
					h = math.Max(h, 1)
					p.FillRect(cx-bw/2, base-h, bw, h, colTint)
				}
				if th := float64(min(b.Threats, b.Count)) / float64(maxC) * plotH; b.Threats > 0 {
					th = math.Max(th, 1)
					p.FillRect(cx-bw/2, base-th, bw, th, colAccent)
				}
			}
			if i%step == 0 && cx-labelW/2 >= marginX-4 && cx+labelW/2 <= marginX+contW+4 {
				t := time.UnixMilli(b.Start).In(time.Local)
				lab := t.Format("15:04")
				if daily || (t.Hour() == 0 && !daily) {
					lab = t.Format("Jan 2")
				}
				p.Text(cx, base+5, pdf.Helvetica, 7.5, colGrey, pdf.Center, lab)
			}
		}
	}
	l.y = base + 20
}

func (l *layout) severities(d *Data) {
	var rows []int
	var sum, maxN int64
	for s := 1; s <= 6; s++ {
		if n := d.BySeverity[s]; n > 0 {
			rows = append(rows, s)
			sum += n
			maxN = max(maxN, n)
		}
	}
	const rowH = 19.0
	l.section("Events by severity", math.Max(1, float64(len(rows)))*rowH)
	if len(rows) == 0 {
		l.none()
		return
	}
	total := d.Total
	if total < sum {
		total = sum
	}
	barX, barW := marginX+90, 270.0
	for _, s := range rows {
		n := d.BySeverity[s]
		y := l.y
		l.p.Text(marginX, y+2, pdf.Helvetica, 9.5, colText, pdf.Left, SeverityName(s))
		l.p.FillRect(barX, y+1, barW, 12, colTrack)
		l.p.FillRect(barX, y+1, math.Max(2, barW*float64(n)/float64(maxN)), 12, sevColor(s))
		l.p.Text(barX+barW+14, y+2, pdf.HelveticaBold, 9.5, colText, pdf.Left, num(n))
		pct := fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total))
		if 100*float64(n)/float64(total) < 0.1 {
			pct = "<0.1%"
		}
		l.p.Text(marginX+contW, y+2, pdf.Helvetica, 9.5, colGrey, pdf.Right, pct)
		l.y += rowH
	}
}

// rankRow is one line of a ranked list.
type rankRow struct {
	name, sub string
	n         int64
}

// ranked draws rows with a rank, a name, an optional second column and a small bar, in a column x..x+w.
func (l *layout) ranked(x, w float64, rows []rankRow, y float64) float64 {
	var maxN int64
	hasSub := false
	for _, r := range rows {
		maxN = max(maxN, r.n)
		hasSub = hasSub || r.sub != ""
	}
	nameW := w * 0.42
	subW := 0.0
	if hasSub {
		nameW, subW = w*0.26, w*0.18
	}
	barX := x + 18 + nameW + subW + 6
	cntW := 44.0
	barW := x + w - cntW - barX
	for i, r := range rows {
		l.p.Text(x, y+1.5, pdf.Helvetica, 8.5, colGrey, pdf.Left, strconv.Itoa(i+1))
		l.p.Text(x+18, y+1.5, pdf.Helvetica, 9, colText, pdf.Left, pdf.Ellipsize(pdf.Helvetica, 9, nameW-6, r.name))
		if hasSub {
			l.p.Text(x+18+nameW, y+1.5, pdf.Helvetica, 9, colGrey, pdf.Left, pdf.Ellipsize(pdf.Helvetica, 9, subW-6, r.sub))
		}
		l.p.FillRect(barX, y+2, barW, 8, colTrack)
		if maxN > 0 && r.n > 0 {
			l.p.FillRect(barX, y+2, math.Max(1.5, barW*float64(r.n)/float64(maxN)), 8, colAccent)
		}
		l.p.Text(x+w, y+1.5, pdf.HelveticaBold, 9, colText, pdf.Right, num(r.n))
		y += 16
	}
	return y
}

func namedRows(in []storage.NamedCount) []rankRow {
	var rows []rankRow
	for i, c := range in {
		if i == maxRanked {
			break
		}
		rows = append(rows, rankRow{name: c.Name, n: c.Count})
	}
	return rows
}

func (l *layout) sourcesAndCountries(d *Data) {
	src, cty := namedRows(d.TopSources), namedRows(d.TopCountry)
	rowsN := max(len(src), len(cty), 1)
	need := 16*float64(rowsN) + 14
	if l.p != nil && l.y > topY+0.1 {
		l.y += 18
	}
	l.ensure(24 + need)
	const gap = 28.0
	w := (contW - gap) / 2
	for i, t := range []string{"Top sources", "Top countries"} {
		x := marginX + float64(i)*(w+gap)
		l.p.Text(x, l.y, pdf.HelveticaBold, 11.5, colText, pdf.Left, t)
		l.p.Line(x, l.y+17, x+w, l.y+17, 0.5, colRule)
	}
	y := l.y + 26
	end := y
	for i, rows := range [][]rankRow{src, cty} {
		x := marginX + float64(i)*(w+gap)
		if len(rows) == 0 {
			l.p.Text(x, y, pdf.Helvetica, 9.5, colGrey, pdf.Left, "None in this period.")
			end = math.Max(end, y+14)
			continue
		}
		end = math.Max(end, l.ranked(x, w, rows, y))
	}
	l.y = end
}

func (l *layout) threats(d *Data) {
	var rows []rankRow
	for i, t := range d.TopThreats {
		if i == maxRanked {
			break
		}
		rows = append(rows, rankRow{name: t.IP, sub: t.Country, n: t.Count})
	}
	l.section("Threat-listed addresses", 16*math.Max(1, float64(len(rows))))
	if len(rows) == 0 {
		l.none()
		return
	}
	l.y = l.ranked(marginX, contW, rows, l.y)
}

var groupLabels = map[string]string{"src_ip": "Source IP", "dst_ip": "Destination IP", "user": "User", "host": "Host", "source": "Source"}

func (l *layout) alerts(d *Data) {
	a := d.Alerts
	// Totals line.
	var sev []string
	for s := 6; s >= 0; s-- {
		if n := a.BySeverity[s]; n > 0 {
			sev = append(sev, fmt.Sprintf("%s %s", SeverityName(s), num(n)))
		}
	}
	var statuses []string
	for k := range a.ByStatus {
		statuses = append(statuses, k)
	}
	sort.Strings(statuses)
	var st []string
	for _, k := range statuses {
		if n := a.ByStatus[k]; n > 0 {
			st = append(st, fmt.Sprintf("%s %s", capital(k), num(n)))
		}
	}
	var lines []string
	if len(sev) > 0 {
		lines = append(lines, pdf.Wrap(pdf.Helvetica, 9, contW, "By severity: "+strings.Join(sev, ", "))...)
	}
	if len(st) > 0 {
		lines = append(lines, pdf.Wrap(pdf.Helvetica, 9, contW, "By status: "+strings.Join(st, ", "))...)
	}
	const headH, rowH = 20.0, 16.5
	first := headH + rowH
	if len(a.List) == 0 {
		first = 14
	}
	need := first
	if len(lines) > 0 {
		need += 13 + 4
	}
	l.section("Alerts opened", need)
	for _, ln := range lines {
		l.ensure(13)
		l.p.Text(marginX, l.y, pdf.Helvetica, 9, colText, pdf.Left, ln)
		l.y += 13
	}
	if len(lines) > 0 {
		l.y += 4
	}
	if len(a.List) == 0 {
		if a.Opened == 0 {
			l.none()
		}
		return
	}
	cols := []struct {
		title string
		w     float64
		right bool
	}{{"SEVERITY", 50, false}, {"RULE", 136, false}, {"WHO / WHAT", 122, false}, {"EVENTS", 38, true}, {"STATUS", 72, false}, {"OPENED", 97.28, false}}
	header := func() {
		l.p.FillRect(marginX, l.y, contW, headH, colPanel)
		x := marginX
		for _, c := range cols {
			if c.right {
				l.p.Text(x+c.w-8, l.y+6.5, pdf.HelveticaBold, 7, colGrey, pdf.Right, c.title)
			} else {
				l.p.Text(x+8, l.y+6.5, pdf.HelveticaBold, 7, colGrey, pdf.Left, c.title)
			}
			x += c.w
		}
		l.y += headH
	}
	header()
	for _, al := range a.List {
		if l.y+rowH > bottomY {
			l.newPage()
			header()
		}
		value := al.GroupValue
		if al.GroupLabel != "" {
			value = al.GroupLabel
		}
		who := value
		if lab, ok := groupLabels[al.GroupBy]; ok {
			who = lab + ": " + value
		} else if al.GroupBy != "" {
			who = al.GroupBy + ": " + value
		}
		rule := al.RuleName
		if rule == "" {
			rule = "(raised by hand)"
		}
		cells := []string{SeverityName(al.Severity), rule, who, num(al.Count), capital(al.Status), stamp(al.CreatedAt)}
		x := marginX
		for i, c := range cols {
			font, col := pdf.Helvetica, colText
			if i == 0 {
				font, col = pdf.HelveticaBold, sevColor(al.Severity)
			}
			txt := pdf.Ellipsize(font, 8.5, c.w-12, cells[i])
			if c.right {
				l.p.Text(x+c.w-8, l.y+4.5, font, 8.5, col, pdf.Right, txt)
			} else {
				l.p.Text(x+8, l.y+4.5, font, 8.5, col, pdf.Left, txt)
			}
			x += c.w
		}
		l.y += rowH
		l.p.Line(marginX, l.y, marginX+contW, l.y, 0.4, colRule)
	}
	if a.More > 0 {
		l.ensure(20)
		l.y += 8
		l.p.Text(marginX, l.y, pdf.Helvetica, 9, colGrey, pdf.Left, fmt.Sprintf("\u2026 and %s more alerts not listed.", num(a.More)))
		l.y += 12
	}
}

func (l *layout) feeds(d *Data) {
	l.section("Threat feeds in use", 14)
	if len(d.Feeds) == 0 {
		l.ensure(14)
		l.p.Text(marginX, l.y, pdf.Helvetica, 9.5, colGrey, pdf.Left, "No feeds are turned on.")
		l.y += 14
		return
	}
	names := d.Feeds
	extra := 0
	if len(names) > 60 {
		extra = len(names) - 60
		names = names[:60]
	}
	text := strings.Join(names, ", ")
	if extra > 0 {
		text += fmt.Sprintf(", and %d more", extra)
	}
	for _, ln := range pdf.Wrap(pdf.Helvetica, 9.5, contW, text) {
		l.ensure(14)
		l.p.Text(marginX, l.y, pdf.Helvetica, 9.5, colText, pdf.Left, ln)
		l.y += 14
	}
}
