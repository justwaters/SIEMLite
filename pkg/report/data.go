// Package report builds the security summary SIEMLite can show, download as a PDF, and send on a
// schedule: what happened over a period, from the events, alerts and threat lists already stored.
package report

import (
	"context"
	"fmt"
	"time"

	"siemlite/pkg/storage"
)

// MaxAlertRows is how many alerts a report lists; the rest are only counted.
const MaxAlertRows = 40

// Data is everything a report says. The PDF and the page both draw from it.
type Data struct {
	Title     string `json:"title"`
	Start     int64  `json:"start"` // the period, in milliseconds since 1970
	End       int64  `json:"end"`
	Generated int64  `json:"generated"`
	Version   string `json:"version"`
	Host      string `json:"host,omitempty"`

	Total      int64                   `json:"total"`   // events in the period
	Threats    int64                   `json:"threats"` // of which matched a threat list
	BySeverity map[int]int64           `json:"by_severity"`
	BucketMs   int64                   `json:"bucket_ms"`
	Buckets    []storage.Bucket        `json:"buckets"` // oldest first
	TopSources []storage.NamedCount    `json:"top_sources"`
	TopCountry []storage.NamedCount    `json:"top_countries"`
	TopThreats []storage.ThreatSummary `json:"top_threat_ips"`

	Alerts AlertSummary `json:"alerts"`
	// Feeds are the threat lists in use, by name.
	Feeds []string `json:"feeds"`
}

// AlertSummary is the alerts opened in the period.
type AlertSummary struct {
	Opened     int64            `json:"opened"`
	BySeverity map[int]int64    `json:"by_severity"`
	ByStatus   map[string]int64 `json:"by_status"`
	List       []storage.Alert  `json:"list"` // most serious first, at most MaxAlertRows
	More       int64            `json:"more"` // opened but not listed
}

// Source is what Build reads.
type Source interface {
	Overview(ctx context.Context, startMs, endMs, bucketMs int64, f storage.Filter) (*storage.Overview, error)
	AlertsInRange(ctx context.Context, fromMs, toMs int64, limit int) ([]storage.Alert, int64, map[int]int64, map[string]int64, error)
}

// Build reads the period [start, end) (milliseconds). Bars are an hour wide for a day or two, a day
// wide for longer. feeds names the threat lists in use.
func Build(ctx context.Context, src Source, start, end int64, version, host string, feeds []string, now time.Time) (*Data, error) {
	if end <= start {
		return nil, fmt.Errorf("the report period ends before it starts")
	}
	bucket := time.Hour
	if end-start > 2*24*3600_000 {
		bucket = 24 * time.Hour
	}
	// Align the first bar to the bucket so every bar is whole.
	b := bucket.Milliseconds()
	alignedStart := start - ((start%b)+b)%b
	alignedEnd := end
	if rem := (alignedEnd - alignedStart) % b; rem != 0 {
		alignedEnd += b - rem
	}
	ov, err := src.Overview(ctx, alignedStart, alignedEnd, b, storage.Filter{})
	if err != nil {
		return nil, err
	}
	list, total, bySev, byStatus, err := src.AlertsInRange(ctx, start, end, MaxAlertRows)
	if err != nil {
		return nil, err
	}
	d := &Data{
		Title: "SIEMLite security report", Start: start, End: end, Generated: now.UnixMilli(), Version: version, Host: host,
		Total: ov.Total, Threats: ov.Threats, BySeverity: ov.BySeverity, BucketMs: b, Buckets: ov.Buckets,
		TopSources: ov.TopSources, TopCountry: ov.TopCountry, TopThreats: ov.TopThreats, Feeds: feeds,
		Alerts: AlertSummary{Opened: total, BySeverity: bySev, ByStatus: byStatus, List: list, More: max(0, total-int64(len(list)))},
	}
	if d.BySeverity == nil {
		d.BySeverity = map[int]int64{}
	}
	return d, nil
}

// SeverityName is the word for an OCSF severity.
func SeverityName(n int) string {
	switch n {
	case 0:
		return "Unknown"
	case 1:
		return "Informational"
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	case 6:
		return "Fatal"
	}
	return "Other"
}

// Text is a short plain-text summary, used as the body of the email a scheduled report is sent in.
func (d *Data) Text() string {
	loc := time.Local
	span := fmt.Sprintf("%s to %s", time.UnixMilli(d.Start).In(loc).Format("Jan 2, 2006 15:04"), time.UnixMilli(d.End).In(loc).Format("Jan 2, 2006 15:04"))
	high := d.BySeverity[4] + d.BySeverity[5] + d.BySeverity[6]
	s := fmt.Sprintf("%s\n%s\n\nEvents: %d\nHigh or worse: %d\nThreat intel matches: %d\nAlerts opened: %d\n", d.Title, span, d.Total, high, d.Threats, d.Alerts.Opened)
	for sev := 6; sev >= 2; sev-- {
		if n := d.Alerts.BySeverity[sev]; n > 0 {
			s += fmt.Sprintf("  %s: %d\n", SeverityName(sev), n)
		}
	}
	if len(d.TopThreats) > 0 {
		s += "\nMost active threat-listed addresses:\n"
		for i, t := range d.TopThreats {
			if i == 5 {
				break
			}
			s += fmt.Sprintf("  %s (%d events)\n", t.IP, t.Count)
		}
	}
	return s + "\nThe full report is attached as a PDF.\n"
}
