package report

import (
	"fmt"
	"os"
	"testing"
	"time"

	"siemlite/pkg/storage"
)

// sampleData is a rich, realistic week.
func sampleData() *Data {
	loc := time.Local
	end := time.Date(2026, 11, 18, 0, 0, 0, 0, loc)
	start := end.AddDate(0, 0, -7)
	d := &Data{
		Title: "SIEMLite security report", Start: start.UnixMilli(), End: end.UnixMilli(),
		Generated: time.Date(2026, 11, 18, 8, 30, 0, 0, loc).UnixMilli(), Version: "v0.52", Host: "siem-edge-01",
		BucketMs:   24 * 3600_000,
		BySeverity: map[int]int64{1: 61240, 2: 18310, 3: 4120, 4: 912, 5: 143, 6: 7},
	}
	counts := []int64{10420, 12100, 9800, 15230, 14870, 11050, 10100}
	threats := []int64{120, 340, 90, 760, 410, 150, 133}
	for i, c := range counts {
		d.Buckets = append(d.Buckets, storage.Bucket{Start: start.AddDate(0, 0, i).UnixMilli(), Count: c, Threats: threats[i]})
		d.Total += c
		d.Threats += threats[i]
	}
	for i, n := range []string{"10.20.4.17", "10.20.4.52", "192.168.1.10", "172.16.8.3", "10.20.9.200", "192.168.7.44", "203.0.113.9", "fw-edge-01.corp.example.com"} {
		d.TopSources = append(d.TopSources, storage.NamedCount{Name: n, Count: int64(20000 / (i + 1))})
	}
	for i, n := range []string{"United States", "Germany", "China", "Russia", "Brazil", "Netherlands"} {
		d.TopCountry = append(d.TopCountry, storage.NamedCount{Name: n, Count: int64(30000 / (i + 1))})
	}
	for i, ip := range []string{"185.220.101.4", "45.155.205.233", "91.240.118.172", "194.26.135.80", "103.75.201.2", "162.142.125.9"} {
		d.TopThreats = append(d.TopThreats, storage.ThreatSummary{IP: ip, Country: []string{"Germany", "Russia", "Russia", "Netherlands", "India", "United States"}[i], Count: int64(400 / (i + 1))})
	}
	rules := []string{"SSH brute force", "Impossible travel login", "Threat-listed address contacted", "Port scan detected", "Admin account created", "Large outbound transfer", "Malware beacon pattern"}
	groups := []string{"src_ip", "user", "host", "dst_ip"}
	vals := []string{"185.220.101.4", "m.okafor", "db-prod-02", "203.0.113.77", "45.155.205.233", "j.lindqvist"}
	statuses := []string{"open", "acknowledged", "resolved", "open", "closed"}
	sevs := []int{6, 5, 5, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 5, 4, 3, 2, 4, 3, 3, 2, 2, 4, 3, 5}
	sevCount := map[int]int64{}
	stCount := map[string]int64{}
	for i, s := range sevs {
		st := statuses[i%len(statuses)]
		d.Alerts.List = append(d.Alerts.List, storage.Alert{
			ID: int64(i + 1), RuleName: rules[i%len(rules)], Severity: s, GroupBy: groups[i%len(groups)], GroupValue: vals[i%len(vals)],
			Status: st, Count: int64(5 + i*13), CreatedAt: start.Add(time.Duration(i*6)*time.Hour + 17*time.Minute).UnixMilli(),
		})
		sevCount[s]++
		stCount[st]++
	}
	d.Alerts.Opened = int64(len(sevs)) + 12
	d.Alerts.More = 12
	d.Alerts.BySeverity, d.Alerts.ByStatus = sevCount, stCount
	d.Alerts.BySeverity[2] += 12
	d.Alerts.ByStatus["open"] += 12
	d.Feeds = []string{"Spamhaus DROP", "Feodo Tracker botnet C2", "Emerging Threats compromised IPs"}
	return d
}

func TestWriteSampleReport(t *testing.T) {
	path := os.Getenv("SIEMLITE_SAMPLE_PDF")
	if path == "" {
		t.Skip("SIEMLITE_SAMPLE_PDF not set")
	}
	b, err := sampleData().PDF()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Println("wrote", path, len(b), "bytes")
}
