// Package enrich adds context to events as they are ingested: GeoIP and ASN
// for their IP addresses, and threat intel matches (see pkg/intel). Field
// names follow OCSF (location, autonomous_system).
package enrich

import "siemlite/pkg/ocsf"

// Enricher adds what it knows about ev to d. It must be safe for concurrent
// use and must not modify ev.
type Enricher interface {
	Enrich(ev *ocsf.Event, d *Data)
}

// Chain runs enrichers in order.
type Chain []Enricher

// Enrich implements Enricher.
func (c Chain) Enrich(ev *ocsf.Event, d *Data) {
	for _, e := range c {
		e.Enrich(ev, d)
	}
}

// Data is the enrichment document stored alongside an event.
type Data struct {
	Src         *Endpoint    `json:"src_endpoint,omitempty"`
	Dst         *Endpoint    `json:"dst_endpoint,omitempty"`
	ThreatIntel []IntelMatch `json:"threat_intel,omitempty"`
}

// Empty reports whether nothing was added.
func (d *Data) Empty() bool {
	return d.Src == nil && d.Dst == nil && len(d.ThreatIntel) == 0
}

// Endpoint is what is known about one IP address.
type Endpoint struct {
	Location         *Location         `json:"location,omitempty"`
	AutonomousSystem *AutonomousSystem `json:"autonomous_system,omitempty"`
}

// Location is an OCSF location object.
type Location struct {
	City      string `json:"city,omitempty"`
	Country   string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	Continent string `json:"continent,omitempty"`
	// Coordinates are [longitude, latitude], as OCSF specifies.
	Coordinates []float64 `json:"coordinates,omitempty"`
}

// AutonomousSystem is an OCSF autonomous_system object.
type AutonomousSystem struct {
	Number int    `json:"number,omitempty"`
	Name   string `json:"name,omitempty"`
}

// IntelMatch records one threat intel indicator found in an event.
type IntelMatch struct {
	Type        string `json:"type"`  // ip, cidr, domain or hash
	Value       string `json:"value"` // the indicator as listed
	Matched     string `json:"matched,omitempty"`
	Field       string `json:"field"` // where it was found, e.g. src_endpoint.ip or raw_data
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
}

// Country returns the endpoint's country code or "".
func (e *Endpoint) Country() string {
	if e == nil || e.Location == nil {
		return ""
	}
	return e.Location.Country
}

// ASN returns the endpoint's autonomous system number or 0.
func (e *Endpoint) ASN() int {
	if e == nil || e.AutonomousSystem == nil {
		return 0
	}
	return e.AutonomousSystem.Number
}
