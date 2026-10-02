// Package ocsf defines a compact subset of the Open Cybersecurity Schema
// Framework (OCSF) v1.x event model, plus validation and normalization.
package ocsf

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// SchemaVersion is the OCSF version stamped on events that omit one.
const SchemaVersion = "1.3.0"

// OCSF category_uid values.
const (
	CategorySystemActivity      = 1
	CategoryFindings            = 2
	CategoryIAM                 = 3
	CategoryNetworkActivity     = 4
	CategoryDiscovery           = 5
	CategoryApplicationActivity = 6
	CategoryRemediation         = 7
	CategoryUnmanagedDevices    = 8
)

// OCSF severity_id values.
const (
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
	SeverityOther         = 99
)

// Event is a normalized OCSF event. Time is epoch milliseconds.
type Event struct {
	Time        int64     `json:"time"`
	CategoryUID int       `json:"category_uid"`
	ClassUID    int       `json:"class_uid"`
	ActivityID  int       `json:"activity_id"`
	TypeUID     int       `json:"type_uid,omitempty"`
	SeverityID  int       `json:"severity_id"`
	StatusID    int       `json:"status_id,omitempty"`
	Message     string    `json:"message,omitempty"`
	Metadata    Metadata  `json:"metadata"`
	SrcEndpoint *Endpoint `json:"src_endpoint,omitempty"`
	DstEndpoint *Endpoint `json:"dst_endpoint,omitempty"`
	// Device is the host that reported the event (e.g. the syslog sender),
	// as opposed to the endpoints the event is about.
	Device   *Endpoint      `json:"device,omitempty"`
	Actor    *Actor         `json:"actor,omitempty"`
	Unmapped map[string]any `json:"unmapped,omitempty"`
	// RawData is the original log line. When empty, Prepare fills it with the
	// JSON encoding of the event so full-text search still has content.
	RawData string `json:"raw_data,omitempty"`
}

// Metadata describes the event's schema version and producing product.
type Metadata struct {
	Version string   `json:"version"`
	Product *Product `json:"product,omitempty"`
}

// Product identifies the sensor or application that produced the event.
type Product struct {
	Name       string `json:"name,omitempty"`
	VendorName string `json:"vendor_name,omitempty"`
}

// Endpoint is a network endpoint (src_endpoint / dst_endpoint).
type Endpoint struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// Actor is the entity that performed the activity.
type Actor struct {
	User *User `json:"user,omitempty"`
}

// User is an OCSF user object.
type User struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// ValidationError reports the first field that failed validation.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason)
}

// SrcIP returns the source IP or "".
func (e *Event) SrcIP() string {
	if e.SrcEndpoint == nil {
		return ""
	}
	return e.SrcEndpoint.IP
}

// DstIP returns the destination IP or "".
func (e *Event) DstIP() string {
	if e.DstEndpoint == nil {
		return ""
	}
	return e.DstEndpoint.IP
}

// ProductName returns the producing product's name or "".
func (e *Event) ProductName() string {
	if e.Metadata.Product == nil {
		return ""
	}
	return e.Metadata.Product.Name
}

// DeviceName returns the reporting device's hostname, else its IP, or "".
func (e *Event) DeviceName() string {
	if e.Device == nil {
		return ""
	}
	if e.Device.Hostname != "" {
		return e.Device.Hostname
	}
	return e.Device.IP
}

// UserName returns the acting user's name or "".
func (e *Event) UserName() string {
	if e.Actor == nil || e.Actor.User == nil {
		return ""
	}
	return e.Actor.User.Name
}

// Validate checks the event against the constraints SIEMLite relies on.
func (e *Event) Validate() error {
	if e.Time <= 0 {
		return &ValidationError{"time", "must be a positive epoch-millisecond timestamp"}
	}
	if e.CategoryUID < CategorySystemActivity || e.CategoryUID > CategoryUnmanagedDevices {
		return &ValidationError{"category_uid", "must be between 1 and 8"}
	}
	if e.ClassUID <= 0 {
		return &ValidationError{"class_uid", "must be positive"}
	}
	if e.ClassUID/1000 != e.CategoryUID {
		return &ValidationError{"class_uid", fmt.Sprintf("%d does not belong to category_uid %d", e.ClassUID, e.CategoryUID)}
	}
	if !validSeverity(e.SeverityID) {
		return &ValidationError{"severity_id", "must be 0-6 or 99"}
	}
	if err := validateIP("src_endpoint.ip", e.SrcIP()); err != nil {
		return err
	}
	if err := validateIP("dst_endpoint.ip", e.DstIP()); err != nil {
		return err
	}
	if e.Device != nil {
		return validateIP("device.ip", e.Device.IP)
	}
	return nil
}

// Prepare normalizes the event (defaults for time, version, type_uid, raw
// data) and then validates it.
func (e *Event) Prepare() error {
	if e.Time == 0 {
		e.Time = time.Now().UnixMilli()
	}
	if e.Metadata.Version == "" {
		e.Metadata.Version = SchemaVersion
	}
	if e.TypeUID == 0 && e.ClassUID > 0 {
		e.TypeUID = e.ClassUID*100 + e.ActivityID
	}
	if err := e.Validate(); err != nil {
		return err
	}
	if e.RawData == "" {
		b, err := json.Marshal(e)
		if err != nil {
			return &ValidationError{"unmapped", err.Error()}
		}
		e.RawData = string(b)
	}
	return nil
}

func validateIP(field, ip string) error {
	if ip == "" {
		return nil
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return &ValidationError{field, "not a valid IP address"}
	}
	return nil
}

func validSeverity(id int) bool {
	return (id >= SeverityUnknown && id <= SeverityFatal) || id == SeverityOther
}
