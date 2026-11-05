// Package audit records what people and SIEMLite itself do (sign-ins,
// changes to users, sources, parsers, backups and alerts) as ordinary
// events from the built-in INTERNAL source, so the audit log is searched,
// filtered, alerted on and retained like every other log.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"siemlite/pkg/ingest"
	"siemlite/pkg/ocsf"
	"siemlite/pkg/storage"
)

// OCSF classes used for audit events.
const (
	Authentication = 3002 // sign-in, sign-out
	AccountChange  = 3001 // users and their access
	APIActivity    = 6003 // everything else changed through SIEMLite
)

// Entry is one audited action.
type Entry struct {
	Action   string // short machine name, e.g. "user.create"
	Message  string // what happened, in a sentence
	Actor    string // who did it
	IP       string // where from, if known
	Class    int    // default APIActivity
	Severity int    // default informational
	Fields   map[string]string
}

// Submitter stores events; *ingest.Worker satisfies it.
type Submitter interface {
	SubmitWith(ctx context.Context, ev *ocsf.Event, opts ingest.SubmitOptions) error
}

// SourceFinder resolves the INTERNAL source.
type SourceFinder interface {
	Builtin(ctx context.Context, kind string) (int64, error)
}

// Logger records entries. A nil Logger records nothing.
type Logger struct {
	submit  Submitter
	sources SourceFinder
	log     *slog.Logger
	host    string
}

// New returns a Logger.
func New(submit Submitter, sources SourceFinder, log *slog.Logger) *Logger {
	if log == nil {
		log = slog.Default()
	}
	host, _ := os.Hostname()
	return &Logger{submit: submit, sources: sources, log: log, host: host}
}

// Event builds the OCSF event for an entry.
func Event(e Entry, host string, now time.Time) *ocsf.Event {
	if e.Class == 0 {
		e.Class = APIActivity
	}
	if e.Severity == 0 {
		e.Severity = ocsf.SeverityInformational
	}
	ev := &ocsf.Event{
		Time: now.UnixMilli(), CategoryUID: e.Class / 1000, ClassUID: e.Class, ActivityID: 99,
		SeverityID: e.Severity, Message: e.Message,
		Metadata: ocsf.Metadata{Product: &ocsf.Product{Name: "SIEMLite", VendorName: "SIEMLite"}},
	}
	if e.Actor != "" {
		ev.Actor = &ocsf.Actor{User: &ocsf.User{Name: e.Actor}}
	}
	if e.IP != "" {
		ev.SrcEndpoint = &ocsf.Endpoint{IP: e.IP}
	}
	if host != "" {
		ev.Device = &ocsf.Endpoint{Hostname: host}
	}
	return ev
}

// Record stores an entry. It never fails the caller: problems are logged.
func (l *Logger) Record(ctx context.Context, e Entry) {
	if l == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	id, err := l.sources.Builtin(ctx, storage.SourceInternal)
	if err != nil {
		l.log.Error("audit: no INTERNAL source", "err", err)
		return
	}
	fields := make(map[string]string, len(e.Fields)+1)
	for k, v := range e.Fields {
		fields[k] = v
	}
	// Set last: no field an entry carries can change what the event is. Rules, and the guard that keeps
	// them from counting SIEMLite's own alert events, read this to tell events apart.
	fields["action"] = e.Action
	if err := l.submit.SubmitWith(ctx, Event(e, l.host, time.Now()), ingest.SubmitOptions{SourceID: id, Fields: fields}); err != nil {
		l.log.Error("audit: event not stored", "action", e.Action, "err", err)
	}
}

// LateBatch records a mass ingestion of late events from one source (see
// pkg/ingest) as a High event; the built-in rule "Mass ingestion of late
// logs" turns it into an alert. The events themselves keep their severity.
func (l *Logger) LateBatch(ctx context.Context, source string, b ingest.LateBatch, retentionDays int) {
	msg := fmt.Sprintf("Mass ingestion of late logs: %d events more than %d days old from %s, dated %s to %s",
		b.Stored+b.Refused, int(ingest.LateAfter.Hours()/24), source, b.Oldest.UTC().Format("2006-01-02"), b.Newest.UTC().Format("2006-01-02"))
	if b.Refused > 0 {
		msg += fmt.Sprintf(" (%d stored, %d refused as older than the %d days events are kept)", b.Stored, b.Refused, retentionDays)
	}
	l.Record(ctx, Entry{Action: "ingest.late", Actor: source, Severity: ocsf.SeverityHigh, Message: msg + ".",
		Fields: map[string]string{"source": source, "stored": strconv.Itoa(b.Stored), "refused": strconv.Itoa(b.Refused),
			"oldest": b.Oldest.UTC().Format(time.RFC3339), "newest": b.Newest.UTC().Format(time.RFC3339)}})
}
