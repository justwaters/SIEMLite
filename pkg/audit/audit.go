// Package audit records what people and SIEMLite itself do (sign-ins,
// changes to users, sources, parsers, backups and alerts) as ordinary
// events from the built-in INTERNAL source, so the audit log is searched,
// filtered, alerted on and retained like every other log.
package audit

import (
	"context"
	"log/slog"
	"os"
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
	fields := map[string]string{"action": e.Action}
	for k, v := range e.Fields {
		fields[k] = v
	}
	if err := l.submit.SubmitWith(ctx, Event(e, l.host, time.Now()), ingest.SubmitOptions{SourceID: id, Fields: fields}); err != nil {
		l.log.Error("audit: event not stored", "action", e.Action, "err", err)
	}
}
