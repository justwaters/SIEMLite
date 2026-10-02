// Package search combines time-window, OCSF field and FTS5 filters.
package search

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"siemlite/pkg/storage"
)

const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// InvalidQueryError marks a caller mistake (bad bounds, malformed FTS5
// syntax) as opposed to an internal failure.
type InvalidQueryError struct{ Reason string }

func (e *InvalidQueryError) Error() string { return "invalid query: " + e.Reason }

// Query is a unified search request. Zero values mean "no constraint".
type Query struct {
	Start, End time.Time

	CategoryUID *int
	ClassUID    *int
	SeverityID  *int
	SrcIP       string
	DstIP       string
	UserName    string
	Source      string
	Host        string
	Country     string // ISO country code of either endpoint
	ASN         int    // autonomous system number of either endpoint
	ThreatOnly  bool   // only events that matched threat intel

	// Text is a raw FTS5 expression, e.g. `failed AND "invalid user"`.
	Text string

	Limit  int // default 100, max 1000
	Offset int
}

// Result is a page of matching events, newest first.
type Result struct {
	Events []storage.Record `json:"events"`
	Count  int              `json:"count"`
	Limit  int              `json:"limit"`
	Offset int              `json:"offset"`
	TookMs float64          `json:"took_ms"`
}

// Engine executes searches against a repository.
type Engine struct {
	repo *storage.Repository
}

// NewEngine returns an Engine over repo.
func NewEngine(repo *storage.Repository) *Engine { return &Engine{repo: repo} }

// Search validates q and runs it.
func (e *Engine) Search(ctx context.Context, q Query) (*Result, error) {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	switch {
	case q.Limit < 0 || q.Limit > MaxLimit:
		return nil, &InvalidQueryError{fmt.Sprintf("limit must be between 1 and %d", MaxLimit)}
	case q.Offset < 0:
		return nil, &InvalidQueryError{"offset must not be negative"}
	case !q.Start.IsZero() && !q.End.IsZero() && q.End.Before(q.Start):
		return nil, &InvalidQueryError{"end is before start"}
	}

	f := storage.Filter{
		CategoryUID: q.CategoryUID,
		ClassUID:    q.ClassUID,
		SeverityID:  q.SeverityID,
		SrcIP:       q.SrcIP,
		DstIP:       q.DstIP,
		UserName:    q.UserName,
		Source:      q.Source,
		Host:        q.Host,
		Country:     strings.ToUpper(strings.TrimSpace(q.Country)),
		ASN:         q.ASN,
		ThreatOnly:  q.ThreatOnly,
		Match:       strings.TrimSpace(q.Text),
		Limit:       q.Limit,
		Offset:      q.Offset,
	}
	if !q.Start.IsZero() {
		f.StartMs = q.Start.UnixMilli()
	}
	if !q.End.IsZero() {
		f.EndMs = q.End.UnixMilli()
	}

	began := time.Now()
	events, err := e.repo.Search(ctx, f)
	if err != nil {
		if isFTSSyntaxError(err) {
			return nil, &InvalidQueryError{"malformed full-text expression: " + err.Error()}
		}
		return nil, err
	}
	return &Result{
		Events: events,
		Count:  len(events),
		Limit:  q.Limit,
		Offset: q.Offset,
		TookMs: float64(time.Since(began).Microseconds()) / 1000,
	}, nil
}

// isFTSSyntaxError recognizes SQLite errors caused by a bad MATCH expression.
func isFTSSyntaxError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "fts5:") ||
		strings.Contains(msg, "no such column") ||
		strings.Contains(msg, "unterminated string")
}
