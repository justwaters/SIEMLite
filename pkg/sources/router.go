// Package sources decides how lines from each source are parsed: with the
// parser assigned to the source on the Sources page, or automatically.
package sources

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"siemlite/pkg/ocsf"
	"siemlite/pkg/parser"
	"siemlite/pkg/storage"
)

// cacheTTL bounds how long a source's parser is reused before it is looked
// up again; Invalidate clears it immediately after a change in this process.
const cacheTTL = 15 * time.Second

// Router parses lines for a source. It is safe for concurrent use.
type Router struct {
	repo *storage.Repository

	mu      sync.Mutex
	cache   map[int64]cached
	builtin map[string]int64
}

type cached struct {
	p       *parser.Parser
	name    string
	none    bool // keep lines as they arrive, with no detection
	expires time.Time
}

// New returns a Router.
func New(repo *storage.Repository) *Router {
	return &Router{repo: repo, cache: map[int64]cached{}, builtin: map[string]int64{}}
}

// Invalidate forgets cached parsers after a source or parser changes.
func (r *Router) Invalidate() {
	r.mu.Lock()
	r.cache = map[int64]cached{}
	r.mu.Unlock()
}

// Builtin returns the id of the syslog, upload or INTERNAL source.
func (r *Router) Builtin(ctx context.Context, kind string) (int64, error) {
	r.mu.Lock()
	id, ok := r.builtin[kind]
	r.mu.Unlock()
	if ok {
		return id, nil
	}
	s, err := r.repo.BuiltinSource(ctx, kind)
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.builtin[kind] = s.ID
	r.mu.Unlock()
	return s.ID, nil
}

// parserFor returns the source's parser, or nil for automatic parsing. none
// is true when the source keeps its lines as they arrive instead.
func (r *Router) parserFor(ctx context.Context, sourceID int64) (p *parser.Parser, name string, none bool, err error) {
	now := time.Now()
	r.mu.Lock()
	c, ok := r.cache[sourceID]
	r.mu.Unlock()
	if ok && now.Before(c.expires) {
		return c.p, c.name, c.none, nil
	}
	c = cached{expires: now.Add(cacheTTL)}
	src, err := r.repo.GetSource(ctx, sourceID)
	if err != nil && !errors.Is(err, storage.ErrSourceNotFound) {
		return nil, "", false, err
	}
	if src != nil && src.ParserNone {
		c.none = true
	}
	if src != nil && src.ParserID != nil {
		sp, err := r.repo.GetParser(ctx, *src.ParserID)
		if err != nil && !errors.Is(err, storage.ErrParserNotFound) {
			return nil, "", false, err
		}
		if sp != nil {
			var def parser.Definition
			if err := json.Unmarshal([]byte(sp.Definition), &def); err == nil {
				def.Name = sp.Name
				if p, err := parser.Compile(def); err == nil {
					c.p, c.name = p, sp.Name
				}
			}
		}
	}
	r.mu.Lock()
	r.cache[sourceID] = c
	r.mu.Unlock()
	return c.p, c.name, c.none, nil
}

// Parse turns one line from a source into an event plus any extra fields.
// A source set to None keeps each line as it is. A line the source's parser can't read is parsed automatically and marked
// with a parse_error field, so nothing is lost. Blank lines return nil.
func (r *Router) Parse(ctx context.Context, sourceID int64, line string, d parser.Defaults) (*ocsf.Event, map[string]string, error) {
	p, name, none, err := r.parserFor(ctx, sourceID)
	if err != nil {
		return nil, nil, err
	}
	if none {
		return parser.PlainLine(line, d), nil, nil
	}
	if p == nil {
		return parser.ParseLine(line, d), nil, nil
	}
	res, err := p.Parse(line, d)
	if errors.Is(err, parser.ErrNoMatch) {
		ev := parser.ParseLine(line, d)
		return ev, map[string]string{"parse_error": "didn't match the " + name + " parser"}, nil
	}
	if err != nil || res == nil {
		return nil, nil, err
	}
	if len(res.Extra) == 0 {
		return res.Event, nil, nil
	}
	return res.Event, res.Extra, nil
}
