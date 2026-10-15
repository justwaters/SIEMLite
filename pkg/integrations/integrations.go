// Package integrations is the list of built-in integrations the Integrations
// page shows: services SIEMLite can connect to (email, single sign-on). Each is
// compiled in; the page turns one on or off and opens its settings.
package integrations

import (
	"context"
	"sort"
	"sync"
)

// Integration states, as the page shows them.
const (
	StateNeedsSetup = "needs_setup" // nothing saved yet
	StateOff        = "off"         // set up, but turned off
	StateOn         = "on"
	StateError      = "error"
)

// Info is one integration's card.
type Info struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	State       string `json:"state"`
	// Summary is one line about how it is set up, or what is wrong.
	Summary    string `json:"summary,omitempty"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
}

// InputError is a mistake in what a person entered (or a request that would
// cause harm, like turning off the only way in), worded for them. Integrations
// return it so the API can answer 400 with the message rather than 500.
type InputError string

func (e InputError) Error() string { return string(e) }

// Integration is what the page needs from each one. Its own settings are
// saved and tested through its own endpoints.
type Integration interface {
	ID() string
	Name() string
	Description() string
	// Info reports the current state. Only Configured, Enabled and Summary need
	// filling in; List adds the rest.
	Info(ctx context.Context) (Info, error)
	// SetEnabled turns the integration on or off without touching its settings.
	SetEnabled(ctx context.Context, on bool) error
}

// Registry holds the integrations, in the order they were added.
type Registry struct {
	mu    sync.RWMutex
	items []Integration
}

// New returns a Registry of items.
func New(items ...Integration) *Registry {
	r := &Registry{}
	for _, it := range items {
		r.Add(it)
	}
	return r
}

// Add registers an integration (nil is ignored, so an optional one can be passed unchecked).
func (r *Registry) Add(it Integration) {
	if it == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, it)
}

// Get finds an integration by id.
func (r *Registry) Get(id string) (Integration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, it := range r.items {
		if it.ID() == id {
			return it, true
		}
	}
	return nil, false
}

// Describe fills in an integration's Info with its fixed details and state.
func Describe(ctx context.Context, it Integration) Info {
	info, err := it.Info(ctx)
	info.ID, info.Name, info.Description = it.ID(), it.Name(), it.Description()
	switch {
	case err != nil:
		info.State, info.Summary = StateError, err.Error()
	case !info.Configured:
		info.State = StateNeedsSetup
	case !info.Enabled:
		info.State = StateOff
	default:
		info.State = StateOn
	}
	return info
}

// List describes every integration, sorted by name.
func (r *Registry) List(ctx context.Context) []Info {
	r.mu.RLock()
	items := append([]Integration(nil), r.items...)
	r.mu.RUnlock()
	out := make([]Info, 0, len(items))
	for _, it := range items {
		out = append(out, Describe(ctx, it))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
