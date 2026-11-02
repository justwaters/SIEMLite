package integrations

import (
	"context"
	"errors"
	"testing"
)

type fake struct {
	id, name   string
	configured bool
	enabled    bool
	err        error
}

func (f *fake) ID() string          { return f.id }
func (f *fake) Name() string        { return f.name }
func (f *fake) Description() string { return f.name + " does things" }
func (f *fake) Info(context.Context) (Info, error) {
	return Info{Configured: f.configured, Enabled: f.enabled && f.configured, Summary: "s"}, f.err
}
func (f *fake) SetEnabled(_ context.Context, on bool) error { f.enabled = on; return nil }

func TestRegistry(t *testing.T) {
	ctx := context.Background()
	zeta := &fake{id: "zeta", name: "Zeta"}
	on := &fake{id: "email", name: "Email", configured: true, enabled: true}
	off := &fake{id: "sso", name: "Single sign-on", configured: true}
	bad := &fake{id: "bad", name: "Broken", err: errors.New("it broke")}
	r := New(zeta, on, off, bad, nil)

	list := r.List(ctx)
	if len(list) != 4 {
		t.Fatalf("len = %d: %+v", len(list), list)
	}
	want := map[string]string{"zeta": StateNeedsSetup, "email": StateOn, "sso": StateOff, "bad": StateError}
	for _, i := range list {
		if i.State != want[i.ID] || i.Name == "" || i.Description == "" {
			t.Errorf("%s: %+v", i.ID, i)
		}
		if i.ID == "bad" && i.Summary != "it broke" {
			t.Errorf("an error should be the summary: %q", i.Summary)
		}
	}
	// Sorted by name: Broken, Email, Single sign-on, Zeta.
	if list[0].ID != "bad" || list[1].ID != "email" || list[3].ID != "zeta" {
		t.Errorf("order: %v %v %v %v", list[0].ID, list[1].ID, list[2].ID, list[3].ID)
	}
	if it, ok := r.Get("sso"); !ok || it.ID() != "sso" {
		t.Error("Get sso")
	}
	if _, ok := r.Get("nope"); ok {
		t.Error("Get found a missing id")
	}
}

// leaky reports itself enabled while it has nothing set up, as a saved "on" setting can.
type leaky struct{ fake }

func (l *leaky) Info(context.Context) (Info, error) { return Info{Enabled: true}, nil }

func TestNotSetUpIsNeverOn(t *testing.T) {
	info := Describe(context.Background(), &leaky{fake{id: "mcp", name: "Agents"}})
	if info.State != StateNeedsSetup || info.Enabled {
		t.Errorf("an integration with nothing set up = state %q, enabled %v; want %q, off", info.State, info.Enabled, StateNeedsSetup)
	}
}
