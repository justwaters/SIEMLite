package update

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewerWithBetas(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.34", "v0.34-beta.2", true},         // the release is newer than its betas
		{"v0.34-beta.2", "v0.34", false},        // and a beta is older than its release
		{"v0.34-beta.2", "v0.34-beta.1", true},  // later beta
		{"v0.34-beta.10", "v0.34-beta.9", true}, // numbers compare as numbers
		{"v0.34-beta.1", "v0.34-alpha.9", true}, // words compare as words
		{"v0.34-rc.1", "v0.34-beta.5", true},    //
		{"v0.34-beta", "v0.34-beta.1", false},   // fewer parts is older
		{"v0.34-beta.1", "v0.34-beta", true},    //
		{"v0.34-1", "v0.34-beta", false},        // a number is older than a word
		{"v0.34-beta", "v0.34-1", true},         //
		{"v0.34-beta.1", "v0.33", true},         // a beta of a later number beats the earlier release
		{"v0.33", "v0.34-beta.1", false},        //
		{"v0.34-beta.1", "v0.34-beta.1", false}, //
		{"v0.34-", "v0.33", false},              // not a tag
		{"v0.34-beta..1", "v0.33", false},       // not a tag
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func FuzzNewerOrdering(f *testing.F) {
	for _, s := range []string{"v0.34", "v0.34-beta.1", "v0.34-beta.10", "v1.0-rc.1", "v0.9.1", "dev", "v1-", "v0.1-a.b.c"} {
		f.Add(s, "v0.34-beta.2")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := Newer(a, b), Newer(b, a)
		if ab && ba {
			t.Fatalf("%q and %q are each newer than the other", a, b)
		}
		if Newer(a, a) {
			t.Fatalf("%q is newer than itself", a)
		}
		if (!tagRe.MatchString(a) || !tagRe.MatchString(b)) && (ab || ba) {
			t.Fatalf("compared a non-release: %q %q", a, b)
		}
	})
}

// A fake GitHub with a stable latest and a list that has a newer beta, a draft, and junk.
func fakeChannels(t *testing.T) *Checker {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.33","html_url":"https://example.test/v0.33","body":"stable notes"}`)
	})
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"tag_name":"v0.34-beta.2","html_url":"https://example.test/b2","body":"second beta","prerelease":true},
			{"tag_name":"v0.34-beta.1","html_url":"https://example.test/b1","prerelease":true},
			{"tag_name":"v9.9","html_url":"https://example.test/draft","draft":true},
			{"tag_name":"not-a-version","html_url":"https://example.test/x"},
			{"tag_name":"v0.33","html_url":"https://example.test/v0.33","body":"stable notes"}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New("v0.32", "/nonexistent/siemlite")
	c.API, c.ListAPI = srv.URL+"/latest", srv.URL+"/list"
	c.InContainer = func() bool { return false }
	return c
}

func TestChannels(t *testing.T) {
	ctx := context.Background()
	c := fakeChannels(t)
	if got := c.Channel(); got != Stable {
		t.Fatalf("default channel %q", got)
	}
	st := c.Check(ctx, false)
	if st.Latest != "v0.33" || st.Prerelease || st.Channel != Stable || !st.Available {
		t.Fatalf("stable = %+v", st)
	}
	c.SetChannel(Beta) // no forced check: the cached stable answer must not be reused
	st = c.Check(ctx, false)
	if st.Latest != "v0.34-beta.2" || !st.Prerelease || st.Channel != Beta || !st.Available || st.Notes != "second beta" {
		t.Fatalf("beta = %+v", st)
	}
	c.SetChannel("nonsense") // anything but beta is stable
	if st = c.Check(ctx, false); st.Latest != "v0.33" || st.Channel != Stable {
		t.Fatalf("back to stable = %+v", st)
	}
	if !ValidChannel("beta") || !ValidChannel("stable") || ValidChannel("") || ValidChannel("Beta ") {
		t.Error("ValidChannel")
	}
}

// Someone running a beta ahead of Stable is offered nothing on Stable (no going back), and the
// next Stable release of that number is newer than their beta.
func TestBetaUsersAreNotDowngraded(t *testing.T) {
	ctx := context.Background()
	c := fakeChannels(t)
	c.Current = "v0.34-beta.1"
	if st := c.Check(ctx, true); st.Available || st.Latest != "v0.33" {
		t.Errorf("on Stable while running a newer beta: %+v", st)
	}
	c.SetChannel(Beta)
	if st := c.Check(ctx, true); !st.Available || st.Latest != "v0.34-beta.2" {
		t.Errorf("on Beta: %+v", st)
	}
	c.Current = "v0.34-beta.2"
	if st := c.Check(ctx, true); st.Available {
		t.Errorf("already on the newest beta: %+v", st)
	}
}

func TestBetaListFailures(t *testing.T) {
	ctx := context.Background()
	for name, body := range map[string]string{"empty": `[]`, "only drafts": `[{"tag_name":"v1.0","draft":true}]`, "not a list": `{"x":1}`, "junk": `<html>`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := New("v0.32", "/x")
		c.ListAPI, c.API = srv.URL, srv.URL
		c.SetChannel(Beta)
		st := c.Check(ctx, true)
		srv.Close()
		if st.Error == "" || st.Available || !strings.Contains(st.Error, "Couldn't check") {
			t.Errorf("%s: %+v", name, st)
		}
	}
	// The list address is derived from the latest-release address.
	c := New("v0", "/x")
	if got := c.listURL(); !strings.HasSuffix(got, "/releases?per_page=30") || strings.Contains(got, "latest") {
		t.Errorf("derived list address %q", got)
	}
}
