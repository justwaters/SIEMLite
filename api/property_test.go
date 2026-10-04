package api_test

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"siemlite/pkg/auth"
	"siemlite/pkg/search"
	"siemlite/pkg/storage"
)

// TestRestrictedVisibilityProperty gives randomly chosen users random sets
// of sources and runs random searches as each. Whatever the filters, a
// limited user's results must be exactly the admin's results for the same
// search, less every event from a source they weren't given.
func TestRestrictedVisibilityProperty(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("root", auth.RoleAdmin)
	root := e.client()
	e.login(root, "root", password)

	// Five token sources, each sending lines that share words with the others.
	var ids []int64
	for i := 0; i < 5; i++ {
		var src struct {
			Source storage.Source `json:"source"`
			Token  string         `json:"token"`
		}
		if got := e.call(root, "POST", "/api/v1/sources", map[string]any{"name": fmt.Sprintf("app%d", i)}, &src, nil); got != 201 {
			t.Fatalf("create source = %d", got)
		}
		ids = append(ids, src.Source.ID)
		var lines []string
		for j := 0; j < 30; j++ {
			// Within the dashboard's last 24 hours, whenever the test runs.
			at := time.Now().Add(-time.Duration(j*30+i) * time.Minute).Format(time.Stamp) // syslog times are local
			lines = append(lines, fmt.Sprintf("%s web%d sshd[1]: Failed password for user%d from 10.0.%d.%d port 22 tag%d shared",
				at, j%3, j%4, j%5, j%7, i))
		}
		expect(t, "send", e.do(e.client(), "POST", "/api/v1/logs", strings.Join(lines, "\n"),
			map[string]string{"Authorization": "Bearer " + src.Token}), 202)
	}
	internal, err := e.repo.BuiltinSource(ctx, storage.SourceInternal)
	if err != nil {
		t.Fatal(err)
	}
	ids = append(ids, internal.ID) // the audit log is a source like any other
	if err := e.worker.Drain(ctx); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(7))
	pick := func(vals ...string) string { return vals[rng.Intn(len(vals))] }
	for u := 0; u < 12; u++ {
		var allowed []int64
		for _, id := range ids {
			if rng.Intn(2) == 0 {
				allowed = append(allowed, id)
			}
		}
		if len(allowed) == 0 {
			allowed = ids[:1]
		}
		name := fmt.Sprintf("user%d", u)
		if got := e.call(root, "POST", "/api/v1/users", map[string]any{
			"username": name, "password": password, "role": "standard", "sources": allowed,
		}, nil, nil); got != 201 {
			t.Fatalf("create %s = %d", name, got)
		}
		c := e.client()
		e.login(c, name, password)
		e.worker.Drain(ctx) // so audit events don't land between searches

		for q := 0; q < 15; q++ {
			v := url.Values{"limit": {"1000"}}
			if s := pick("", "failed", "shared", "tag1 OR tag3", `"failed password"`, "signed", "user2"); s != "" {
				v.Set("q", s)
			}
			if rng.Intn(3) == 0 {
				v.Set("source_id", fmt.Sprint(ids[rng.Intn(len(ids))]))
			}
			if s := pick("", "", "10.0.1.2", "10.0.3.0", "127.0.0.1"); s != "" {
				v.Set("src_ip", s)
			}
			if s := pick("", "", "user1", "root"); s != "" {
				v.Set("user", s)
			}
			if s := pick("", "", "web0", "web2"); s != "" {
				v.Set("host", s)
			}
			var mine, all search.Result
			if got := e.call(c, "GET", "/api/v1/search?"+v.Encode(), nil, &mine, nil); got != 200 {
				t.Fatalf("%s search %s = %d", name, v.Encode(), got)
			}
			e.call(root, "GET", "/api/v1/search?"+v.Encode(), nil, &all, nil)
			var want []int64
			for _, ev := range all.Events {
				if slices.Contains(allowed, ev.SourceID) {
					want = append(want, ev.ID)
				}
			}
			var got []int64
			for _, ev := range mine.Events {
				if !slices.Contains(allowed, ev.SourceID) {
					t.Fatalf("%s (sources %v) saw event %d from source %d with %s", name, allowed, ev.ID, ev.SourceID, v.Encode())
				}
				got = append(got, ev.ID)
			}
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Fatalf("%s (sources %v) %s: got %d events, want %d", name, allowed, v.Encode(), len(got), len(want))
			}
			// Paging never leaks either.
			v.Set("limit", "7")
			v.Set("offset", fmt.Sprint(rng.Intn(20)))
			e.call(c, "GET", "/api/v1/search?"+v.Encode(), nil, &mine, nil)
			for _, ev := range mine.Events {
				if !slices.Contains(allowed, ev.SourceID) {
					t.Fatalf("%s saw source %d on a later page", name, ev.SourceID)
				}
			}
		}

		// The dashboard and the sources list agree with the searches.
		var stats struct {
			Overview storage.Overview `json:"overview"`
		}
		e.call(c, "GET", "/api/v1/stats", nil, &stats, nil)
		var mine search.Result
		e.call(c, "GET", "/api/v1/search?limit=1000", nil, &mine, nil)
		if stats.Overview.Total != int64(len(mine.Events)) {
			t.Errorf("%s stats total = %d, search finds %d", name, stats.Overview.Total, len(mine.Events))
		}
		var visible []storage.Source
		e.call(c, "GET", "/api/v1/sources", nil, &visible, nil)
		for _, s := range visible {
			if !slices.Contains(allowed, s.ID) {
				t.Errorf("%s (sources %v) can see source %d %q", name, allowed, s.ID, s.Name)
			}
		}
	}
}
